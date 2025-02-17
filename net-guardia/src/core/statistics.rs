use crate::core::system::System;
use crate::model::direction::{Direction, FlowDirection};
use crate::model::flow_stats::FlowStats;
use crate::model::ip_address::IntoNative;
use crate::model::time_type::TimeType;
use crate::utils::log_entry::system::SystemEntry;
use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::Pod;
use net_guardia_common::model::flow_stats::EbpfFlowStats;
use net_guardia_common::model::ip_address::{EbpfAddrPortV4, EbpfAddrPortV6};
use std::collections::HashMap as StdHashMap;
use std::net::{SocketAddrV4, SocketAddrV6};
use std::sync::OnceLock;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::info;

static STATISTICS: OnceLock<RwLock<Statistics>> = OnceLock::new();

pub struct Statistics {
    terminate: bool,
    ipv4_maps: StdHashMap<(Direction, FlowDirection, TimeType), FlowMap<EbpfAddrPortV4>>,
    ipv6_maps: StdHashMap<(Direction, FlowDirection, TimeType), FlowMap<EbpfAddrPortV6>>,
}

impl Statistics {
    const INGRESS_MAPS: [((Direction, FlowDirection, TimeType), (&'static str, &'static str)); 6] = [
        (
            (Direction::Ingress, FlowDirection::Source, TimeType::_1Min),
            ("IPV4_INGRESS_SRC_1MIN", "IPV6_INGRESS_SRC_1MIN"),
        ),
        (
            (Direction::Ingress, FlowDirection::Source, TimeType::_10Min),
            ("IPV4_INGRESS_SRC_10MIN", "IPV6_INGRESS_SRC_10MIN"),
        ),
        (
            (Direction::Ingress, FlowDirection::Source, TimeType::_1Hour),
            ("IPV4_INGRESS_SRC_1HOUR", "IPV6_INGRESS_SRC_1HOUR"),
        ),
        (
            (Direction::Ingress, FlowDirection::Destination, TimeType::_1Min),
            ("IPV4_INGRESS_DST_1MIN", "IPV6_INGRESS_DST_1MIN"),
        ),
        (
            (Direction::Ingress, FlowDirection::Destination, TimeType::_10Min),
            ("IPV4_INGRESS_DST_10MIN", "IPV6_INGRESS_DST_10MIN"),
        ),
        (
            (Direction::Ingress, FlowDirection::Destination, TimeType::_1Hour),
            ("IPV4_INGRESS_DST_1HOUR", "IPV6_INGRESS_DST_1HOUR"),
        ),
    ];

    const EGRESS_MAPS: [((Direction, FlowDirection, TimeType), (&'static str, &'static str)); 6] = [
        (
            (Direction::Egress, FlowDirection::Source, TimeType::_1Min),
            ("IPV4_EGRESS_SRC_1MIN", "IPV6_EGRESS_SRC_1MIN"),
        ),
        (
            (Direction::Egress, FlowDirection::Source, TimeType::_10Min),
            ("IPV4_EGRESS_SRC_10MIN", "IPV6_EGRESS_SRC_10MIN"),
        ),
        (
            (Direction::Egress, FlowDirection::Source, TimeType::_1Hour),
            ("IPV4_EGRESS_SRC_1HOUR", "IPV6_EGRESS_SRC_1HOUR"),
        ),
        (
            (Direction::Egress, FlowDirection::Destination, TimeType::_1Min),
            ("IPV4_EGRESS_DST_1MIN", "IPV6_EGRESS_DST_1MIN"),
        ),
        (
            (Direction::Egress, FlowDirection::Destination, TimeType::_10Min),
            ("IPV4_EGRESS_DST_10MIN", "IPV6_EGRESS_DST_10MIN"),
        ),
        (
            (Direction::Egress, FlowDirection::Destination, TimeType::_1Hour),
            ("IPV4_EGRESS_DST_1HOUR", "IPV6_EGRESS_DST_1HOUR"),
        ),
    ];

    pub async fn initialize() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Initializing);
        let mut system = System::instance_mut().await;
        let mut ipv4_maps = StdHashMap::new();
        let mut ipv6_maps = StdHashMap::new();
        let ingress_ebpf = &mut system.ingress_ebpf;
        for (key, (ipv4_name, ipv6_name)) in Self::INGRESS_MAPS {
            ipv4_maps.insert(
                key,
                FlowMap {
                    map: AyaHashMap::try_from(ingress_ebpf.take_map(ipv4_name).unwrap())?,
                },
            );
            ipv6_maps.insert(
                key,
                FlowMap {
                    map: AyaHashMap::try_from(ingress_ebpf.take_map(ipv6_name).unwrap())?,
                },
            );
        }
        let egress_ebpf = &mut system.egress_ebpf;
        for (key, (ipv4_name, ipv6_name)) in Self::EGRESS_MAPS {
            ipv4_maps.insert(
                key,
                FlowMap {
                    map: AyaHashMap::try_from(egress_ebpf.take_map(ipv4_name).unwrap())?,
                },
            );
            ipv6_maps.insert(
                key,
                FlowMap {
                    map: AyaHashMap::try_from(egress_ebpf.take_map(ipv6_name).unwrap())?,
                },
            );
        }
        let statistics = Statistics {
            terminate: false,
            ipv4_maps,
            ipv6_maps,
        };
        STATISTICS.get_or_init(|| RwLock::new(statistics));
        info!("{}", SystemEntry::InitializeComplete);
        Ok(())
    }

    #[inline(always)]
    pub async fn instance() -> RwLockReadGuard<'static, Statistics> {
        // Initialization has been ensured
        let once_lock = STATISTICS.get().unwrap();
        // There is no lock acquired multiple times, so this is safe
        once_lock.read().await
    }

    #[inline(always)]
    pub async fn instance_mut() -> RwLockWriteGuard<'static, Statistics> {
        // Initialization has been ensured
        let once_lock = STATISTICS.get().unwrap();
        // There is no lock acquired multiple times, so this is safe
        once_lock.write().await
    }

    pub async fn run() {
        tokio::spawn(async {
            loop {
                Statistics::cleanup_expired_flows().await;
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        });
    }

    pub async fn terminate() {
        let mut statistics = Statistics::instance_mut().await;
        statistics.terminate = true;
    }

    pub async fn cleanup_expired_flows() {
        let mut statistics = Statistics::instance_mut().await;
        let boot_time = System::boot_time().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        statistics
            .ipv4_maps
            .iter_mut()
            .for_each(|((_, _, time_type), map)| map.cleanup(boot_time, now, time_type.duration()));
        statistics
            .ipv6_maps
            .iter_mut()
            .for_each(|((_, _, time_type), map)| map.cleanup(boot_time, now, time_type.duration()));
    }

    pub async fn get_ipv4_flow_data(
        direction: Direction,
        flow_direction: FlowDirection,
        time_type: TimeType,
    ) -> StdHashMap<SocketAddrV4, FlowStats> {
        let statistics = Statistics::instance().await;
        statistics
            .ipv4_maps
            .get(&(direction, flow_direction, time_type))
            .map(|map| map.get_map())
            .unwrap()
    }

    pub async fn get_ipv6_flow_data(
        direction: Direction,
        flow_direction: FlowDirection,
        time_type: TimeType,
    ) -> StdHashMap<SocketAddrV6, FlowStats> {
        let statistics = Statistics::instance().await;
        statistics
            .ipv6_maps
            .get(&(direction, flow_direction, time_type))
            .map(|map| map.get_map())
            .unwrap()
    }
}

struct FlowMap<T> {
    map: AyaHashMap<MapData, T, EbpfFlowStats>,
}

impl<T: IntoNative + Pod> FlowMap<T> {
    fn get_map(&self) -> StdHashMap<T::Native, FlowStats> {
        self.map
            .iter()
            .filter_map(Result::ok)
            .map(|(key, value)| (key.into_native(), FlowStats::from(value)))
            .collect()
    }

    fn cleanup(&mut self, boot_time: u64, now: u64, window: u64) {
        let expired_keys: Vec<T> = self
            .map
            .iter()
            .filter_map(|result| {
                result
                    .ok()
                    .and_then(|(key, stats)| (now - stats[2] - boot_time > window).then_some(key))
            })
            .collect();
        expired_keys.iter().for_each(|key| {
            let _ = self.map.remove(key);
        });
    }
}
