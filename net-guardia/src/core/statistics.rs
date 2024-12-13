use crate::core::system::System;
use crate::model::direction::Direction;
use crate::model::flow_stats::FlowStats;
use crate::model::ip_address::SocketAddressType;
use crate::model::time_type::TimeType;
use crate::utils::log_entry::system::SystemEntry;
use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::Pod;
use net_guardia_common::model::flow_stats::EbpfFlowStats;
use net_guardia_common::model::ip_address::{EbpfAddrPortV4, EbpfAddrPortV6};
use std::collections::HashMap as StdHashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::OnceLock;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::info;

static STATISTICS: OnceLock<RwLock<Statistics>> = OnceLock::new();

pub struct Statistics {
    terminate: bool,
    ipv4_maps: StdHashMap<(Direction, TimeType), FlowMap<EbpfAddrPortV4>>,
    ipv6_maps: StdHashMap<(Direction, TimeType), FlowMap<EbpfAddrPortV6>>,
}

impl Statistics {
    const MAP_CONFIGS: [((Direction, TimeType), (&'static str, &'static str)); 6] = [
        (
            (Direction::Source, TimeType::_1Min),
            ("IPV4_SRC_1MIN", "IPV6_SRC_1MIN"),
        ),
        (
            (Direction::Source, TimeType::_10Min),
            ("IPV4_SRC_10MIN", "IPV6_SRC_10MIN"),
        ),
        (
            (Direction::Source, TimeType::_1Hour),
            ("IPV4_SRC_1HOUR", "IPV6_SRC_1HOUR"),
        ),
        (
            (Direction::Destination, TimeType::_1Min),
            ("IPV4_DST_1MIN", "IPV6_DST_1MIN"),
        ),
        (
            (Direction::Destination, TimeType::_10Min),
            ("IPV4_DST_10MIN", "IPV6_DST_10MIN"),
        ),
        (
            (Direction::Destination, TimeType::_1Hour),
            ("IPV4_DST_1HOUR", "IPV6_DST_1HOUR"),
        ),
    ];

    pub async fn initialize() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Initializing);
        let mut system = System::instance_mut().await;
        let ebpf = &mut system.ebpf;
        let mut ipv4_maps = StdHashMap::new();
        let mut ipv6_maps = StdHashMap::new();
        for (key, (ipv4_name, ipv6_name)) in Self::MAP_CONFIGS {
            ipv4_maps.insert(
                key,
                FlowMap {
                    map: AyaHashMap::try_from(ebpf.take_map(ipv4_name).unwrap())?,
                },
            );
            ipv6_maps.insert(
                key,
                FlowMap {
                    map: AyaHashMap::try_from(ebpf.take_map(ipv6_name).unwrap())?,
                },
            );
        }
        let monitor = Statistics {
            terminate: false,
            ipv4_maps,
            ipv6_maps,
        };
        STATISTICS.get_or_init(|| RwLock::new(monitor));
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
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            }
        });
    }

    pub async fn terminate() {
        let mut monitor = Statistics::instance_mut().await;
        monitor.terminate = true;
    }

    pub async fn cleanup_expired_flows() {
        let mut monitor = Statistics::instance_mut().await;
        let boot_time = System::boot_time().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        monitor
            .ipv4_maps
            .iter_mut()
            .for_each(|((_, time_type), map)| map.cleanup(boot_time, now, time_type.duration()));
        monitor
            .ipv6_maps
            .iter_mut()
            .for_each(|((_, time_type), map)| map.cleanup(boot_time, now, time_type.duration()));
    }

    pub async fn get_ipv4_flow_data(
        direction: Direction,
        time_type: TimeType,
    ) -> StdHashMap<SocketAddrV4, FlowStats> {
        let monitor = Statistics::instance().await;
        monitor
            .ipv4_maps
            .get(&(direction, time_type))
            .map(|map| map.get_map())
            .unwrap()
    }

    pub async fn get_ipv6_flow_data(
        direction: Direction,
        time_type: TimeType,
    ) -> StdHashMap<SocketAddrV6, FlowStats> {
        let monitor = Statistics::instance().await;
        monitor
            .ipv6_maps
            .get(&(direction, time_type))
            .map(|map| map.get_map())
            .unwrap()
    }
}

struct FlowMap<T> {
    map: AyaHashMap<MapData, T, EbpfFlowStats>,
}

impl<T: SocketAddressType + Pod> FlowMap<T> {
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
