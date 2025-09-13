use std::collections::HashMap;
use std::net::{SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::{Ebpf, Pod};
use common::model::flow_stats::FlowStats;
use common::model::ip_address::{AddrPortV4, AddrPortV6};
use tokio::select;
use tokio::sync::{oneshot, RwLock};
use tokio::time::{sleep, Duration};

use crate::core::infrastructure::app_config::AppConfig;
use crate::model::direction::{Direction, FlowDirection};
use crate::model::error::ebpf::EbpfError;
use crate::model::error::Error;
use crate::model::ip_address::NativeConvert;
use crate::model::time_type::TimeType;
use crate::utils::boot_time::boot_time;

pub struct Statistics {
    app_config: Arc<AppConfig>,
    boot_time: u64,
    ipv4_maps: HashMap<(Direction, FlowDirection, TimeType), RwLock<FlowMap<AddrPortV4>>>,
    ipv6_maps: HashMap<(Direction, FlowDirection, TimeType), RwLock<FlowMap<AddrPortV6>>>,
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

    pub fn new(
        app_config: Arc<AppConfig>,
        ingress_ebpf: &mut Ebpf,
        egress_ebpf: &mut Ebpf,
    ) -> Result<Statistics, Error> {
        let boot_time = boot_time();
        let mut ipv4_maps = HashMap::new();
        let mut ipv6_maps = HashMap::new();
        for (key, (ipv4_name, ipv6_name)) in Self::INGRESS_MAPS {
            ipv4_maps.insert(key, RwLock::new(FlowMap::new(ingress_ebpf, ipv4_name)?));
            ipv6_maps.insert(key, RwLock::new(FlowMap::new(ingress_ebpf, ipv6_name)?));
        }
        for (key, (ipv4_name, ipv6_name)) in Self::EGRESS_MAPS {
            ipv4_maps.insert(key, RwLock::new(FlowMap::new(egress_ebpf, ipv4_name)?));
            ipv6_maps.insert(key, RwLock::new(FlowMap::new(egress_ebpf, ipv6_name)?));
        }
        let statistics = Statistics {
            app_config,
            boot_time,
            ipv4_maps,
            ipv6_maps,
        };
        Ok(statistics)
    }

    pub async fn run(self: Arc<Self>) -> oneshot::Sender<()> {
        let refresh_interval = self.app_config.refresh_interval;
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            let mut receiver = receiver;
            loop {
                select! {
                    biased;
                    _ = &mut receiver => break,
                    _ = sleep(Duration::from_secs(refresh_interval)) => {
                        self.cleanup_expired_flows().await;
                    },
                }
            }
        });
        sender
    }

    pub async fn cleanup_expired_flows(self: &Arc<Self>) {
        let boot_time = self.boot_time;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        for ((_, _, time_type), map) in self.ipv4_maps.iter() {
            map.write().await.cleanup(boot_time, now, time_type.duration())
        }
        for ((_, _, time_type), map) in self.ipv6_maps.iter() {
            map.write().await.cleanup(boot_time, now, time_type.duration())
        }
    }

    pub async fn get_ipv4_flow_data(
        &self,
        direction: Direction,
        flow_direction: FlowDirection,
        time_type: TimeType,
    ) -> HashMap<SocketAddrV4, FlowStats> {
        self.ipv4_maps
            .get(&(direction, flow_direction, time_type))
            .unwrap()
            .write()
            .await
            .get_map()
    }

    pub async fn get_ipv6_flow_data(
        &self,
        direction: Direction,
        flow_direction: FlowDirection,
        time_type: TimeType,
    ) -> HashMap<SocketAddrV6, FlowStats> {
        self.ipv6_maps
            .get(&(direction, flow_direction, time_type))
            .unwrap()
            .write()
            .await
            .get_map()
    }
}

struct FlowMap<T> {
    map: AyaHashMap<MapData, T, FlowStats>,
}

impl<T: NativeConvert + Pod> FlowMap<T> {
    fn new(ebpf: &mut Ebpf, map_name: &str) -> Result<Self, Error> {
        let map = ebpf.take_map(map_name).ok_or(EbpfError::MapNotFound)?;
        let map = AyaHashMap::try_from(map).map_err(EbpfError::MapOperationError)?;
        Ok(Self { map })
    }

    fn get_map(&self) -> HashMap<T::Native, FlowStats> {
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
                    .and_then(|(key, stats)| (now - stats.last_seen - boot_time > window).then_some(key))
            })
            .collect();
        expired_keys.iter().for_each(|key| {
            let _ = self.map.remove(key);
        });
    }
}
