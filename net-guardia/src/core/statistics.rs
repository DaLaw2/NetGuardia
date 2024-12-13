use crate::core::system::System;
use crate::model::flow_stats::FlowStats;
use crate::model::flow_type::FlowType;
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
    ipv4_src_1min: AyaHashMap<MapData, EbpfAddrPortV4, EbpfFlowStats>,
    ipv4_src_10min: AyaHashMap<MapData, EbpfAddrPortV4, EbpfFlowStats>,
    ipv4_src_1hour: AyaHashMap<MapData, EbpfAddrPortV4, EbpfFlowStats>,
    ipv6_src_1min: AyaHashMap<MapData, EbpfAddrPortV6, EbpfFlowStats>,
    ipv6_src_10min: AyaHashMap<MapData, EbpfAddrPortV6, EbpfFlowStats>,
    ipv6_src_1hour: AyaHashMap<MapData, EbpfAddrPortV6, EbpfFlowStats>,
    ipv4_dst_1min: AyaHashMap<MapData, EbpfAddrPortV4, EbpfFlowStats>,
    ipv4_dst_10min: AyaHashMap<MapData, EbpfAddrPortV4, EbpfFlowStats>,
    ipv4_dst_1hour: AyaHashMap<MapData, EbpfAddrPortV4, EbpfFlowStats>,
    ipv6_dst_1min: AyaHashMap<MapData, EbpfAddrPortV6, EbpfFlowStats>,
    ipv6_dst_10min: AyaHashMap<MapData, EbpfAddrPortV6, EbpfFlowStats>,
    ipv6_dst_1hour: AyaHashMap<MapData, EbpfAddrPortV6, EbpfFlowStats>,
}

impl Statistics {
    pub async fn initialize() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Initializing);
        let mut system = System::instance_mut().await;
        let ebpf = &mut system.ebpf;
        let monitor = Statistics {
            terminate: false,
            ipv4_src_1min: AyaHashMap::try_from(ebpf.take_map("IPV4_SRC_1MIN").unwrap())?,
            ipv4_src_10min: AyaHashMap::try_from(ebpf.take_map("IPV4_SRC_10MIN").unwrap())?,
            ipv4_src_1hour: AyaHashMap::try_from(ebpf.take_map("IPV4_SRC_1HOUR").unwrap())?,
            ipv6_src_1min: AyaHashMap::try_from(ebpf.take_map("IPV6_SRC_1MIN").unwrap())?,
            ipv6_src_10min: AyaHashMap::try_from(ebpf.take_map("IPV6_SRC_10MIN").unwrap())?,
            ipv6_src_1hour: AyaHashMap::try_from(ebpf.take_map("IPV6_SRC_1HOUR").unwrap())?,
            ipv4_dst_1min: AyaHashMap::try_from(ebpf.take_map("IPV4_DST_1MIN").unwrap())?,
            ipv4_dst_10min: AyaHashMap::try_from(ebpf.take_map("IPV4_DST_10MIN").unwrap())?,
            ipv4_dst_1hour: AyaHashMap::try_from(ebpf.take_map("IPV4_DST_1HOUR").unwrap())?,
            ipv6_dst_1min: AyaHashMap::try_from(ebpf.take_map("IPV6_DST_1MIN").unwrap())?,
            ipv6_dst_10min: AyaHashMap::try_from(ebpf.take_map("IPV6_DST_10MIN").unwrap())?,
            ipv6_dst_1hour: AyaHashMap::try_from(ebpf.take_map("IPV6_DST_1HOUR").unwrap())?,
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
        const ONE_MIN: u64 = 60 * 1_000_000_000;
        const TEN_MIN: u64 = 10 * ONE_MIN;
        const ONE_HOUR: u64 = 60 * ONE_MIN;

        let mut monitor = Statistics::instance_mut().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        Statistics::cleanup_map(&mut monitor.ipv4_src_1min, now, ONE_MIN).await;
        Statistics::cleanup_map(&mut monitor.ipv4_dst_1min, now, ONE_MIN).await;
        Statistics::cleanup_map(&mut monitor.ipv4_src_10min, now, TEN_MIN).await;
        Statistics::cleanup_map(&mut monitor.ipv4_dst_10min, now, TEN_MIN).await;
        Statistics::cleanup_map(&mut monitor.ipv4_src_1hour, now, ONE_HOUR).await;
        Statistics::cleanup_map(&mut monitor.ipv4_dst_1hour, now, ONE_HOUR).await;
        Statistics::cleanup_map(&mut monitor.ipv6_src_1min, now, ONE_MIN).await;
        Statistics::cleanup_map(&mut monitor.ipv6_dst_1min, now, ONE_MIN).await;
        Statistics::cleanup_map(&mut monitor.ipv6_src_10min, now, TEN_MIN).await;
        Statistics::cleanup_map(&mut monitor.ipv6_dst_10min, now, TEN_MIN).await;
        Statistics::cleanup_map(&mut monitor.ipv6_src_1hour, now, ONE_HOUR).await;
        Statistics::cleanup_map(&mut monitor.ipv6_dst_1hour, now, ONE_HOUR).await;
    }

    async fn cleanup_map<K>(map: &mut AyaHashMap<MapData, K, EbpfFlowStats>, now: u64, window: u64)
    where
        K: Pod,
    {
        let boot_time = System::boot_time().await;
        let expired_keys: Vec<K> = map
            .iter()
            .filter_map(|result| {
                if let Ok((key, stats)) = result {
                    if now - stats[2] - boot_time > window {
                        Some(key)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();
        for key in expired_keys {
            let _ = map.remove(&key);
        }
    }

    pub async fn get_ipv4_flow_data(flow_type: FlowType) -> StdHashMap<SocketAddrV4, FlowStats> {
        let monitor = Statistics::instance().await;
        let iter = match flow_type {
            FlowType::Src1Min => monitor.ipv4_src_1min.iter(),
            FlowType::Src10Min => monitor.ipv4_src_10min.iter(),
            FlowType::Src1Hour => monitor.ipv4_src_1hour.iter(),
            FlowType::Dst1Min => monitor.ipv4_dst_1min.iter(),
            FlowType::Dst10Min => monitor.ipv4_dst_10min.iter(),
            FlowType::Dst1Hour => monitor.ipv4_dst_1hour.iter(),
        };
        iter.filter_map(Result::ok)
            .map(|(key, value)| {
                let ip = Ipv4Addr::from(key[0]);
                let port = key[1] as u16;
                (SocketAddrV4::new(ip, port), FlowStats::from(value))
            })
            .collect()
    }

    pub async fn get_ipv6_flow_data(flow_type: FlowType) -> StdHashMap<SocketAddrV6, FlowStats> {
        let monitor = Statistics::instance().await;
        let iter = match flow_type {
            FlowType::Src1Min => monitor.ipv6_src_1min.iter(),
            FlowType::Src10Min => monitor.ipv6_src_10min.iter(),
            FlowType::Src1Hour => monitor.ipv6_src_1hour.iter(),
            FlowType::Dst1Min => monitor.ipv6_dst_1min.iter(),
            FlowType::Dst10Min => monitor.ipv6_dst_10min.iter(),
            FlowType::Dst1Hour => monitor.ipv6_dst_1hour.iter(),
        };
        iter.filter_map(Result::ok)
            .map(|(key, value)| {
                let ip = Ipv6Addr::from(key[0]);
                let port = key[1] as u16;
                (SocketAddrV6::new(ip, port, 0, 0), FlowStats::from(value))
            })
            .collect()
    }
}
