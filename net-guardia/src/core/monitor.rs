use crate::core::system::System;
use crate::model::flow_type::{IPv4FlowType, IPv6FlowType};
use crate::utils::log_entry::system::SystemEntry;
use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::Pod;
use net_guardia_common::model::flow_stats::EbpfFlowStats;
use net_guardia_common::model::ip_address::{EbpfAddrPortV4, EbpfAddrPortV6};
use std::collections::HashMap as StdHashMap;
use std::sync::OnceLock;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::info;

static MONITOR: OnceLock<RwLock<Monitor>> = OnceLock::new();

pub struct Monitor {
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

impl Monitor {
    pub async fn initialize() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Initializing);
        let mut system = System::instance_mut().await;
        let mut ebpf = &mut system.ebpf;
        let monitor = Monitor {
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
        MONITOR.get_or_init(|| RwLock::new(monitor));
        info!("{}", SystemEntry::InitializeComplete);
        Ok(())
    }

    #[inline(always)]
    pub async fn instance() -> RwLockReadGuard<'static, Monitor> {
        // Initialization has been ensured
        let once_lock = MONITOR.get().unwrap();
        // There is no lock acquired multiple times, so this is safe
        once_lock.read().await
    }

    #[inline(always)]
    pub async fn instance_mut() -> RwLockWriteGuard<'static, Monitor> {
        // Initialization has been ensured
        let once_lock = MONITOR.get().unwrap();
        // There is no lock acquired multiple times, so this is safe
        once_lock.write().await
    }

    pub async fn run() {
        tokio::spawn(async {
            loop {
                Monitor::cleanup_expired_flows().await;
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            }
        });
    }

    pub async fn terminate() {
        let mut monitor = Monitor::instance_mut().await;
        monitor.terminate = true;
    }

    pub async fn cleanup_expired_flows() {
        const ONE_MIN: u64 = 60 * 1_000_000_000;
        const TEN_MIN: u64 = 10 * ONE_MIN;
        const ONE_HOUR: u64 = 60 * ONE_MIN;

        let mut monitor = Monitor::instance_mut().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        Monitor::cleanup_map(&mut monitor.ipv4_src_1min, now, ONE_MIN).await;
        Monitor::cleanup_map(&mut monitor.ipv4_dst_1min, now, ONE_MIN).await;
        Monitor::cleanup_map(&mut monitor.ipv4_src_10min, now, TEN_MIN).await;
        Monitor::cleanup_map(&mut monitor.ipv4_dst_10min, now, TEN_MIN).await;
        Monitor::cleanup_map(&mut monitor.ipv4_src_1hour, now, ONE_HOUR).await;
        Monitor::cleanup_map(&mut monitor.ipv4_dst_1hour, now, ONE_HOUR).await;
        Monitor::cleanup_map(&mut monitor.ipv6_src_1min, now, ONE_MIN).await;
        Monitor::cleanup_map(&mut monitor.ipv6_dst_1min, now, ONE_MIN).await;
        Monitor::cleanup_map(&mut monitor.ipv6_src_10min, now, TEN_MIN).await;
        Monitor::cleanup_map(&mut monitor.ipv6_dst_10min, now, TEN_MIN).await;
        Monitor::cleanup_map(&mut monitor.ipv6_src_1hour, now, ONE_HOUR).await;
        Monitor::cleanup_map(&mut monitor.ipv6_dst_1hour, now, ONE_HOUR).await;
    }

    async fn cleanup_map<K>(map: &mut AyaHashMap<MapData, K, EbpfFlowStats>, now: u64, window: u64)
    where
        K: Pod,
    {
        let expired_keys: Vec<K> = map
            .iter()
            .filter_map(|result| {
                if let Ok((key, stats)) = result {
                    if now - stats[2] > window {
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

    pub async fn get_ipv4_flow_data(
        ipv4_flow_type: IPv4FlowType,
    ) -> StdHashMap<EbpfAddrPortV4, EbpfFlowStats> {
        let monitor = Monitor::instance().await;
        let iter = match ipv4_flow_type {
            IPv4FlowType::Src1Min => monitor.ipv4_src_1min.iter(),
            IPv4FlowType::Src10Min => monitor.ipv4_src_10min.iter(),
            IPv4FlowType::Src1Hour => monitor.ipv4_src_1hour.iter(),
            IPv4FlowType::Dst1Min => monitor.ipv4_dst_1min.iter(),
            IPv4FlowType::Dst10Min => monitor.ipv4_dst_10min.iter(),
            IPv4FlowType::Dst1Hour => monitor.ipv4_dst_1hour.iter(),
        };
        iter.filter_map(|result| result.ok()).collect()
    }

    pub async fn get_ipv6_flow_data(
        ipv6_flow_type: IPv6FlowType,
    ) -> StdHashMap<EbpfAddrPortV6, EbpfFlowStats> {
        let monitor = Monitor::instance().await;
        let iter = match ipv6_flow_type {
            IPv6FlowType::Src1Min => monitor.ipv6_src_1min.iter(),
            IPv6FlowType::Src10Min => monitor.ipv6_src_10min.iter(),
            IPv6FlowType::Src1Hour => monitor.ipv6_src_1hour.iter(),
            IPv6FlowType::Dst1Min => monitor.ipv6_dst_1min.iter(),
            IPv6FlowType::Dst10Min => monitor.ipv6_dst_10min.iter(),
            IPv6FlowType::Dst1Hour => monitor.ipv6_dst_1hour.iter(),
        };
        iter.filter_map(|result| result.ok()).collect()
    }
}
