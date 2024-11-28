use crate::core::system::System;
use crate::model::flow_type::{IPv4FlowType, IPv6FlowType};
use crate::utils::log_entry::system::SystemEntry;
use aya::maps::{HashMap as AyaHashMap, MapData};
use net_guardia_common::model::flow_status::FlowStatus;
use net_guardia_common::model::ip_address::{AddrPortV4, AddrPortV6};
use std::collections::HashMap as StdHashMap;
use std::sync::OnceLock;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::info;

static MONITOR: OnceLock<RwLock<Monitor>> = OnceLock::new();

pub struct Monitor {
    src_ipv4_1min: AyaHashMap<MapData, AddrPortV4, FlowStatus>,
    src_ipv6_1min: AyaHashMap<MapData, AddrPortV6, FlowStatus>,
    src_ipv4_10min: AyaHashMap<MapData, AddrPortV4, FlowStatus>,
    src_ipv6_10min: AyaHashMap<MapData, AddrPortV6, FlowStatus>,
    src_ipv4_1hour: AyaHashMap<MapData, AddrPortV4, FlowStatus>,
    src_ipv6_1hour: AyaHashMap<MapData, AddrPortV6, FlowStatus>,
    dst_ipv4_1min: AyaHashMap<MapData, AddrPortV4, FlowStatus>,
    dst_ipv6_1min: AyaHashMap<MapData, AddrPortV6, FlowStatus>,
    dst_ipv4_10min: AyaHashMap<MapData, AddrPortV4, FlowStatus>,
    dst_ipv6_10min: AyaHashMap<MapData, AddrPortV6, FlowStatus>,
    dst_ipv4_1hour: AyaHashMap<MapData, AddrPortV4, FlowStatus>,
    dst_ipv6_1hour: AyaHashMap<MapData, AddrPortV6, FlowStatus>,
}

impl Monitor {
    pub async fn initialize() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Initializing);
        let mut system = System::instance_mut().await;
        let mut ebpf = &mut system.ebpf;
        let monitor = Monitor {
            src_ipv4_1min: AyaHashMap::try_from(ebpf.take_map("SRC_IPV4_1MIN").unwrap())?,
            src_ipv6_1min: AyaHashMap::try_from(ebpf.take_map("SRC_IPV6_1MIN").unwrap())?,
            src_ipv4_10min: AyaHashMap::try_from(ebpf.take_map("SRC_IPV4_10MIN").unwrap())?,
            src_ipv6_10min: AyaHashMap::try_from(ebpf.take_map("SRC_IPV6_10MIN").unwrap())?,
            src_ipv4_1hour: AyaHashMap::try_from(ebpf.take_map("SRC_IPV4_1HOUR").unwrap())?,
            src_ipv6_1hour: AyaHashMap::try_from(ebpf.take_map("SRC_IPV6_1HOUR").unwrap())?,
            dst_ipv4_1min: AyaHashMap::try_from(ebpf.take_map("DST_IPV4_1MIN").unwrap())?,
            dst_ipv6_1min: AyaHashMap::try_from(ebpf.take_map("DST_IPV6_1MIN").unwrap())?,
            dst_ipv4_10min: AyaHashMap::try_from(ebpf.take_map("DST_IPV4_10MIN").unwrap())?,
            dst_ipv6_10min: AyaHashMap::try_from(ebpf.take_map("DST_IPV6_10MIN").unwrap())?,
            dst_ipv4_1hour: AyaHashMap::try_from(ebpf.take_map("DST_IPV4_1HOUR").unwrap())?,
            dst_ipv6_1hour: AyaHashMap::try_from(ebpf.take_map("DST_IPV6_1HOUR").unwrap())?,
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

    pub async fn get_ipv4_flow_data(
        ipv4_flow_type: IPv4FlowType,
    ) -> StdHashMap<AddrPortV4, FlowStatus> {
        let monitor = Monitor::instance().await;
        let iter = match ipv4_flow_type {
            IPv4FlowType::SrcIPv4_1Min => monitor.src_ipv4_1min.iter(),
            IPv4FlowType::SrcIPv4_10Min => monitor.src_ipv4_10min.iter(),
            IPv4FlowType::SrcIPv4_1Hour => monitor.src_ipv4_1hour.iter(),
            IPv4FlowType::DstIPv4_1Min => monitor.dst_ipv4_1min.iter(),
            IPv4FlowType::DstIPv4_10Min => monitor.dst_ipv4_10min.iter(),
            IPv4FlowType::DstIPv4_1Hour => monitor.dst_ipv4_1hour.iter(),
        };
        iter.filter_map(|result| result.ok()).collect()
    }

    pub async fn get_ipv6_flow_data(
        ipv6_flow_type: IPv6FlowType,
    ) -> StdHashMap<AddrPortV6, FlowStatus> {
        let monitor = Monitor::instance().await;
        let iter = match ipv6_flow_type {
            IPv6FlowType::SrcIPv6_1Min => monitor.src_ipv6_1min.iter(),
            IPv6FlowType::SrcIPv6_10Min => monitor.src_ipv6_10min.iter(),
            IPv6FlowType::SrcIPv6_1Hour => monitor.src_ipv6_1hour.iter(),
            IPv6FlowType::DstIPv6_1Min => monitor.dst_ipv6_1min.iter(),
            IPv6FlowType::DstIPv6_10Min => monitor.dst_ipv6_10min.iter(),
            IPv6FlowType::DstIPv6_1Hour => monitor.dst_ipv6_1hour.iter(),
        };
        iter.filter_map(|result| result.ok()).collect()
    }
}
