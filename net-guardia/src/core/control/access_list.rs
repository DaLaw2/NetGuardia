use crate::core::system::System;
use crate::utils::ip_address::convert_ports_to_vec;
use crate::utils::log_entry::ebpf::EbpfEntry;
use crate::utils::log_entry::system::SystemEntry;
use aya::maps::{HashMap as AyaHashMap, MapData};
use net_guardia_common::model::ip_address::{IPv4, IPv6, Port};
use net_guardia_common::MAX_RULES_PORT;
use std::collections::HashMap as StdHashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::OnceLock;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::info;

static ACCESS_LIST: OnceLock<RwLock<AccessList>> = OnceLock::new();

pub struct AccessList {
    ipv4_src_white_list: AyaHashMap<MapData, IPv4, [Port; MAX_RULES_PORT]>,
    ipv6_src_white_list: AyaHashMap<MapData, IPv6, [Port; MAX_RULES_PORT]>,
    ipv4_dst_white_list: AyaHashMap<MapData, IPv4, [Port; MAX_RULES_PORT]>,
    ipv6_dst_white_list: AyaHashMap<MapData, IPv6, [Port; MAX_RULES_PORT]>,
    ipv4_src_black_list: AyaHashMap<MapData, IPv4, [Port; MAX_RULES_PORT]>,
    ipv6_src_black_list: AyaHashMap<MapData, IPv6, [Port; MAX_RULES_PORT]>,
    ipv4_dst_black_list: AyaHashMap<MapData, IPv4, [Port; MAX_RULES_PORT]>,
    ipv6_dst_black_list: AyaHashMap<MapData, IPv6, [Port; MAX_RULES_PORT]>,
}

impl AccessList {
    pub async fn initialize() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Initializing);
        let mut system = System::instance_mut().await;
        let ebpf = &mut system.ebpf;
        let access_list = AccessList {
            ipv4_src_white_list: AyaHashMap::try_from(
                ebpf.take_map("IPV4_SRC_WHITELIST").unwrap(),
            )?,
            ipv6_src_white_list: AyaHashMap::try_from(
                ebpf.take_map("IPV6_SRC_WHITELIST").unwrap(),
            )?,
            ipv4_dst_white_list: AyaHashMap::try_from(
                ebpf.take_map("IPV4_DST_WHITELIST").unwrap(),
            )?,
            ipv6_dst_white_list: AyaHashMap::try_from(
                ebpf.take_map("IPV6_DST_WHITELIST").unwrap(),
            )?,
            ipv4_src_black_list: AyaHashMap::try_from(
                ebpf.take_map("IPV4_SRC_BLACKLIST").unwrap(),
            )?,
            ipv6_src_black_list: AyaHashMap::try_from(
                ebpf.take_map("IPV6_SRC_BLACKLIST").unwrap(),
            )?,
            ipv4_dst_black_list: AyaHashMap::try_from(
                ebpf.take_map("IPV4_DST_BLACKLIST").unwrap(),
            )?,
            ipv6_dst_black_list: AyaHashMap::try_from(
                ebpf.take_map("IPV6_DST_BLACKLIST").unwrap(),
            )?,
        };
        ACCESS_LIST.get_or_init(|| RwLock::new(access_list));
        info!("{}", SystemEntry::InitializeComplete);
        Ok(())
    }

    #[inline(always)]
    pub async fn instance() -> RwLockReadGuard<'static, AccessList> {
        let once_lock = ACCESS_LIST.get().unwrap();
        once_lock.read().await
    }

    #[inline(always)]
    pub async fn instance_mut() -> RwLockWriteGuard<'static, AccessList> {
        let once_lock = ACCESS_LIST.get().unwrap();
        once_lock.write().await
    }

    pub async fn get_ipv4_src_white_list() -> StdHashMap<Ipv4Addr, Vec<Port>> {
        let access_list = AccessList::instance().await;
        access_list
            .ipv4_src_white_list
            .iter()
            .filter_map(Result::ok)
            .map(|(key, value)| (Ipv4Addr::from(key), convert_ports_to_vec(value)))
            .collect()
    }

    pub async fn get_ipv6_src_white_list() -> StdHashMap<Ipv6Addr, Vec<Port>> {
        let access_list = AccessList::instance().await;
        access_list
            .ipv6_src_white_list
            .iter()
            .filter_map(Result::ok)
            .map(|(key, value)| (Ipv6Addr::from(key), convert_ports_to_vec(value)))
            .collect()
    }

    pub async fn add_ipv4_src_white_list(address: SocketAddrV4) -> anyhow::Result<()> {
        let ip: u32 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        let mut new_ports = [0_u16; MAX_RULES_PORT];
        if port == 0 {
            new_ports[0] = 0;
        } else if let Ok(ports) = access_list.ipv4_src_white_list.get(&ip, 0) {
            if ports[0] == 0 {
                return Ok(());
            }
            let mut index = None;
            for (i, &value) in ports.iter().enumerate() {
                if value == port {
                    return Ok(());
                }
                if index.is_none() && value == 0 {
                    index = Some(i);
                }
            }
            if index.is_none() {
                return Err(EbpfEntry::RuleReachLimit.into());
            }
            new_ports.copy_from_slice(&ports);
            new_ports[index.unwrap()] = port;
        } else {
            new_ports[0] = port;
        }
        access_list
            .ipv4_src_white_list
            .insert(ip, new_ports, 0)
            .map_err(|_| EbpfEntry::MapOperationError)?;
        Ok(())
    }

    pub async fn add_ipv6_src_white_list(address: SocketAddrV6) -> anyhow::Result<()> {
        let ip: u128 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        let mut new_ports = [0_u16; MAX_RULES_PORT];
        if port == 0 {
            new_ports[0] = 0;
        } else if let Ok(ports) = access_list.ipv6_src_white_list.get(&ip, 0) {
            if ports[0] == 0 {
                return Ok(());
            }
            let mut index = None;
            for (i, &value) in ports.iter().enumerate() {
                if value == port {
                    return Ok(());
                }
                if index.is_none() && value == 0 {
                    index = Some(i);
                }
            }
            if index.is_none() {
                return Err(EbpfEntry::RuleReachLimit.into());
            }
            new_ports.copy_from_slice(&ports);
            new_ports[index.unwrap()] = port;
        } else {
            new_ports[0] = port;
        }
        access_list
            .ipv6_src_white_list
            .insert(ip, new_ports, 0)
            .map_err(|_| EbpfEntry::MapOperationError)?;
        Ok(())
    }

    pub async fn remove_ipv4_src_white_list(address: SocketAddrV4) -> anyhow::Result<()> {
        let ip: u32 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        if let Ok(mut ports) = access_list.ipv4_src_white_list.get(&ip, 0) {
            if port == 0 {
                access_list
                    .ipv4_src_white_list
                    .remove(&ip)
                    .map_err(|_| EbpfEntry::MapOperationError)?;
                return Ok(());
            }
            if let Some(index) = ports.iter().position(|&x| x == port) {
                for i in index..(MAX_RULES_PORT - 1) {
                    ports[i] = ports[i + 1];
                }
                ports[MAX_RULES_PORT - 1] = 0;
                if ports[0] == 0 {
                    access_list
                        .ipv4_src_white_list
                        .remove(&ip)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                } else {
                    access_list
                        .ipv4_src_white_list
                        .insert(ip, ports, 0)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                }
            }
            Ok(())
        } else {
            Err(EbpfEntry::IpDoesNotExist)?
        }
    }

    pub async fn remove_ipv6_src_white_list(address: SocketAddrV6) -> anyhow::Result<()> {
        let ip: u128 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        if let Ok(mut ports) = access_list.ipv6_src_white_list.get(&ip, 0) {
            if port == 0 {
                access_list
                    .ipv6_src_white_list
                    .remove(&ip)
                    .map_err(|_| EbpfEntry::MapOperationError)?;
                return Ok(());
            }
            if let Some(index) = ports.iter().position(|&x| x == port) {
                for i in index..(MAX_RULES_PORT - 1) {
                    ports[i] = ports[i + 1];
                }
                ports[MAX_RULES_PORT - 1] = 0;
                if ports[0] == 0 {
                    access_list
                        .ipv6_src_white_list
                        .remove(&ip)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                } else {
                    access_list
                        .ipv6_src_white_list
                        .insert(ip, ports, 0)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                }
            }
            Ok(())
        } else {
            Err(EbpfEntry::IpDoesNotExist)?
        }
    }

    pub async fn get_ipv4_dst_white_list() -> StdHashMap<Ipv4Addr, Vec<Port>> {
        let access_list = AccessList::instance().await;
        access_list
            .ipv4_dst_white_list
            .iter()
            .filter_map(Result::ok)
            .map(|(key, value)| (Ipv4Addr::from(key), convert_ports_to_vec(value)))
            .collect()
    }

    pub async fn get_ipv6_dst_white_list() -> StdHashMap<Ipv6Addr, Vec<Port>> {
        let access_list = AccessList::instance().await;
        access_list
            .ipv6_dst_white_list
            .iter()
            .filter_map(Result::ok)
            .map(|(key, value)| (Ipv6Addr::from(key), convert_ports_to_vec(value)))
            .collect()
    }

    pub async fn add_ipv4_dst_white_list(address: SocketAddrV4) -> anyhow::Result<()> {
        let ip: u32 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        let mut new_ports = [0_u16; MAX_RULES_PORT];
        if port == 0 {
            new_ports[0] = 0;
        } else if let Ok(ports) = access_list.ipv4_dst_white_list.get(&ip, 0) {
            if ports[0] == 0 {
                return Ok(());
            }
            let mut index = None;
            for (i, &value) in ports.iter().enumerate() {
                if value == port {
                    return Ok(());
                }
                if index.is_none() && value == 0 {
                    index = Some(i);
                }
            }
            if index.is_none() {
                return Err(EbpfEntry::RuleReachLimit.into());
            }
            new_ports.copy_from_slice(&ports);
            new_ports[index.unwrap()] = port;
        } else {
            new_ports[0] = port;
        }
        access_list
            .ipv4_dst_white_list
            .insert(ip, new_ports, 0)
            .map_err(|_| EbpfEntry::MapOperationError)?;
        Ok(())
    }

    pub async fn add_ipv6_dst_white_list(address: SocketAddrV6) -> anyhow::Result<()> {
        let ip: u128 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        let mut new_ports = [0_u16; MAX_RULES_PORT];
        if port == 0 {
            new_ports[0] = 0;
        } else if let Ok(ports) = access_list.ipv6_dst_white_list.get(&ip, 0) {
            if ports[0] == 0 {
                return Ok(());
            }
            let mut index = None;
            for (i, &value) in ports.iter().enumerate() {
                if value == port {
                    return Ok(());
                }
                if index.is_none() && value == 0 {
                    index = Some(i);
                }
            }
            if index.is_none() {
                return Err(EbpfEntry::RuleReachLimit.into());
            }
            new_ports.copy_from_slice(&ports);
            new_ports[index.unwrap()] = port;
        } else {
            new_ports[0] = port;
        }
        access_list
            .ipv6_dst_white_list
            .insert(ip, new_ports, 0)
            .map_err(|_| EbpfEntry::MapOperationError)?;
        Ok(())
    }

    pub async fn remove_ipv4_dst_white_list(address: SocketAddrV4) -> anyhow::Result<()> {
        let ip: u32 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        if let Ok(mut ports) = access_list.ipv4_dst_white_list.get(&ip, 0) {
            if port == 0 {
                access_list
                    .ipv4_dst_white_list
                    .remove(&ip)
                    .map_err(|_| EbpfEntry::MapOperationError)?;
                return Ok(());
            }
            if let Some(index) = ports.iter().position(|&x| x == port) {
                for i in index..(MAX_RULES_PORT - 1) {
                    ports[i] = ports[i + 1];
                }
                ports[MAX_RULES_PORT - 1] = 0;
                if ports[0] == 0 {
                    access_list
                        .ipv4_dst_white_list
                        .remove(&ip)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                } else {
                    access_list
                        .ipv4_dst_white_list
                        .insert(ip, ports, 0)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                }
            }
            Ok(())
        } else {
            Err(EbpfEntry::IpDoesNotExist)?
        }
    }

    pub async fn remove_ipv6_dst_white_list(address: SocketAddrV6) -> anyhow::Result<()> {
        let ip: u128 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        if let Ok(mut ports) = access_list.ipv6_dst_white_list.get(&ip, 0) {
            if port == 0 {
                access_list
                    .ipv6_dst_white_list
                    .remove(&ip)
                    .map_err(|_| EbpfEntry::MapOperationError)?;
                return Ok(());
            }
            if let Some(index) = ports.iter().position(|&x| x == port) {
                for i in index..(MAX_RULES_PORT - 1) {
                    ports[i] = ports[i + 1];
                }
                ports[MAX_RULES_PORT - 1] = 0;
                if ports[0] == 0 {
                    access_list
                        .ipv6_dst_white_list
                        .remove(&ip)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                } else {
                    access_list
                        .ipv6_dst_white_list
                        .insert(ip, ports, 0)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                }
            }
            Ok(())
        } else {
            Err(EbpfEntry::IpDoesNotExist)?
        }
    }

    pub async fn get_ipv4_src_black_list() -> StdHashMap<Ipv4Addr, Vec<Port>> {
        let access_list = AccessList::instance().await;
        access_list
            .ipv4_src_black_list
            .iter()
            .filter_map(Result::ok)
            .map(|(key, value)| (Ipv4Addr::from(key), convert_ports_to_vec(value)))
            .collect()
    }

    pub async fn get_ipv6_src_black_list() -> StdHashMap<Ipv6Addr, Vec<Port>> {
        let access_list = AccessList::instance().await;
        access_list
            .ipv6_src_black_list
            .iter()
            .filter_map(Result::ok)
            .map(|(key, value)| (Ipv6Addr::from(key), convert_ports_to_vec(value)))
            .collect()
    }

    pub async fn add_ipv4_src_black_list(address: SocketAddrV4) -> anyhow::Result<()> {
        let ip: u32 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        let mut new_ports = [0_u16; MAX_RULES_PORT];
        if port == 0 {
            new_ports[0] = 0;
        } else if let Ok(ports) = access_list.ipv4_src_black_list.get(&ip, 0) {
            if ports[0] == 0 {
                return Ok(());
            }
            let mut index = None;
            for (i, &value) in ports.iter().enumerate() {
                if value == port {
                    return Ok(());
                }
                if index.is_none() && value == 0 {
                    index = Some(i);
                }
            }
            if index.is_none() {
                return Err(EbpfEntry::RuleReachLimit.into());
            }
            new_ports.copy_from_slice(&ports);
            new_ports[index.unwrap()] = port;
        } else {
            new_ports[0] = port;
        }
        access_list
            .ipv4_src_black_list
            .insert(ip, new_ports, 0)
            .map_err(|_| EbpfEntry::MapOperationError)?;
        Ok(())
    }

    pub async fn add_ipv6_src_black_list(address: SocketAddrV6) -> anyhow::Result<()> {
        let ip: u128 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        let mut new_ports = [0_u16; MAX_RULES_PORT];
        if port == 0 {
            new_ports[0] = 0;
        } else if let Ok(ports) = access_list.ipv6_src_black_list.get(&ip, 0) {
            if ports[0] == 0 {
                return Ok(());
            }
            let mut index = None;
            for (i, &value) in ports.iter().enumerate() {
                if value == port {
                    return Ok(());
                }
                if index.is_none() && value == 0 {
                    index = Some(i);
                }
            }
            if index.is_none() {
                return Err(EbpfEntry::RuleReachLimit.into());
            }
            new_ports.copy_from_slice(&ports);
            new_ports[index.unwrap()] = port;
        } else {
            new_ports[0] = port;
        }
        access_list
            .ipv6_src_black_list
            .insert(ip, new_ports, 0)
            .map_err(|_| EbpfEntry::MapOperationError)?;
        Ok(())
    }

    pub async fn remove_ipv4_src_black_list(address: SocketAddrV4) -> anyhow::Result<()> {
        let ip: u32 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        if let Ok(mut ports) = access_list.ipv4_src_black_list.get(&ip, 0) {
            if port == 0 {
                access_list
                    .ipv4_src_black_list
                    .remove(&ip)
                    .map_err(|_| EbpfEntry::MapOperationError)?;
                return Ok(());
            }
            if let Some(index) = ports.iter().position(|&x| x == port) {
                for i in index..(MAX_RULES_PORT - 1) {
                    ports[i] = ports[i + 1];
                }
                ports[MAX_RULES_PORT - 1] = 0;
                if ports[0] == 0 {
                    access_list
                        .ipv4_src_black_list
                        .remove(&ip)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                } else {
                    access_list
                        .ipv4_src_black_list
                        .insert(ip, ports, 0)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                }
            }
            Ok(())
        } else {
            Err(EbpfEntry::IpDoesNotExist)?
        }
    }

    pub async fn remove_ipv6_src_black_list(address: SocketAddrV6) -> anyhow::Result<()> {
        let ip: u128 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        if let Ok(mut ports) = access_list.ipv6_src_black_list.get(&ip, 0) {
            if port == 0 {
                access_list
                    .ipv6_src_black_list
                    .remove(&ip)
                    .map_err(|_| EbpfEntry::MapOperationError)?;
                return Ok(());
            }
            if let Some(index) = ports.iter().position(|&x| x == port) {
                for i in index..(MAX_RULES_PORT - 1) {
                    ports[i] = ports[i + 1];
                }
                ports[MAX_RULES_PORT - 1] = 0;
                if ports[0] == 0 {
                    access_list
                        .ipv6_src_black_list
                        .remove(&ip)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                } else {
                    access_list
                        .ipv6_src_black_list
                        .insert(ip, ports, 0)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                }
            }
            Ok(())
        } else {
            Err(EbpfEntry::IpDoesNotExist)?
        }
    }

    pub async fn get_ipv4_dst_black_list() -> StdHashMap<Ipv4Addr, Vec<Port>> {
        let access_list = AccessList::instance().await;
        access_list
            .ipv4_dst_black_list
            .iter()
            .filter_map(Result::ok)
            .map(|(key, value)| (Ipv4Addr::from(key), convert_ports_to_vec(value)))
            .collect()
    }

    pub async fn get_ipv6_dst_black_list() -> StdHashMap<Ipv6Addr, Vec<Port>> {
        let access_list = AccessList::instance().await;
        access_list
            .ipv6_dst_black_list
            .iter()
            .filter_map(Result::ok)
            .map(|(key, value)| (Ipv6Addr::from(key), convert_ports_to_vec(value)))
            .collect()
    }

    pub async fn add_ipv4_dst_black_list(address: SocketAddrV4) -> anyhow::Result<()> {
        let ip: u32 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        let mut new_ports = [0_u16; MAX_RULES_PORT];
        if port == 0 {
            new_ports[0] = 0;
        } else if let Ok(ports) = access_list.ipv4_dst_black_list.get(&ip, 0) {
            if ports[0] == 0 {
                return Ok(());
            }
            let mut index = None;
            for (i, &value) in ports.iter().enumerate() {
                if value == port {
                    return Ok(());
                }
                if index.is_none() && value == 0 {
                    index = Some(i);
                }
            }
            if index.is_none() {
                return Err(EbpfEntry::RuleReachLimit.into());
            }
            new_ports.copy_from_slice(&ports);
            new_ports[index.unwrap()] = port;
        } else {
            new_ports[0] = port;
        }
        access_list
            .ipv4_dst_black_list
            .insert(ip, new_ports, 0)
            .map_err(|_| EbpfEntry::MapOperationError)?;
        Ok(())
    }

    pub async fn add_ipv6_dst_black_list(address: SocketAddrV6) -> anyhow::Result<()> {
        let ip: u128 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        let mut new_ports = [0_u16; MAX_RULES_PORT];
        if port == 0 {
            new_ports[0] = 0;
        } else if let Ok(ports) = access_list.ipv6_dst_black_list.get(&ip, 0) {
            if ports[0] == 0 {
                return Ok(());
            }
            let mut index = None;
            for (i, &value) in ports.iter().enumerate() {
                if value == port {
                    return Ok(());
                }
                if index.is_none() && value == 0 {
                    index = Some(i);
                }
            }
            if index.is_none() {
                return Err(EbpfEntry::RuleReachLimit.into());
            }
            new_ports.copy_from_slice(&ports);
            new_ports[index.unwrap()] = port;
        } else {
            new_ports[0] = port;
        }
        access_list
            .ipv6_dst_black_list
            .insert(ip, new_ports, 0)
            .map_err(|_| EbpfEntry::MapOperationError)?;
        Ok(())
    }

    pub async fn remove_ipv4_dst_black_list(address: SocketAddrV4) -> anyhow::Result<()> {
        let ip: u32 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        if let Ok(mut ports) = access_list.ipv4_dst_black_list.get(&ip, 0) {
            if port == 0 {
                access_list
                    .ipv4_dst_black_list
                    .remove(&ip)
                    .map_err(|_| EbpfEntry::MapOperationError)?;
                return Ok(());
            }
            if let Some(index) = ports.iter().position(|&x| x == port) {
                for i in index..(MAX_RULES_PORT - 1) {
                    ports[i] = ports[i + 1];
                }
                ports[MAX_RULES_PORT - 1] = 0;
                if ports[0] == 0 {
                    access_list
                        .ipv4_dst_black_list
                        .remove(&ip)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                } else {
                    access_list
                        .ipv4_dst_black_list
                        .insert(ip, ports, 0)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                }
            }
            Ok(())
        } else {
            Err(EbpfEntry::IpDoesNotExist)?
        }
    }

    pub async fn remove_ipv6_dst_black_list(address: SocketAddrV6) -> anyhow::Result<()> {
        let ip: u128 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessList::instance_mut().await;
        if let Ok(mut ports) = access_list.ipv6_dst_black_list.get(&ip, 0) {
            if port == 0 {
                access_list
                    .ipv6_dst_black_list
                    .remove(&ip)
                    .map_err(|_| EbpfEntry::MapOperationError)?;
                return Ok(());
            }
            if let Some(index) = ports.iter().position(|&x| x == port) {
                for i in index..(MAX_RULES_PORT - 1) {
                    ports[i] = ports[i + 1];
                }
                ports[MAX_RULES_PORT - 1] = 0;
                if ports[0] == 0 {
                    access_list
                        .ipv6_dst_black_list
                        .remove(&ip)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                } else {
                    access_list
                        .ipv6_dst_black_list
                        .insert(ip, ports, 0)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                }
            }
            Ok(())
        } else {
            Err(EbpfEntry::IpDoesNotExist)?
        }
    }
}
