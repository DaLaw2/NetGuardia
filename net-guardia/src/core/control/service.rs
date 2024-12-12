use crate::core::system::System;
use crate::model::http_method::HttpMethod;
use crate::utils::log_entry::ebpf::EbpfEntry;
use crate::utils::log_entry::system::SystemEntry;
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData};
use net_guardia_common::model::http_method::EbpfHttpMethod;
use net_guardia_common::model::ip_address::{EbpfAddrPortV4, EbpfAddrPortV6, IPv4, IPv6};
use net_guardia_common::model::placeholder::PlaceHolder;
use std::collections::HashMap as StdHashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::OnceLock;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{error, info};

static SERVICE: OnceLock<RwLock<Service>> = OnceLock::new();

pub struct Service {
    ipv4_http_service: AyaHashMap<MapData, EbpfAddrPortV4, EbpfHttpMethod>,
    ipv6_http_service: AyaHashMap<MapData, EbpfAddrPortV6, EbpfHttpMethod>,
    ssh_white_list_enable: AyaArray<MapData, PlaceHolder>,
    ipv4_ssh_service: AyaHashMap<MapData, EbpfAddrPortV4, PlaceHolder>,
    ipv6_ssh_service: AyaHashMap<MapData, EbpfAddrPortV6, PlaceHolder>,
    ipv4_ssh_white_list: AyaHashMap<MapData, IPv4, PlaceHolder>,
    ipv6_ssh_white_list: AyaHashMap<MapData, IPv6, PlaceHolder>,
    ipv4_ssh_black_list: AyaHashMap<MapData, IPv4, PlaceHolder>,
    ipv6_ssh_black_list: AyaHashMap<MapData, IPv6, PlaceHolder>,
    ipv4_scanner_list: AyaHashMap<MapData, IPv4, PlaceHolder>,
    ipv6_scanner_list: AyaHashMap<MapData, IPv6, PlaceHolder>,
}

impl Service {
    pub async fn initialize() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Initializing);
        let mut system = System::instance_mut().await;
        let ebpf = &mut system.ebpf;
        let mut service = Service {
            ipv4_http_service: AyaHashMap::try_from(ebpf.take_map("IPV4_HTTP_SERVICE").unwrap())?,
            ipv6_http_service: AyaHashMap::try_from(ebpf.take_map("IPV6_HTTP_SERVICE").unwrap())?,
            ssh_white_list_enable: AyaArray::try_from(
                ebpf.take_map("SSH_WHITE_LIST_ENABLE").unwrap(),
            )?,
            ipv4_ssh_service: AyaHashMap::try_from(ebpf.take_map("IPV4_SSH_SERVICE").unwrap())?,
            ipv6_ssh_service: AyaHashMap::try_from(ebpf.take_map("IPV6_SSH_SERVICE").unwrap())?,
            ipv4_ssh_white_list: AyaHashMap::try_from(
                ebpf.take_map("IPV4_SSH_WHITE_LIST").unwrap(),
            )?,
            ipv6_ssh_white_list: AyaHashMap::try_from(
                ebpf.take_map("IPV6_SSH_WHITE_LIST").unwrap(),
            )?,
            ipv4_ssh_black_list: AyaHashMap::try_from(
                ebpf.take_map("IPV4_SSH_BLACK_LIST").unwrap(),
            )?,
            ipv6_ssh_black_list: AyaHashMap::try_from(
                ebpf.take_map("IPV6_SSH_BLACK_LIST").unwrap(),
            )?,
            ipv4_scanner_list: AyaHashMap::try_from(ebpf.take_map("IPV4_SCANNER_LIST").unwrap())?,
            ipv6_scanner_list: AyaHashMap::try_from(ebpf.take_map("IPV6_SCANNER_LIST").unwrap())?,
        };
        if service.ssh_white_list_enable.set(0, 0_u8, 0).is_err() {
            error!(" ");
        }
        SERVICE.get_or_init(|| RwLock::new(service));
        info!("{}", SystemEntry::InitializeComplete);
        Ok(())
    }

    #[inline(always)]
    pub async fn instance() -> RwLockReadGuard<'static, Service> {
        let once_lock = SERVICE.get().unwrap();
        once_lock.read().await
    }

    #[inline(always)]
    pub async fn instance_mut() -> RwLockWriteGuard<'static, Service> {
        let once_lock = SERVICE.get().unwrap();
        once_lock.write().await
    }

    pub async fn get_ipv4_http_service() -> StdHashMap<SocketAddrV4, Vec<HttpMethod>> {
        let service = Service::instance().await;
        service
            .ipv4_http_service
            .iter()
            .filter_map(Result::ok)
            .map(|(key, value)| {
                let address = Ipv4Addr::from(key[0]);
                let port = key[1] as u16;
                (
                    SocketAddrV4::new(address, port),
                    HttpMethod::convert_from_ebpf(value),
                )
            })
            .collect()
    }

    pub async fn get_ipv6_http_service() -> StdHashMap<SocketAddrV6, Vec<HttpMethod>> {
        let service = Service::instance().await;
        service
            .ipv6_http_service
            .iter()
            .filter_map(Result::ok)
            .map(|(key, value)| {
                let address = Ipv6Addr::from(key[0]);
                let port = key[1] as u16;
                (
                    SocketAddrV6::new(address, port, 0, 0),
                    HttpMethod::convert_from_ebpf(value),
                )
            })
            .collect()
    }

    pub async fn add_ipv4_http_service(
        address: SocketAddrV4,
        http_method: Vec<HttpMethod>,
    ) -> anyhow::Result<()> {
        let ip: u32 = (*address.ip()).into();
        let port = address.port();
        let addr_port = [ip, port as u32];
        let ebpf_method = HttpMethod::convert_to_ebpf(http_method);
        let mut service = Service::instance_mut().await;
        service
            .ipv4_http_service
            .insert(addr_port, ebpf_method, 0)
            .map_err(|_| EbpfEntry::RuleReachLimit)?;
        Ok(())
    }

    pub async fn add_ipv6_http_service(
        address: SocketAddrV6,
        http_method: Vec<HttpMethod>,
    ) -> anyhow::Result<()> {
        let ip: u128 = (*address.ip()).into();
        let port = address.port();
        let addr_port = [ip, port as u128];
        let ebpf_method = HttpMethod::convert_to_ebpf(http_method);
        let mut service = Service::instance_mut().await;
        service
            .ipv6_http_service
            .insert(addr_port, ebpf_method, 0)
            .map_err(|_| EbpfEntry::RuleReachLimit)?;
        Ok(())
    }

    pub async fn remove_ipv4_http_service(
        address: SocketAddrV4,
        removed_http_method: Vec<HttpMethod>,
    ) -> anyhow::Result<()> {
        let ip: u32 = (*address.ip()).into();
        let port = address.port();
        let addr_port = [ip, port as u32];
        let mut service = Service::instance_mut().await;
        if let Ok(current_http_method) = service.ipv4_http_service.get(&addr_port, 0) {
            let mut http_method = HttpMethod::convert_from_ebpf(current_http_method);
            http_method.retain(|method| !removed_http_method.contains(method));
            if http_method.is_empty() {
                service
                    .ipv4_http_service
                    .remove(&addr_port)
                    .map_err(|_| EbpfEntry::MapOperationError)?;
            } else {
                let new_http_method = HttpMethod::convert_to_ebpf(http_method);
                service
                    .ipv4_http_service
                    .insert(&addr_port, new_http_method, 0)
                    .map_err(|_| EbpfEntry::MapOperationError)?;
            }
            Ok(())
        } else {
            Err(EbpfEntry::IpDoesNotExist)?
        }
    }

    pub async fn remove_ipv6_http_service(
        address: SocketAddrV6,
        removed_http_method: Vec<HttpMethod>,
    ) -> anyhow::Result<()> {
        let ip: u128 = (*address.ip()).into();
        let port = address.port();
        let addr_port = [ip, port as u128];
        let mut service = Service::instance_mut().await;
        if let Ok(current_http_method) = service.ipv6_http_service.get(&addr_port, 0) {
            let mut http_method = HttpMethod::convert_from_ebpf(current_http_method);
            http_method.retain(|method| !removed_http_method.contains(method));
            if http_method.is_empty() {
                service
                    .ipv6_http_service
                    .remove(&addr_port)
                    .map_err(|_| EbpfEntry::MapOperationError)?;
            } else {
                let new_http_method = HttpMethod::convert_to_ebpf(http_method);
                service
                    .ipv6_http_service
                    .insert(&addr_port, new_http_method, 0)
                    .map_err(|_| EbpfEntry::MapOperationError)?;
            }
            Ok(())
        } else {
            Err(EbpfEntry::IpDoesNotExist)?
        }
    }

    pub async fn is_ssh_white_list_enable() -> bool {
        let service = Service::instance().await;
        match service.ssh_white_list_enable.get(&0, 0) {
            Ok(status) => {
                if status == 0 {
                    false
                } else {
                    true
                }
            }
            Err(_) => false,
        }
    }

    pub async fn enable_ssh_white_list() -> anyhow::Result<()> {
        let mut service = Service::instance_mut().await;
        service
            .ssh_white_list_enable
            .set(0, 1_u8, 0)
            .map_err(|_| EbpfEntry::MapOperationError)?;
        Ok(())
    }

    pub async fn disable_ssh_white_list() -> anyhow::Result<()> {
        let mut service = Service::instance_mut().await;
        service
            .ssh_white_list_enable
            .set(0, 0_u8, 0)
            .map_err(|_| EbpfEntry::MapOperationError)?;
        Ok(())
    }

    pub async fn get_ipv4_ssh_service() -> Vec<SocketAddrV4> {
        let service = Service::instance().await;
        service
            .ipv4_ssh_service
            .keys()
            .filter_map(Result::ok)
            .map(|key| SocketAddrV4::new(Ipv4Addr::from(key[0]), key[1] as u16))
            .collect()
    }

    pub async fn get_ipv6_ssh_service() -> Vec<SocketAddrV6> {
        let service = Service::instance().await;
        service
            .ipv6_ssh_service
            .keys()
            .filter_map(Result::ok)
            .map(|key| SocketAddrV6::new(Ipv6Addr::from(key[0]), key[1] as u16, 0, 0))
            .collect()
    }

    pub async fn add_ipv4_ssh_service(address: SocketAddrV4) -> anyhow::Result<()> {
        let ip: u32 = (*address.ip()).into();
        let port = address.port();
        let addr_port = [ip, port as u32];
        let mut service = Service::instance_mut().await;
        service
            .ipv4_ssh_service
            .insert(&addr_port, 0_u8, 0)
            .map_err(|_| EbpfEntry::RuleReachLimit)?;
        Ok(())
    }

    pub async fn add_ipv6_ssh_service(address: SocketAddrV6) -> anyhow::Result<()> {
        let ip: u128 = (*address.ip()).into();
        let port = address.port();
        let addr_port = [ip, port as u128];
        let mut service = Service::instance_mut().await;
        service
            .ipv6_ssh_service
            .insert(&addr_port, 0_u8, 0)
            .map_err(|_| EbpfEntry::RuleReachLimit)?;
        Ok(())
    }

    pub async fn remove_ipv4_ssh_service(address: SocketAddrV4) -> anyhow::Result<()> {
        let ip: u32 = (*address.ip()).into();
        let port = address.port();
        let addr_port = [ip, port as u32];
        let mut service = Service::instance_mut().await;
        service
            .ipv4_ssh_service
            .remove(&addr_port)
            .map_err(|_| EbpfEntry::IpDoesNotExist)?;
        Ok(())
    }

    pub async fn remove_ipv6_ssh_service(address: SocketAddrV6) -> anyhow::Result<()> {
        let ip: u128 = (*address.ip()).into();
        let port = address.port();
        let addr_port = [ip, port as u128];
        let mut service = Service::instance_mut().await;
        service
            .ipv6_ssh_service
            .remove(&addr_port)
            .map_err(|_| EbpfEntry::IpDoesNotExist)?;
        Ok(())
    }

    pub async fn get_ipv4_ssh_white_list() -> Vec<Ipv4Addr> {
        let service = Service::instance().await;
        service
            .ipv4_ssh_white_list
            .keys()
            .filter_map(Result::ok)
            .map(|key| Ipv4Addr::from(key))
            .collect()
    }

    pub async fn get_ipv6_ssh_white_list() -> Vec<Ipv6Addr> {
        let service = Service::instance().await;
        service
            .ipv6_ssh_white_list
            .keys()
            .filter_map(Result::ok)
            .map(|key| Ipv6Addr::from(key))
            .collect()
    }

    pub async fn add_ipv4_ssh_white_list(ip: Ipv4Addr) -> anyhow::Result<()> {
        let ip: u32 = ip.into();
        let mut service = Service::instance_mut().await;
        service
            .ipv4_ssh_white_list
            .insert(ip, 0_u8, 0)
            .map_err(|_| EbpfEntry::RuleReachLimit)?;
        Ok(())
    }

    pub async fn add_ipv6_ssh_white_list(ip: Ipv6Addr) -> anyhow::Result<()> {
        let ip: u128 = ip.into();
        let mut service = Service::instance_mut().await;
        service
            .ipv6_ssh_white_list
            .insert(ip, 0_u8, 0)
            .map_err(|_| EbpfEntry::RuleReachLimit)?;
        Ok(())
    }

    pub async fn remove_ipv4_ssh_white_list(ip: Ipv4Addr) -> anyhow::Result<()> {
        let ip: u32 = ip.into();
        let mut service = Service::instance_mut().await;
        service
            .ipv4_ssh_white_list
            .remove(&ip)
            .map_err(|_| EbpfEntry::IpDoesNotExist)?;
        Ok(())
    }

    pub async fn remove_ipv6_ssh_white_list(ip: Ipv6Addr) -> anyhow::Result<()> {
        let ip: u128 = ip.into();
        let mut service = Service::instance_mut().await;
        service
            .ipv6_ssh_white_list
            .remove(&ip)
            .map_err(|_| EbpfEntry::IpDoesNotExist)?;
        Ok(())
    }

    pub async fn get_ipv4_ssh_black_list() -> Vec<Ipv4Addr> {
        let service = Service::instance().await;
        service
            .ipv4_ssh_black_list
            .keys()
            .filter_map(Result::ok)
            .map(|key| Ipv4Addr::from(key))
            .collect()
    }

    pub async fn get_ipv6_ssh_black_list() -> Vec<Ipv6Addr> {
        let service = Service::instance().await;
        service
            .ipv6_ssh_black_list
            .keys()
            .filter_map(Result::ok)
            .map(|key| Ipv6Addr::from(key))
            .collect()
    }

    pub async fn add_ipv4_ssh_black_list(ip: Ipv4Addr) -> anyhow::Result<()> {
        let ip: u32 = ip.into();
        let mut service = Service::instance_mut().await;
        service
            .ipv4_ssh_black_list
            .insert(ip, 0_u8, 0)
            .map_err(|_| EbpfEntry::RuleReachLimit)?;
        Ok(())
    }

    pub async fn add_ipv6_ssh_black_list(ip: Ipv6Addr) -> anyhow::Result<()> {
        let ip: u128 = ip.into();
        let mut service = Service::instance_mut().await;
        service
            .ipv6_ssh_black_list
            .insert(ip, 0_u8, 0)
            .map_err(|_| EbpfEntry::RuleReachLimit)?;
        Ok(())
    }

    pub async fn remove_ipv4_ssh_black_list(ip: Ipv4Addr) -> anyhow::Result<()> {
        let ip: u32 = ip.into();
        let mut service = Service::instance_mut().await;
        service
            .ipv4_ssh_black_list
            .remove(&ip)
            .map_err(|_| EbpfEntry::IpDoesNotExist)?;
        Ok(())
    }

    pub async fn remove_ipv6_ssh_black_list(ip: Ipv6Addr) -> anyhow::Result<()> {
        let ip: u128 = ip.into();
        let mut service = Service::instance_mut().await;
        service
            .ipv6_ssh_black_list
            .remove(&ip)
            .map_err(|_| EbpfEntry::IpDoesNotExist)?;
        Ok(())
    }

    pub async fn get_ipv4_scanner_list() -> Vec<Ipv4Addr> {
        let service = Service::instance().await;
        service
            .ipv4_scanner_list
            .keys()
            .filter_map(Result::ok)
            .map(|key| Ipv4Addr::from(key))
            .collect()
    }

    pub async fn get_ipv6_scanner_list() -> Vec<Ipv6Addr> {
        let service = Service::instance().await;
        service
            .ipv6_scanner_list
            .keys()
            .filter_map(Result::ok)
            .map(|key| Ipv6Addr::from(key))
            .collect()
    }

    pub async fn remove_ipv4_scanner_list(ip: Ipv4Addr) -> anyhow::Result<()> {
        let ip: u32 = ip.into();
        let mut service = Service::instance_mut().await;
        service
            .ipv4_scanner_list
            .remove(&ip)
            .map_err(|_| EbpfEntry::IpDoesNotExist)?;
        Ok(())
    }

    pub async fn remove_ipv6_scanner_list(ip: Ipv6Addr) -> anyhow::Result<()> {
        let ip: u128 = ip.into();
        let mut service = Service::instance_mut().await;
        service
            .ipv6_scanner_list
            .remove(&ip)
            .map_err(|_| EbpfEntry::IpDoesNotExist)?;
        Ok(())
    }
}
