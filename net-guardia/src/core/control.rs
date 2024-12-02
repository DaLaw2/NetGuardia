use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::OnceLock;
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{error, info};
use net_guardia_common::MAX_RULES_PORT;
use net_guardia_common::model::http_method::EbpfHttpMethod;
use net_guardia_common::model::ip_address::{EbpfAddrPortV4, EbpfAddrPortV6, IPv4, IPv6, Port};
use net_guardia_common::model::placeholder::PlaceHolder;
use crate::core::system::System;
use crate::utils::log_entry::system::SystemEntry;

static CONTROL: OnceLock<RwLock<Control>> = OnceLock::new();

pub struct Control {
    ipv4_black_list: AyaHashMap<MapData, IPv4, [Port; MAX_RULES_PORT]>,
    ipv6_black_list: AyaHashMap<MapData, IPv6, [Port; MAX_RULES_PORT]>,
    ipv4_http_service: AyaHashMap<MapData, EbpfAddrPortV4, EbpfHttpMethod>,
    ipv6_http_service: AyaHashMap<MapData, EbpfAddrPortV6, EbpfHttpMethod>,
    ssh_white_list_only: AyaArray<MapData, PlaceHolder>,
    ipv4_ssh_service: AyaHashMap<MapData, EbpfAddrPortV4, PlaceHolder>,
    ipv6_ssh_service: AyaHashMap<MapData, EbpfAddrPortV6, PlaceHolder>,
    ipv4_ssh_white_list: AyaHashMap<MapData, IPv4, PlaceHolder>,
    ipv6_ssh_white_list: AyaHashMap<MapData, IPv6, PlaceHolder>,
    ipv4_ssh_black_list: AyaHashMap<MapData, IPv4, PlaceHolder>,
    ipv6_ssh_black_list: AyaHashMap<MapData, IPv6, PlaceHolder>,
    ipv4_scanner_list: AyaHashMap<MapData, IPv4, PlaceHolder>,
    ipv6_scanner_list: AyaHashMap<MapData, IPv6, PlaceHolder>
}

impl Control {
    pub async fn initialize() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Initializing);
        let mut system = System::instance_mut().await;
        let mut ebpf = &mut system.ebpf;
        let control = Control {
            ipv4_black_list: AyaHashMap::try_from(ebpf.take_map("IPV4_BLACKLIST").unwrap())?,
            ipv6_black_list: AyaHashMap::try_from(ebpf.take_map("IPV6_BLACKLIST").unwrap())?,
            ipv4_http_service: AyaHashMap::try_from(ebpf.take_map("IPV4_HTTP_SERVICE").unwrap())?,
            ipv6_http_service: AyaHashMap::try_from(ebpf.take_map("IPV6_HTTP_SERVICE").unwrap())?,
            ssh_white_list_only: AyaArray::try_from(ebpf.take_map("SSH_WHITE_LIST_ONLY").unwrap())?,
            ipv4_ssh_service: AyaHashMap::try_from(ebpf.take_map("IPV4_SSH_SERVICE").unwrap())?,
            ipv6_ssh_service: AyaHashMap::try_from(ebpf.take_map("IPV6_SSH_SERVICE").unwrap())?,
            ipv4_ssh_white_list: AyaHashMap::try_from(ebpf.take_map("IPV4_SSH_WHITE_LIST").unwrap())?,
            ipv6_ssh_white_list: AyaHashMap::try_from(ebpf.take_map("IPV6_SSH_WHITE_LIST").unwrap())?,
            ipv4_ssh_black_list: AyaHashMap::try_from(ebpf.take_map("IPV4_SSH_BLACK_LIST").unwrap())?,
            ipv6_ssh_black_list: AyaHashMap::try_from(ebpf.take_map("IPV6_SSH_BLACK_LIST").unwrap())?,
            ipv4_scanner_list: AyaHashMap::try_from(ebpf.take_map("IPV4_SCANNER_LIST").unwrap())?,
            ipv6_scanner_list: AyaHashMap::try_from(ebpf.take_map("IPV6_SCANNER_LIST").unwrap())?,
        };
        CONTROL.get_or_init(|| RwLock::new(control));
        info!("{}", SystemEntry::InitializeComplete);
        Ok(())
    }

    #[inline(always)]
    pub async fn instance() -> RwLockReadGuard<'static, Control> {
        // Initialization has been ensured
        let once_lock = CONTROL.get().unwrap();
        // There is no lock acquired multiple times, so this is safe
        once_lock.read().await
    }

    #[inline(always)]
    pub async fn instance_mut() -> RwLockWriteGuard<'static, Control> {
        // Initialization has been ensured
        let once_lock = CONTROL.get().unwrap();
        // There is no lock acquired multiple times, so this is safe
        once_lock.write().await
    }

    pub async fn add_ipv4_http_service(address: SocketAddrV4, ) {

    }

    pub async fn enable_ssh_white_list() {
        let control = Control::instance().await;
        if control.ssh_white_list_only.set(0, 0_u8, 0).is_err() {
            error!(" ");
        }
    }

    pub async fn add_ipv4_ssh_white_list(ip: Ipv4Addr) {
        let ip: u32 = ip.into();
        let mut control = Control::instance_mut().await;
        if control.ipv4_ssh_white_list.insert(ip, 0_u8, 0).is_err() {
            error!(" ");
        }
    }

    pub async fn add_ipv6_ssh_white_list(ip: Ipv6Addr) {
        let ip: u128 = ip.into();
        let mut control = Control::instance_mut().await;
        if control.ipv6_ssh_white_list.insert(ip, 0_u8, 0).is_err() {
            error!(" ");
        }
    }

    pub async fn add_ipv4_ssh_black_list(ip: Ipv4Addr) {
        let ip: u32 = ip.into();
        let mut control = Control::instance_mut().await;
        if control.ipv4_ssh_black_list.insert(ip, 0_u8, 0).is_err() {
            error!(" ");
        }
    }

    pub async fn add_ipv6_ssh_black_list(ip: Ipv6Addr) {
        let ip: u128 = ip.into();
        let mut control = Control::instance_mut().await;
        if control.ipv6_ssh_black_list.insert(ip, 0_u8, 0).is_err() {
            error!(" ");
        }
    }
}
