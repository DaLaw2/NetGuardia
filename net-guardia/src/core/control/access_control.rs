use crate::core::system::System;
use crate::model::direction::FlowDirection;
use crate::model::ip_address::IntoNative;
use crate::model::list_type::ListType;
use crate::utils::ip_address::convert_ports_to_vec;
use crate::utils::log_entry::ebpf::EbpfEntry;
use crate::utils::log_entry::system::SystemEntry;
use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::Pod;
use net_guardia_common::model::ip_address::{IPv4, IPv6, Port};
use net_guardia_common::MAX_RULES_PORT;
use std::collections::HashMap as StdHashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::OnceLock;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::info;

static ACCESS_CONTROL: OnceLock<RwLock<AccessControl>> = OnceLock::new();

pub struct AccessControl {
    ipv4_maps: StdHashMap<(FlowDirection, ListType), AccessMap<IPv4>>,
    ipv6_maps: StdHashMap<(FlowDirection, ListType), AccessMap<IPv6>>,
}

impl AccessControl {
    const MAP_CONFIGS: [((FlowDirection, ListType), (&'static str, &'static str)); 4] = [
        (
            (FlowDirection::Source, ListType::White),
            ("IPV4_SRC_WHITELIST", "IPV6_SRC_WHITELIST"),
        ),
        (
            (FlowDirection::Source, ListType::Black),
            ("IPV4_SRC_BLACKLIST", "IPV6_SRC_BLACKLIST"),
        ),
        (
            (FlowDirection::Destination, ListType::White),
            ("IPV4_DST_WHITELIST", "IPV6_DST_WHITELIST"),
        ),
        (
            (FlowDirection::Destination, ListType::Black),
            ("IPV4_DST_BLACKLIST", "IPV6_DST_BLACKLIST"),
        ),
    ];

    pub async fn initialize() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Initializing);
        let mut system = System::instance_mut().await;
        let ebpf = &mut system.ingress_ebpf;
        let mut ipv4_maps = StdHashMap::new();
        let mut ipv6_maps = StdHashMap::new();
        for (key, (ipv4_name, ipv6_name)) in Self::MAP_CONFIGS {
            ipv4_maps.insert(
                key,
                AccessMap {
                    map: AyaHashMap::try_from(ebpf.take_map(ipv4_name).unwrap())?,
                },
            );
            ipv6_maps.insert(
                key,
                AccessMap {
                    map: AyaHashMap::try_from(ebpf.take_map(ipv6_name).unwrap())?,
                },
            );
        }
        ACCESS_CONTROL.get_or_init(|| {
            RwLock::new(AccessControl {
                ipv4_maps,
                ipv6_maps,
            })
        });
        info!("{}", SystemEntry::InitializeComplete);
        Ok(())
    }

    #[inline(always)]
    pub async fn instance() -> RwLockReadGuard<'static, AccessControl> {
        let once_lock = ACCESS_CONTROL.get().unwrap();
        once_lock.read().await
    }

    #[inline(always)]
    pub async fn instance_mut() -> RwLockWriteGuard<'static, AccessControl> {
        let once_lock = ACCESS_CONTROL.get().unwrap();
        once_lock.write().await
    }

    pub async fn get_ipv4_list(
        direction: FlowDirection,
        list_type: ListType,
    ) -> StdHashMap<Ipv4Addr, Vec<Port>> {
        let access_list = AccessControl::instance().await;
        access_list
            .ipv4_maps
            .get(&(direction, list_type))
            .map(|map| map.get_list())
            .unwrap()
    }

    pub async fn get_ipv6_list(
        direction: FlowDirection,
        list_type: ListType,
    ) -> StdHashMap<Ipv6Addr, Vec<Port>> {
        let access_list = AccessControl::instance().await;
        access_list
            .ipv6_maps
            .get(&(direction, list_type))
            .map(|map| map.get_list())
            .unwrap()
    }

    pub async fn add_ipv4_list(
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV4,
    ) -> anyhow::Result<()> {
        let ip: u32 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessControl::instance_mut().await;
        let map = access_list
            .ipv4_maps
            .get_mut(&(direction, list_type))
            .unwrap();
        map.add(ip, port)
    }

    pub async fn add_ipv6_list(
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV6,
    ) -> anyhow::Result<()> {
        let ip: u128 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessControl::instance_mut().await;
        let map = access_list
            .ipv6_maps
            .get_mut(&(direction, list_type))
            .unwrap();
        map.add(ip, port)
    }

    pub async fn remove_ipv4_list(
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV4,
    ) -> anyhow::Result<()> {
        let ip: u32 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessControl::instance_mut().await;
        let map = access_list
            .ipv4_maps
            .get_mut(&(direction, list_type))
            .unwrap();
        map.remove(ip, port)
    }

    pub async fn remove_ipv6_list(
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV6,
    ) -> anyhow::Result<()> {
        let ip: u128 = (*address.ip()).into();
        let port = address.port();
        let mut access_list = AccessControl::instance_mut().await;
        let map = access_list
            .ipv6_maps
            .get_mut(&(direction, list_type))
            .unwrap();
        map.remove(ip, port)
    }
}

struct AccessMap<T> {
    map: AyaHashMap<MapData, T, [Port; MAX_RULES_PORT]>,
}

impl<T: IntoNative + Pod> AccessMap<T> {
    fn get_list(&self) -> StdHashMap<T::Native, Vec<Port>> {
        self.map
            .iter()
            .filter_map(Result::ok)
            .map(|(key, value)| (key.into_native(), convert_ports_to_vec(value)))
            .collect()
    }

    fn add(&mut self, ip: T, port: Port) -> anyhow::Result<()> {
        let mut new_ports = [0_u16; MAX_RULES_PORT];
        if port == 0 {
            new_ports[0] = 0;
        } else if let Ok(ports) = self.map.get(&ip, 0) {
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
        self.map
            .insert(ip, new_ports, 0)
            .map_err(|_| EbpfEntry::MapOperationError)?;
        Ok(())
    }

    fn remove(&mut self, ip: T, port: Port) -> anyhow::Result<()> {
        if let Ok(mut ports) = self.map.get(&ip, 0) {
            if port == 0 {
                self.map
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
                    self.map
                        .remove(&ip)
                        .map_err(|_| EbpfEntry::MapOperationError)?;
                } else {
                    self.map
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
