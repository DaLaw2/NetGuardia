use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::{Ebpf, Pod};
use common::model::ip_address::{IPv4, IPv6, Port};
use common::model::port_rule::PortRule;
use tokio::sync::RwLock;

use crate::model::direction::FlowDirection;
use crate::model::error::ebpf::EbpfError;
use crate::model::error::Error;
use crate::model::ip_address::NativeConvert;
use crate::model::list_type::ListType;

pub struct AccessControl {
    ipv4_src_whitelist: RwLock<MapWrapper<IPv4>>,
    ipv4_src_blacklist: RwLock<MapWrapper<IPv4>>,
    ipv4_dst_whitelist: RwLock<MapWrapper<IPv4>>,
    ipv4_dst_blacklist: RwLock<MapWrapper<IPv4>>,
    ipv6_src_whitelist: RwLock<MapWrapper<IPv6>>,
    ipv6_src_blacklist: RwLock<MapWrapper<IPv6>>,
    ipv6_dst_whitelist: RwLock<MapWrapper<IPv6>>,
    ipv6_dst_blacklist: RwLock<MapWrapper<IPv6>>,
}

impl AccessControl {
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, Error> {
        let access_control = Self {
            ipv4_src_whitelist: RwLock::new(MapWrapper::new(ebpf, "IPV4_SRC_WHITELIST")?),
            ipv4_src_blacklist: RwLock::new(MapWrapper::new(ebpf, "IPV4_SRC_BLACKLIST")?),
            ipv4_dst_whitelist: RwLock::new(MapWrapper::new(ebpf, "IPV4_DST_WHITELIST")?),
            ipv4_dst_blacklist: RwLock::new(MapWrapper::new(ebpf, "IPV4_DST_BLACKLIST")?),
            ipv6_src_whitelist: RwLock::new(MapWrapper::new(ebpf, "IPV6_SRC_WHITELIST")?),
            ipv6_src_blacklist: RwLock::new(MapWrapper::new(ebpf, "IPV6_SRC_BLACKLIST")?),
            ipv6_dst_whitelist: RwLock::new(MapWrapper::new(ebpf, "IPV6_DST_WHITELIST")?),
            ipv6_dst_blacklist: RwLock::new(MapWrapper::new(ebpf, "IPV6_DST_BLACKLIST")?),
        };
        Ok(access_control)
    }

    pub async fn get_ipv4_list(&self, direction: FlowDirection, list_type: ListType) -> HashMap<Ipv4Addr, Vec<Port>> {
        let map_wrapper = match (direction, list_type) {
            (FlowDirection::Source, ListType::White) => self.ipv4_src_whitelist.read().await,
            (FlowDirection::Source, ListType::Black) => self.ipv4_src_blacklist.read().await,
            (FlowDirection::Destination, ListType::White) => self.ipv4_dst_whitelist.read().await,
            (FlowDirection::Destination, ListType::Black) => self.ipv4_dst_blacklist.read().await,
        };
        map_wrapper.get_list()
    }

    pub async fn get_ipv6_list(&self, direction: FlowDirection, list_type: ListType) -> HashMap<Ipv6Addr, Vec<Port>> {
        let map_wrapper = match (direction, list_type) {
            (FlowDirection::Source, ListType::White) => self.ipv6_src_whitelist.read().await,
            (FlowDirection::Source, ListType::Black) => self.ipv6_src_blacklist.read().await,
            (FlowDirection::Destination, ListType::White) => self.ipv6_dst_whitelist.read().await,
            (FlowDirection::Destination, ListType::Black) => self.ipv6_dst_blacklist.read().await,
        };
        map_wrapper.get_list()
    }

    pub async fn add_ipv4_list(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV4,
    ) -> Result<(), Error> {
        let ip: u32 = (*address.ip()).to_bits().to_be();
        let port = address.port();
        let mut map_wrapper = match (direction, list_type) {
            (FlowDirection::Source, ListType::White) => self.ipv4_src_whitelist.write().await,
            (FlowDirection::Source, ListType::Black) => self.ipv4_src_blacklist.write().await,
            (FlowDirection::Destination, ListType::White) => self.ipv4_dst_whitelist.write().await,
            (FlowDirection::Destination, ListType::Black) => self.ipv4_dst_blacklist.write().await,
        };
        map_wrapper.add(ip, port)
    }

    pub async fn add_ipv6_list(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV6,
    ) -> Result<(), Error> {
        let ip: u128 = (*address.ip()).to_bits().to_be();
        let port = address.port();
        let mut map_wrapper = match (direction, list_type) {
            (FlowDirection::Source, ListType::White) => self.ipv6_src_whitelist.write().await,
            (FlowDirection::Source, ListType::Black) => self.ipv6_src_blacklist.write().await,
            (FlowDirection::Destination, ListType::White) => self.ipv6_dst_whitelist.write().await,
            (FlowDirection::Destination, ListType::Black) => self.ipv6_dst_blacklist.write().await,
        };
        map_wrapper.add(ip, port)
    }

    pub async fn remove_ipv4_list(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV4,
    ) -> Result<(), Error> {
        let ip: u32 = (*address.ip()).to_bits().to_be();
        let port = address.port();
        let mut map_wrapper = match (direction, list_type) {
            (FlowDirection::Source, ListType::White) => self.ipv4_src_whitelist.write().await,
            (FlowDirection::Source, ListType::Black) => self.ipv4_src_blacklist.write().await,
            (FlowDirection::Destination, ListType::White) => self.ipv4_dst_whitelist.write().await,
            (FlowDirection::Destination, ListType::Black) => self.ipv4_dst_blacklist.write().await,
        };
        map_wrapper.remove(ip, port)
    }

    pub async fn remove_ipv6_list(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV6,
    ) -> Result<(), Error> {
        let ip: u128 = (*address.ip()).to_bits().to_be();
        let port = address.port();
        let mut map_wrapper = match (direction, list_type) {
            (FlowDirection::Source, ListType::White) => self.ipv6_src_whitelist.write().await,
            (FlowDirection::Source, ListType::Black) => self.ipv6_src_blacklist.write().await,
            (FlowDirection::Destination, ListType::White) => self.ipv6_dst_whitelist.write().await,
            (FlowDirection::Destination, ListType::Black) => self.ipv6_dst_blacklist.write().await,
        };
        map_wrapper.remove(ip, port)
    }
}

struct MapWrapper<T> {
    map: AyaHashMap<MapData, T, PortRule>,
}

impl<T: NativeConvert + Pod> MapWrapper<T> {
    fn new(ebpf: &mut Ebpf, map_name: &str) -> Result<Self, Error> {
        let map = ebpf.take_map(map_name).ok_or(EbpfError::MapNotFound)?;
        let map = AyaHashMap::try_from(map).map_err(EbpfError::MapOperationError)?;
        Ok(Self { map })
    }

    fn get_list(&self) -> HashMap<T::Native, Vec<Port>> {
        self.map
            .iter()
            .filter_map(Result::ok)
            .map(|(key, rule)| (key.into_native(), rule.to_port_vec()))
            .collect()
    }

    fn add(&mut self, ip: T, port: Port) -> Result<(), Error> {
        if port == 0 {
            self.map
                .insert(ip, PortRule::new_match_all(), 0)
                .map_err(EbpfError::MapOperationError)?;
            return Ok(());
        }

        let mut rule = self.map.get(&ip, 0).unwrap_or_else(|_| PortRule::new_empty());

        if rule.is_match_all() {
            return Ok(());
        }

        if !rule.add_port(port) {
            Err(EbpfError::RuleReachLimit)?;
        }

        self.map
            .insert(ip, rule, 0)
            .map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    fn remove(&mut self, ip: T, port: Port) -> Result<(), Error> {
        if port == 0 {
            self.map.remove(&ip).map_err(EbpfError::MapOperationError)?;
            return Ok(());
        }

        let mut rule = self.map.get(&ip, 0).map_err(|_| EbpfError::IpDoesNotExist)?;

        if rule.is_match_all() {
            self.map.remove(&ip).map_err(EbpfError::MapOperationError)?;
            return Ok(());
        }

        rule.remove_port(port);

        if rule.is_empty() {
            self.map.remove(&ip).map_err(EbpfError::MapOperationError)?;
        } else {
            self.map
                .insert(ip, rule, 0)
                .map_err(EbpfError::MapOperationError)?;
        }
        Ok(())
    }
}
