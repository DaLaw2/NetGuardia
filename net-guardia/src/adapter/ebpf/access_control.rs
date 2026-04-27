use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::{Ebpf, Pod};
use common::model::ip_address::{IPv4, IPv6, Port};
use common::model::port_rule::PortRule;
use parking_lot::RwLock;

use crate::domain::common::error::Error;
use crate::domain::data_plane::direction::FlowDirection;
use crate::domain::data_plane::error::EbpfError;
use crate::domain::data_plane::ip_address::NativeConvert;
use crate::domain::data_plane::list_type::ListType;
use crate::interface::access_control_admin::AccessControlAdminPort;

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

    pub fn unavailable() -> Self {
        Self {
            ipv4_src_whitelist: RwLock::new(MapWrapper::unavailable()),
            ipv4_src_blacklist: RwLock::new(MapWrapper::unavailable()),
            ipv4_dst_whitelist: RwLock::new(MapWrapper::unavailable()),
            ipv4_dst_blacklist: RwLock::new(MapWrapper::unavailable()),
            ipv6_src_whitelist: RwLock::new(MapWrapper::unavailable()),
            ipv6_src_blacklist: RwLock::new(MapWrapper::unavailable()),
            ipv6_dst_whitelist: RwLock::new(MapWrapper::unavailable()),
            ipv6_dst_blacklist: RwLock::new(MapWrapper::unavailable()),
        }
    }

    pub fn get_ipv4_list(&self, direction: FlowDirection, list_type: ListType) -> HashMap<Ipv4Addr, Vec<Port>> {
        let map_wrapper = match (direction, list_type) {
            (FlowDirection::Source, ListType::White) => self.ipv4_src_whitelist.read(),
            (FlowDirection::Source, ListType::Black) => self.ipv4_src_blacklist.read(),
            (FlowDirection::Destination, ListType::White) => self.ipv4_dst_whitelist.read(),
            (FlowDirection::Destination, ListType::Black) => self.ipv4_dst_blacklist.read(),
        };
        map_wrapper.get_list()
    }

    pub fn get_ipv6_list(&self, direction: FlowDirection, list_type: ListType) -> HashMap<Ipv6Addr, Vec<Port>> {
        let map_wrapper = match (direction, list_type) {
            (FlowDirection::Source, ListType::White) => self.ipv6_src_whitelist.read(),
            (FlowDirection::Source, ListType::Black) => self.ipv6_src_blacklist.read(),
            (FlowDirection::Destination, ListType::White) => self.ipv6_dst_whitelist.read(),
            (FlowDirection::Destination, ListType::Black) => self.ipv6_dst_blacklist.read(),
        };
        map_wrapper.get_list()
    }

    pub fn add_ipv4_list(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV4,
    ) -> Result<(), Error> {
        let ip: u32 = (*address.ip()).to_bits().to_be();
        let port = address.port();
        let mut map_wrapper = match (direction, list_type) {
            (FlowDirection::Source, ListType::White) => self.ipv4_src_whitelist.write(),
            (FlowDirection::Source, ListType::Black) => self.ipv4_src_blacklist.write(),
            (FlowDirection::Destination, ListType::White) => self.ipv4_dst_whitelist.write(),
            (FlowDirection::Destination, ListType::Black) => self.ipv4_dst_blacklist.write(),
        };
        map_wrapper.add(ip, port)
    }

    pub fn add_ipv6_list(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV6,
    ) -> Result<(), Error> {
        let ip: u128 = (*address.ip()).to_bits().to_be();
        let port = address.port();
        let mut map_wrapper = match (direction, list_type) {
            (FlowDirection::Source, ListType::White) => self.ipv6_src_whitelist.write(),
            (FlowDirection::Source, ListType::Black) => self.ipv6_src_blacklist.write(),
            (FlowDirection::Destination, ListType::White) => self.ipv6_dst_whitelist.write(),
            (FlowDirection::Destination, ListType::Black) => self.ipv6_dst_blacklist.write(),
        };
        map_wrapper.add(ip, port)
    }

    pub fn remove_ipv4_list(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV4,
    ) -> Result<(), Error> {
        let ip: u32 = (*address.ip()).to_bits().to_be();
        let port = address.port();
        let mut map_wrapper = match (direction, list_type) {
            (FlowDirection::Source, ListType::White) => self.ipv4_src_whitelist.write(),
            (FlowDirection::Source, ListType::Black) => self.ipv4_src_blacklist.write(),
            (FlowDirection::Destination, ListType::White) => self.ipv4_dst_whitelist.write(),
            (FlowDirection::Destination, ListType::Black) => self.ipv4_dst_blacklist.write(),
        };
        map_wrapper.remove(ip, port)
    }

    pub fn remove_ipv6_list(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV6,
    ) -> Result<(), Error> {
        let ip: u128 = (*address.ip()).to_bits().to_be();
        let port = address.port();
        let mut map_wrapper = match (direction, list_type) {
            (FlowDirection::Source, ListType::White) => self.ipv6_src_whitelist.write(),
            (FlowDirection::Source, ListType::Black) => self.ipv6_src_blacklist.write(),
            (FlowDirection::Destination, ListType::White) => self.ipv6_dst_whitelist.write(),
            (FlowDirection::Destination, ListType::Black) => self.ipv6_dst_blacklist.write(),
        };
        map_wrapper.remove(ip, port)
    }
}

impl AccessControlAdminPort for AccessControl {
    fn get_ipv4_list(&self, direction: FlowDirection, list_type: ListType) -> HashMap<Ipv4Addr, Vec<Port>> {
        self.get_ipv4_list(direction, list_type)
    }

    fn get_ipv6_list(&self, direction: FlowDirection, list_type: ListType) -> HashMap<Ipv6Addr, Vec<Port>> {
        self.get_ipv6_list(direction, list_type)
    }

    fn add_ipv4_list(&self, direction: FlowDirection, list_type: ListType, address: SocketAddrV4) -> Result<(), Error> {
        self.add_ipv4_list(direction, list_type, address)
    }

    fn add_ipv6_list(&self, direction: FlowDirection, list_type: ListType, address: SocketAddrV6) -> Result<(), Error> {
        self.add_ipv6_list(direction, list_type, address)
    }

    fn remove_ipv4_list(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV4,
    ) -> Result<(), Error> {
        self.remove_ipv4_list(direction, list_type, address)
    }

    fn remove_ipv6_list(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV6,
    ) -> Result<(), Error> {
        self.remove_ipv6_list(direction, list_type, address)
    }
}

struct MapWrapper<T> {
    map: Option<AyaHashMap<MapData, T, PortRule>>,
}

impl<T: NativeConvert + Pod> MapWrapper<T> {
    fn new(ebpf: &mut Ebpf, map_name: &str) -> Result<Self, Error> {
        let map = ebpf.take_map(map_name).ok_or(EbpfError::MapNotFound)?;
        let map = AyaHashMap::try_from(map).map_err(EbpfError::MapOperationError)?;
        Ok(Self { map: Some(map) })
    }

    fn unavailable() -> Self {
        Self { map: None }
    }

    fn get_list(&self) -> HashMap<T::Native, Vec<Port>> {
        let Some(map) = self.map.as_ref() else {
            return HashMap::new();
        };
        map.iter()
            .filter_map(Result::ok)
            .map(|(key, rule)| (key.into_native(), rule.to_port_vec()))
            .collect()
    }

    fn add(&mut self, ip: T, port: Port) -> Result<(), Error> {
        let Some(map) = self.map.as_mut() else {
            return Err(EbpfError::NotLoaded.into());
        };
        if port == 0 {
            map.insert(ip, PortRule::new_match_all(), 0)
                .map_err(EbpfError::MapOperationError)?;
            return Ok(());
        }

        let mut rule = map.get(&ip, 0).unwrap_or_else(|_| PortRule::new_empty());

        if rule.is_match_all() {
            return Ok(());
        }

        if !rule.add_port(port) {
            Err(EbpfError::RuleReachLimit)?;
        }

        map.insert(ip, rule, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    fn remove(&mut self, ip: T, port: Port) -> Result<(), Error> {
        let Some(map) = self.map.as_mut() else {
            return Err(EbpfError::NotLoaded.into());
        };
        if port == 0 {
            map.remove(&ip).map_err(EbpfError::MapOperationError)?;
            return Ok(());
        }

        let mut rule = map.get(&ip, 0).map_err(|_| EbpfError::IpDoesNotExist)?;

        if rule.is_match_all() {
            map.remove(&ip).map_err(EbpfError::MapOperationError)?;
            return Ok(());
        }

        rule.remove_port(port);

        if rule.is_empty() {
            map.remove(&ip).map_err(EbpfError::MapOperationError)?;
        } else {
            map.insert(ip, rule, 0).map_err(EbpfError::MapOperationError)?;
        }
        Ok(())
    }
}
