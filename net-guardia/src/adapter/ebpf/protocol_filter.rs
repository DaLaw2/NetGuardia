use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData};
use aya::{Ebpf, Pod};
use common::model::http_method::{HttpMethod, HttpMethodBitmap};
use common::model::ip_address::{AddrPortV4, AddrPortV6, IPv4, IPv6};
use common::model::placeholder::PlaceHolder;
use parking_lot::RwLock;

use crate::model::access_control::ip_address::NativeConvert;
use crate::model::error::Error;
use crate::model::error::ebpf::EbpfError;

pub struct ProtocolFilter {
    ipv4_http_service: RwLock<HttpServiceWrapper<AddrPortV4>>,
    ipv6_http_service: RwLock<HttpServiceWrapper<AddrPortV6>>,
    ssh_white_list_enable: RwLock<WhiteListControl>,
    ipv4_ssh_service: RwLock<EntryMap<AddrPortV4>>,
    ipv6_ssh_service: RwLock<EntryMap<AddrPortV6>>,
    ipv4_ssh_white_list: RwLock<EntryMap<IPv4>>,
    ipv6_ssh_white_list: RwLock<EntryMap<IPv6>>,
    ipv4_ssh_black_list: RwLock<EntryMap<IPv4>>,
    ipv6_ssh_black_list: RwLock<EntryMap<IPv6>>,
}

impl ProtocolFilter {
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, Error> {
        let service = Self {
            ipv4_http_service: RwLock::new(HttpServiceWrapper::new(ebpf, "IPV4_HTTP_SERVICE")?),
            ipv6_http_service: RwLock::new(HttpServiceWrapper::new(ebpf, "IPV6_HTTP_SERVICE")?),
            ssh_white_list_enable: RwLock::new(WhiteListControl::new(ebpf, "SSH_WHITE_LIST_ENABLE")?),
            ipv4_ssh_service: RwLock::new(EntryMap::new(ebpf, "IPV4_SSH_SERVICE")?),
            ipv6_ssh_service: RwLock::new(EntryMap::new(ebpf, "IPV6_SSH_SERVICE")?),
            ipv4_ssh_white_list: RwLock::new(EntryMap::new(ebpf, "IPV4_SSH_WHITE_LIST")?),
            ipv6_ssh_white_list: RwLock::new(EntryMap::new(ebpf, "IPV6_SSH_WHITE_LIST")?),
            ipv4_ssh_black_list: RwLock::new(EntryMap::new(ebpf, "IPV4_SSH_BLACK_LIST")?),
            ipv6_ssh_black_list: RwLock::new(EntryMap::new(ebpf, "IPV6_SSH_BLACK_LIST")?),
        };
        Ok(service)
    }

    /// Construct a ProtocolFilter backed by no eBPF maps.
    pub fn unavailable() -> Self {
        Self {
            ipv4_http_service: RwLock::new(HttpServiceWrapper::unavailable()),
            ipv6_http_service: RwLock::new(HttpServiceWrapper::unavailable()),
            ssh_white_list_enable: RwLock::new(WhiteListControl::unavailable()),
            ipv4_ssh_service: RwLock::new(EntryMap::unavailable()),
            ipv6_ssh_service: RwLock::new(EntryMap::unavailable()),
            ipv4_ssh_white_list: RwLock::new(EntryMap::unavailable()),
            ipv6_ssh_white_list: RwLock::new(EntryMap::unavailable()),
            ipv4_ssh_black_list: RwLock::new(EntryMap::unavailable()),
            ipv6_ssh_black_list: RwLock::new(EntryMap::unavailable()),
        }
    }

    pub fn get_ipv4_http_service(&self) -> HashMap<SocketAddrV4, Vec<HttpMethod>> {
        self.ipv4_http_service.read().get_http_method()
    }

    pub fn get_ipv6_http_service(&self) -> HashMap<SocketAddrV6, Vec<HttpMethod>> {
        self.ipv6_http_service.read().get_http_method()
    }

    pub fn add_ipv4_http_service(&self, address: SocketAddrV4, http_method: Vec<HttpMethod>) -> Result<(), Error> {
        self.ipv4_http_service.write().add_http_service(address, http_method)
    }

    pub fn add_ipv6_http_service(&self, address: SocketAddrV6, http_method: Vec<HttpMethod>) -> Result<(), Error> {
        self.ipv6_http_service.write().add_http_service(address, http_method)
    }

    pub fn remove_ipv4_http_service(
        &self,
        address: SocketAddrV4,
        removed_http_method: Vec<HttpMethod>,
    ) -> Result<(), Error> {
        self.ipv4_http_service
            .write()
            .remove_http_service(address, removed_http_method)
    }

    pub fn remove_ipv6_http_service(
        &self,
        address: SocketAddrV6,
        removed_http_method: Vec<HttpMethod>,
    ) -> Result<(), Error> {
        self.ipv6_http_service
            .write()
            .remove_http_service(address, removed_http_method)
    }

    pub fn is_ssh_white_list_enable(&self) -> bool {
        self.ssh_white_list_enable.read().is_white_list_enable()
    }

    pub fn enable_ssh_white_list(&self) -> Result<(), Error> {
        self.ssh_white_list_enable.write().enable_white_list()
    }

    pub fn disable_ssh_white_list(&self) -> Result<(), Error> {
        self.ssh_white_list_enable.write().disable_white_list()
    }

    pub fn get_ipv4_ssh_service(&self) -> Vec<SocketAddrV4> {
        self.ipv4_ssh_service.read().get_all()
    }

    pub fn get_ipv6_ssh_service(&self) -> Vec<SocketAddrV6> {
        self.ipv6_ssh_service.read().get_all()
    }

    pub fn add_ipv4_ssh_service(&self, address: SocketAddrV4) -> Result<(), Error> {
        self.ipv4_ssh_service.write().add(address)
    }

    pub fn add_ipv6_ssh_service(&self, address: SocketAddrV6) -> Result<(), Error> {
        self.ipv6_ssh_service.write().add(address)
    }

    pub fn remove_ipv4_ssh_service(&self, address: SocketAddrV4) -> Result<(), Error> {
        self.ipv4_ssh_service.write().remove(address)
    }

    pub fn remove_ipv6_ssh_service(&self, address: SocketAddrV6) -> Result<(), Error> {
        self.ipv6_ssh_service.write().remove(address)
    }

    pub fn get_ipv4_ssh_white_list(&self) -> Vec<Ipv4Addr> {
        self.ipv4_ssh_white_list.read().get_all()
    }

    pub fn get_ipv6_ssh_white_list(&self) -> Vec<Ipv6Addr> {
        self.ipv6_ssh_white_list.read().get_all()
    }

    pub fn add_ipv4_ssh_white_list(&self, ip: Ipv4Addr) -> Result<(), Error> {
        self.ipv4_ssh_white_list.write().add(ip)
    }

    pub fn add_ipv6_ssh_white_list(&self, ip: Ipv6Addr) -> Result<(), Error> {
        self.ipv6_ssh_white_list.write().add(ip)
    }

    pub fn remove_ipv4_ssh_white_list(&self, ip: Ipv4Addr) -> Result<(), Error> {
        self.ipv4_ssh_white_list.write().remove(ip)
    }

    pub fn remove_ipv6_ssh_white_list(&self, ip: Ipv6Addr) -> Result<(), Error> {
        self.ipv6_ssh_white_list.write().remove(ip)
    }

    pub fn get_ipv4_ssh_black_list(&self) -> Vec<Ipv4Addr> {
        self.ipv4_ssh_black_list.read().get_all()
    }

    pub fn get_ipv6_ssh_black_list(&self) -> Vec<Ipv6Addr> {
        self.ipv6_ssh_black_list.read().get_all()
    }

    pub fn add_ipv4_ssh_black_list(&self, ip: Ipv4Addr) -> Result<(), Error> {
        self.ipv4_ssh_black_list.write().add(ip)
    }

    pub fn add_ipv6_ssh_black_list(&self, ip: Ipv6Addr) -> Result<(), Error> {
        self.ipv6_ssh_black_list.write().add(ip)
    }

    pub fn remove_ipv4_ssh_black_list(&self, ip: Ipv4Addr) -> Result<(), Error> {
        self.ipv4_ssh_black_list.write().remove(ip)
    }

    pub fn remove_ipv6_ssh_black_list(&self, ip: Ipv6Addr) -> Result<(), Error> {
        self.ipv6_ssh_black_list.write().remove(ip)
    }
}

struct WhiteListControl {
    map: Option<AyaArray<MapData, PlaceHolder>>,
}

impl WhiteListControl {
    fn new(ebpf: &mut Ebpf, map_name: &str) -> Result<Self, Error> {
        let map = ebpf.take_map(map_name).ok_or(EbpfError::MapNotFound)?;
        let map = AyaArray::try_from(map).map_err(EbpfError::MapOperationError)?;
        Ok(Self { map: Some(map) })
    }

    fn unavailable() -> Self {
        Self { map: None }
    }

    fn is_white_list_enable(&self) -> bool {
        let Some(map) = self.map.as_ref() else {
            return false;
        };
        match map.get(&0, 0) {
            Ok(status) => status != 0,
            Err(_) => false,
        }
    }

    fn enable_white_list(&mut self) -> Result<(), Error> {
        let map = self.map.as_mut().ok_or(EbpfError::NotLoaded)?;
        map.set(0, 1_u8, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    fn disable_white_list(&mut self) -> Result<(), Error> {
        let map = self.map.as_mut().ok_or(EbpfError::NotLoaded)?;
        map.set(0, 0_u8, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }
}

struct HttpServiceWrapper<T> {
    map: Option<AyaHashMap<MapData, T, HttpMethodBitmap>>,
}

impl<T: NativeConvert + Pod> HttpServiceWrapper<T> {
    fn new(ebpf: &mut Ebpf, map_name: &str) -> Result<Self, Error> {
        let map = ebpf.take_map(map_name).ok_or(EbpfError::MapNotFound)?;
        let map = AyaHashMap::try_from(map).map_err(EbpfError::MapOperationError)?;
        Ok(Self { map: Some(map) })
    }

    fn unavailable() -> Self {
        Self { map: None }
    }

    fn get_http_method(&self) -> HashMap<T::Native, Vec<HttpMethod>> {
        let Some(map) = self.map.as_ref() else {
            return HashMap::new();
        };
        map.iter()
            .filter_map(Result::ok)
            .map(|(key, value)| {
                let address = key.into_native();
                (address, HttpMethod::convert_from_bitmap(value))
            })
            .collect()
    }

    fn add_http_service(&mut self, address: T::Native, http_method: Vec<HttpMethod>) -> Result<(), Error> {
        let map = self.map.as_mut().ok_or(EbpfError::NotLoaded)?;
        let address = T::from_native(address);
        let ebpf_method = HttpMethod::convert_to_bitmap(http_method);
        map.insert(address, ebpf_method, 0)
            .map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    fn remove_http_service(&mut self, address: T::Native, removed_http_method: Vec<HttpMethod>) -> Result<(), Error> {
        let map = self.map.as_mut().ok_or(EbpfError::NotLoaded)?;
        let address = T::from_native(address);
        if let Ok(current_http_method) = map.get(&address, 0) {
            let mut http_method = HttpMethod::convert_from_bitmap(current_http_method);
            http_method.retain(|method| !removed_http_method.contains(method));
            if http_method.is_empty() {
                map.remove(&address).map_err(EbpfError::MapOperationError)?;
            } else {
                let new_http_method = HttpMethod::convert_to_bitmap(http_method);
                map.insert(address, new_http_method, 0)
                    .map_err(EbpfError::MapOperationError)?;
            }
            Ok(())
        } else {
            Err(EbpfError::IpDoesNotExist)?
        }
    }
}

struct EntryMap<T> {
    map: Option<AyaHashMap<MapData, T, PlaceHolder>>,
}

impl<T: NativeConvert + Pod> EntryMap<T> {
    fn new(ebpf: &mut Ebpf, map_name: &str) -> Result<Self, Error> {
        let map = ebpf.take_map(map_name).ok_or(EbpfError::MapNotFound)?;
        let map = AyaHashMap::try_from(map).map_err(EbpfError::MapOperationError)?;
        Ok(Self { map: Some(map) })
    }

    fn unavailable() -> Self {
        Self { map: None }
    }

    fn get_all(&self) -> Vec<T::Native> {
        let Some(map) = self.map.as_ref() else {
            return Vec::new();
        };
        map.keys().filter_map(Result::ok).map(|key| key.into_native()).collect()
    }

    fn add(&mut self, key: T::Native) -> Result<(), Error> {
        let map = self.map.as_mut().ok_or(EbpfError::NotLoaded)?;
        let key = T::from_native(key);
        map.insert(key, 0_u8, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    fn remove(&mut self, key: T::Native) -> Result<(), Error> {
        let map = self.map.as_mut().ok_or(EbpfError::NotLoaded)?;
        let key = T::from_native(key);
        map.remove(&key).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }
}
