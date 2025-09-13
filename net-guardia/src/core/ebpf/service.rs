use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData};
use aya::{Ebpf, Pod};
use common::model::http_method::{HttpMethod, HttpMethodBitmap};
use common::model::ip_address::{AddrPortV4, AddrPortV6, IPv4, IPv6};
use common::model::placeholder::PlaceHolder;
use tokio::sync::RwLock;

use crate::model::error::ebpf::EbpfError;
use crate::model::error::Error;
use crate::model::ip_address::NativeConvert;

pub struct Service {
    ipv4_http_service: RwLock<HttpServiceWrapper<AddrPortV4>>,
    ipv6_http_service: RwLock<HttpServiceWrapper<AddrPortV6>>,
    ssh_white_list_enable: RwLock<WhiteListControl>,
    ipv4_ssh_service: RwLock<SshServiceWrapper<AddrPortV4>>,
    ipv6_ssh_service: RwLock<SshServiceWrapper<AddrPortV6>>,
    ipv4_ssh_white_list: RwLock<SshListWrapper<IPv4>>,
    ipv6_ssh_white_list: RwLock<SshListWrapper<IPv6>>,
    ipv4_ssh_black_list: RwLock<SshListWrapper<IPv4>>,
    ipv6_ssh_black_list: RwLock<SshListWrapper<IPv6>>,
}

impl Service {
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, Error> {
        let service = Self {
            ipv4_http_service: RwLock::new(HttpServiceWrapper::new(ebpf, "IPV4_HTTP_SERVICE")?),
            ipv6_http_service: RwLock::new(HttpServiceWrapper::new(ebpf, "IPV6_HTTP_SERVICE")?),
            ssh_white_list_enable: RwLock::new(WhiteListControl::new(ebpf, "SSH_WHITE_LIST_ENABLE")?),
            ipv4_ssh_service: RwLock::new(SshServiceWrapper::new(ebpf, "IPV4_SSH_SERVICE")?),
            ipv6_ssh_service: RwLock::new(SshServiceWrapper::new(ebpf, "IPV6_SSH_SERVICE")?),
            ipv4_ssh_white_list: RwLock::new(SshListWrapper::new(ebpf, "IPV4_SSH_WHITE_LIST")?),
            ipv6_ssh_white_list: RwLock::new(SshListWrapper::new(ebpf, "IPV6_SSH_WHITE_LIST")?),
            ipv4_ssh_black_list: RwLock::new(SshListWrapper::new(ebpf, "IPV4_SSH_BLACK_LIST")?),
            ipv6_ssh_black_list: RwLock::new(SshListWrapper::new(ebpf, "IPV6_SSH_BLACK_LIST")?),
        };
        Ok(service)
    }

    pub async fn get_ipv4_http_service(&self) -> HashMap<SocketAddrV4, Vec<HttpMethod>> {
        self.ipv4_http_service.read().await.get_http_method()
    }

    pub async fn get_ipv6_http_service(&self) -> HashMap<SocketAddrV6, Vec<HttpMethod>> {
        self.ipv6_http_service.read().await.get_http_method()
    }

    pub async fn add_ipv4_http_service(
        &self,
        address: SocketAddrV4,
        http_method: Vec<HttpMethod>,
    ) -> Result<(), Error> {
        self.ipv4_http_service
            .write()
            .await
            .add_http_service(address, http_method)
    }

    pub async fn add_ipv6_http_service(
        &self,
        address: SocketAddrV6,
        http_method: Vec<HttpMethod>,
    ) -> Result<(), Error> {
        self.ipv6_http_service
            .write()
            .await
            .add_http_service(address, http_method)
    }

    pub async fn remove_ipv4_http_service(
        &self,
        address: SocketAddrV4,
        removed_http_method: Vec<HttpMethod>,
    ) -> Result<(), Error> {
        self.ipv4_http_service
            .write()
            .await
            .remove_http_service(address, removed_http_method)
    }

    pub async fn remove_ipv6_http_service(
        &self,
        address: SocketAddrV6,
        removed_http_method: Vec<HttpMethod>,
    ) -> Result<(), Error> {
        self.ipv6_http_service
            .write()
            .await
            .remove_http_service(address, removed_http_method)
    }

    pub async fn is_ssh_white_list_enable(&self) -> bool {
        self.ssh_white_list_enable.read().await.is_white_list_enable()
    }

    pub async fn enable_ssh_white_list(&self) -> Result<(), Error> {
        self.ssh_white_list_enable.write().await.enable_white_list()
    }

    pub async fn disable_ssh_white_list(&self) -> Result<(), Error> {
        self.ssh_white_list_enable.write().await.disable_white_list()
    }

    pub async fn get_ipv4_ssh_service(&self) -> Vec<SocketAddrV4> {
        self.ipv4_ssh_service.read().await.get_ssh_service()
    }

    pub async fn get_ipv6_ssh_service(&self) -> Vec<SocketAddrV6> {
        self.ipv6_ssh_service.read().await.get_ssh_service()
    }

    pub async fn add_ipv4_ssh_service(&self, address: SocketAddrV4) -> Result<(), Error> {
        self.ipv4_ssh_service.write().await.add_ssh_service(address)
    }

    pub async fn add_ipv6_ssh_service(&self, address: SocketAddrV6) -> Result<(), Error> {
        self.ipv6_ssh_service.write().await.add_ssh_service(address)
    }

    pub async fn remove_ipv4_ssh_service(&self, address: SocketAddrV4) -> Result<(), Error> {
        self.ipv4_ssh_service.write().await.remove_ssh_service(address)
    }

    pub async fn remove_ipv6_ssh_service(&self, address: SocketAddrV6) -> Result<(), Error> {
        self.ipv6_ssh_service.write().await.remove_ssh_service(address)
    }

    pub async fn get_ipv4_ssh_white_list(&self) -> Vec<Ipv4Addr> {
        self.ipv4_ssh_white_list.read().await.get_list()
    }

    pub async fn get_ipv6_ssh_white_list(&self) -> Vec<Ipv6Addr> {
        self.ipv6_ssh_white_list.read().await.get_list()
    }

    pub async fn add_ipv4_ssh_white_list(&self, ip: Ipv4Addr) -> Result<(), Error> {
        self.ipv4_ssh_white_list.write().await.add_list(ip)
    }

    pub async fn add_ipv6_ssh_white_list(&self, ip: Ipv6Addr) -> Result<(), Error> {
        self.ipv6_ssh_white_list.write().await.add_list(ip)
    }

    pub async fn remove_ipv4_ssh_white_list(&self, ip: Ipv4Addr) -> Result<(), Error> {
        self.ipv4_ssh_white_list.write().await.remove_list(ip)
    }

    pub async fn remove_ipv6_ssh_white_list(&self, ip: Ipv6Addr) -> Result<(), Error> {
        self.ipv6_ssh_white_list.write().await.remove_list(ip)
    }

    pub async fn get_ipv4_ssh_black_list(&self) -> Vec<Ipv4Addr> {
        self.ipv4_ssh_black_list.read().await.get_list()
    }

    pub async fn get_ipv6_ssh_black_list(&self) -> Vec<Ipv6Addr> {
        self.ipv6_ssh_black_list.read().await.get_list()
    }

    pub async fn add_ipv4_ssh_black_list(&self, ip: Ipv4Addr) -> Result<(), Error> {
        self.ipv4_ssh_black_list.write().await.add_list(ip)
    }

    pub async fn add_ipv6_ssh_black_list(&self, ip: Ipv6Addr) -> Result<(), Error> {
        self.ipv6_ssh_black_list.write().await.add_list(ip)
    }

    pub async fn remove_ipv4_ssh_black_list(&self, ip: Ipv4Addr) -> Result<(), Error> {
        self.ipv4_ssh_black_list.write().await.remove_list(ip)
    }

    pub async fn remove_ipv6_ssh_black_list(&self, ip: Ipv6Addr) -> Result<(), Error> {
        self.ipv6_ssh_black_list.write().await.remove_list(ip)
    }
}

struct WhiteListControl {
    map: AyaArray<MapData, PlaceHolder>,
}

impl WhiteListControl {
    fn new(ebpf: &mut Ebpf, map_name: &str) -> Result<Self, Error> {
        let map = ebpf.take_map(map_name).ok_or(EbpfError::MapNotFound)?;
        let map = AyaArray::try_from(map).map_err(EbpfError::MapOperationError)?;
        Ok(Self { map })
    }

    fn is_white_list_enable(&self) -> bool {
        match self.map.get(&0, 0) {
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

    fn enable_white_list(&mut self) -> Result<(), Error> {
        self.map.set(0, 1_u8, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    fn disable_white_list(&mut self) -> Result<(), Error> {
        self.map.set(0, 0_u8, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }
}

struct HttpServiceWrapper<T> {
    map: AyaHashMap<MapData, T, HttpMethodBitmap>,
}

impl<T: NativeConvert + Pod> HttpServiceWrapper<T> {
    fn new(ebpf: &mut Ebpf, map_name: &str) -> Result<Self, Error> {
        let map = ebpf.take_map(map_name).ok_or(EbpfError::MapNotFound)?;
        let map = AyaHashMap::try_from(map).map_err(EbpfError::MapOperationError)?;
        Ok(Self { map })
    }

    fn get_http_method(&self) -> HashMap<T::Native, Vec<HttpMethod>> {
        self.map
            .iter()
            .filter_map(Result::ok)
            .map(|(key, value)| {
                let address = key.into_native();
                (address, HttpMethod::convert_from_bitmap(value))
            })
            .collect()
    }

    fn add_http_service(&mut self, address: T::Native, http_method: Vec<HttpMethod>) -> Result<(), Error> {
        let address = T::from_native(address);
        let ebpf_method = HttpMethod::convert_to_bitmap(http_method);
        self.map
            .insert(address, ebpf_method, 0)
            .map_err(|_| EbpfError::RuleReachLimit)?;
        Ok(())
    }

    fn remove_http_service(&mut self, address: T::Native, removed_http_method: Vec<HttpMethod>) -> Result<(), Error> {
        let address = T::from_native(address);
        if let Ok(current_http_method) = self.map.get(&address, 0) {
            let mut http_method = HttpMethod::convert_from_bitmap(current_http_method);
            http_method.retain(|method| !removed_http_method.contains(method));
            if http_method.is_empty() {
                self.map.remove(&address).map_err(EbpfError::MapOperationError)?;
            } else {
                let new_http_method = HttpMethod::convert_to_bitmap(http_method);
                self.map
                    .insert(&address, new_http_method, 0)
                    .map_err(EbpfError::MapOperationError)?;
            }
            Ok(())
        } else {
            Err(EbpfError::IpDoesNotExist)?
        }
    }
}

struct SshServiceWrapper<T> {
    map: AyaHashMap<MapData, T, PlaceHolder>,
}

impl<T: NativeConvert + Pod> SshServiceWrapper<T> {
    fn new(ebpf: &mut Ebpf, map_name: &str) -> Result<Self, Error> {
        let map = ebpf.take_map(map_name).ok_or(EbpfError::MapNotFound)?;
        let map = AyaHashMap::try_from(map).map_err(EbpfError::MapOperationError)?;
        Ok(Self { map })
    }

    fn get_ssh_service(&self) -> Vec<T::Native> {
        self.map
            .keys()
            .filter_map(Result::ok)
            .map(|key| key.into_native())
            .collect()
    }

    fn add_ssh_service(&mut self, address: T::Native) -> Result<(), Error> {
        let address = T::from_native(address);
        self.map
            .insert(address, 0_u8, 0)
            .map_err(|_| EbpfError::RuleReachLimit)?;
        Ok(())
    }

    fn remove_ssh_service(&mut self, address: T::Native) -> Result<(), Error> {
        let address = T::from_native(address);
        self.map.remove(&address).map_err(|_| EbpfError::IpDoesNotExist)?;
        Ok(())
    }
}

struct SshListWrapper<T> {
    map: AyaHashMap<MapData, T, PlaceHolder>,
}

impl<T: NativeConvert + Pod> SshListWrapper<T> {
    fn new(ebpf: &mut Ebpf, map_name: &str) -> Result<Self, Error> {
        let map = ebpf.take_map(map_name).ok_or(EbpfError::MapNotFound)?;
        let map = AyaHashMap::try_from(map).map_err(EbpfError::MapOperationError)?;
        Ok(Self { map })
    }

    fn get_list(&self) -> Vec<T::Native> {
        self.map
            .keys()
            .filter_map(Result::ok)
            .map(|key| key.into_native())
            .collect()
    }

    fn add_list(&mut self, address: T::Native) -> Result<(), Error> {
        let address = T::from_native(address);
        self.map
            .insert(address, 0_u8, 0)
            .map_err(|_| EbpfError::RuleReachLimit)?;
        Ok(())
    }

    fn remove_list(&mut self, address: T::Native) -> Result<(), Error> {
        let address = T::from_native(address);
        self.map.remove(&address).map_err(|_| EbpfError::IpDoesNotExist)?;
        Ok(())
    }
}
