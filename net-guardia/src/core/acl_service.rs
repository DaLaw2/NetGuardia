use std::net::{SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use crate::interface::port::access_control_admin::AccessControlAdminPort;
use crate::interface::port::app_repo::AppRepo;
use crate::interface::port::geo_block_api::GeoBlockPort;
use crate::model::monitoring::direction::FlowDirection;
use macros::log;

use crate::model::access_control::list_type::ListType;
use crate::model::error::Error;
use crate::model::error::ebpf::EbpfError;

/// Domain service that coordinates ACL changes between DB persistence and eBPF data plane.
/// Atomic write: eBPF first, then DB. If DB fails, rollback eBPF.
pub struct AclService {
    db: Arc<dyn AppRepo>,
    access_control: Arc<dyn AccessControlAdminPort>,
    geo_block: Arc<dyn GeoBlockPort>,
}

impl AclService {
    pub fn new(
        db: Arc<dyn AppRepo>,
        access_control: Arc<dyn AccessControlAdminPort>,
        geo_block: Arc<dyn GeoBlockPort>,
    ) -> Self {
        Self {
            db,
            access_control,
            geo_block,
        }
    }

    pub fn add_ipv4(&self, direction: FlowDirection, list_type: ListType, address: SocketAddrV4) -> Result<(), Error> {
        self.access_control.add_ipv4_list(direction, list_type, address)?;
        if let Err(e) = self.db.insert_acl_rule(
            4,
            direction_str(direction),
            list_type_str(list_type),
            &address.ip().to_string(),
            address.port(),
        ) {
            if let Err(rollback_err) = self.access_control.remove_ipv4_list(direction, list_type, address) {
                log!(EbpfError::RollbackFailed(rollback_err));
            }
            return Err(e);
        }
        Ok(())
    }

    pub fn add_ipv6(&self, direction: FlowDirection, list_type: ListType, address: SocketAddrV6) -> Result<(), Error> {
        self.access_control.add_ipv6_list(direction, list_type, address)?;
        if let Err(e) = self.db.insert_acl_rule(
            6,
            direction_str(direction),
            list_type_str(list_type),
            &address.ip().to_string(),
            address.port(),
        ) {
            if let Err(rollback_err) = self.access_control.remove_ipv6_list(direction, list_type, address) {
                log!(EbpfError::RollbackFailed(rollback_err));
            }
            return Err(e);
        }
        Ok(())
    }

    pub fn remove_ipv4(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV4,
    ) -> Result<(), Error> {
        self.access_control.remove_ipv4_list(direction, list_type, address)?;
        if let Err(e) = self.db.delete_acl_rule(
            4,
            direction_str(direction),
            list_type_str(list_type),
            &address.ip().to_string(),
            address.port(),
        ) {
            if let Err(rollback_err) = self.access_control.add_ipv4_list(direction, list_type, address) {
                log!(EbpfError::RollbackFailed(rollback_err));
            }
            return Err(e);
        }
        Ok(())
    }

    pub fn remove_ipv6(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV6,
    ) -> Result<(), Error> {
        self.access_control.remove_ipv6_list(direction, list_type, address)?;
        if let Err(e) = self.db.delete_acl_rule(
            6,
            direction_str(direction),
            list_type_str(list_type),
            &address.ip().to_string(),
            address.port(),
        ) {
            if let Err(rollback_err) = self.access_control.add_ipv6_list(direction, list_type, address) {
                log!(EbpfError::RollbackFailed(rollback_err));
            }
            return Err(e);
        }
        Ok(())
    }

    pub fn block_geo_countries(&self, codes: &[String]) -> Result<u64, Error> {
        let total = self.geo_block.block_countries(codes)?;
        if let Err(e) = codes.iter().try_for_each(|code| self.db.insert_geo_country(code)) {
            let _ = self.geo_block.unblock_countries(codes);
            return Err(e);
        }
        Ok(total)
    }

    pub fn unblock_geo_countries(&self, codes: &[String]) -> Result<u64, Error> {
        let total = self.geo_block.unblock_countries(codes)?;
        if let Err(e) = codes.iter().try_for_each(|code| self.db.delete_geo_country(code)) {
            let _ = self.geo_block.block_countries(codes);
            return Err(e);
        }
        Ok(total)
    }

    pub fn get_blocked_countries(&self) -> Vec<String> {
        self.geo_block.list_blocked()
    }

    pub fn access_control(&self) -> &dyn AccessControlAdminPort {
        self.access_control.as_ref()
    }
}

fn direction_str(d: FlowDirection) -> &'static str {
    match d {
        FlowDirection::Source => "source",
        FlowDirection::Destination => "destination",
    }
}

fn list_type_str(l: ListType) -> &'static str {
    match l {
        ListType::White => "whitelist",
        ListType::Black => "blacklist",
    }
}
