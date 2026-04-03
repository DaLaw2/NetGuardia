use std::net::{SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use crate::core::ebpf::access_control::AccessControl;
use crate::core::ebpf::geo_block::GeoBlock;
use crate::interface::port::repository::RepositoryPort;
use crate::model::direction::FlowDirection;
use macros::log;

use crate::model::error::Error;
use crate::model::error::ebpf::EbpfError;
use crate::model::list_type::ListType;

/// Domain service that coordinates ACL changes between DB persistence and eBPF data plane.
/// Atomic write: eBPF first, then DB. If DB fails, rollback eBPF.
pub struct AclService {
    db: Arc<dyn RepositoryPort>,
    access_control: Arc<AccessControl>,
    geo_block: Arc<GeoBlock>,
}

impl AclService {
    pub fn new(db: Arc<dyn RepositoryPort>, access_control: Arc<AccessControl>, geo_block: Arc<GeoBlock>) -> Self {
        Self {
            db,
            access_control,
            geo_block,
        }
    }

    pub async fn add_ipv4(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV4,
    ) -> Result<(), Error> {
        self.access_control.add_ipv4_list(direction, list_type, address).await?;
        if let Err(e) = self.db.insert_acl_rule(
            4,
            direction_str(direction),
            list_type_str(list_type),
            &address.ip().to_string(),
            address.port(),
        ) {
            if let Err(rollback_err) = self
                .access_control
                .remove_ipv4_list(direction, list_type, address)
                .await
            {
                log!(EbpfError::RollbackFailed(rollback_err));
            }
            return Err(e);
        }
        Ok(())
    }

    pub async fn add_ipv6(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV6,
    ) -> Result<(), Error> {
        self.access_control.add_ipv6_list(direction, list_type, address).await?;
        if let Err(e) = self.db.insert_acl_rule(
            6,
            direction_str(direction),
            list_type_str(list_type),
            &address.ip().to_string(),
            address.port(),
        ) {
            if let Err(rollback_err) = self
                .access_control
                .remove_ipv6_list(direction, list_type, address)
                .await
            {
                log!(EbpfError::RollbackFailed(rollback_err));
            }
            return Err(e);
        }
        Ok(())
    }

    pub async fn remove_ipv4(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV4,
    ) -> Result<(), Error> {
        self.access_control
            .remove_ipv4_list(direction, list_type, address)
            .await?;
        if let Err(e) = self.db.delete_acl_rule(
            4,
            direction_str(direction),
            list_type_str(list_type),
            &address.ip().to_string(),
            address.port(),
        ) {
            if let Err(rollback_err) = self.access_control.add_ipv4_list(direction, list_type, address).await {
                log!(EbpfError::RollbackFailed(rollback_err));
            }
            return Err(e);
        }
        Ok(())
    }

    pub async fn remove_ipv6(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV6,
    ) -> Result<(), Error> {
        self.access_control
            .remove_ipv6_list(direction, list_type, address)
            .await?;
        if let Err(e) = self.db.delete_acl_rule(
            6,
            direction_str(direction),
            list_type_str(list_type),
            &address.ip().to_string(),
            address.port(),
        ) {
            if let Err(rollback_err) = self.access_control.add_ipv6_list(direction, list_type, address).await {
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
        self.geo_block.get_blocked_countries()
    }

    pub fn access_control(&self) -> &AccessControl {
        &self.access_control
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
