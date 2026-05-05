use std::net::{SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use macros::log;

use crate::domain::common::error::Error;
use crate::domain::data_plane::direction::FlowDirection;
use crate::domain::data_plane::error::EbpfError;
use crate::domain::data_plane::list_type::ListType;
use crate::interface::access_control_admin::AccessControlAdminPort;
use crate::interface::app_repo::AppRepo;
use crate::interface::geo_block_api::GeoBlockPort;

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

    pub async fn add_ipv4(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV4,
    ) -> Result<(), Error> {
        self.access_control.add_ipv4_list(direction, list_type, address)?;
        if let Err(e) = self
            .db
            .insert_acl_rule(
                4,
                direction.as_str(),
                list_type.as_str(),
                &address.ip().to_string(),
                address.port(),
            )
            .await
        {
            if let Err(rollback_err) = self.access_control.remove_ipv4_list(direction, list_type, address) {
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
        self.access_control.add_ipv6_list(direction, list_type, address)?;
        if let Err(e) = self
            .db
            .insert_acl_rule(
                6,
                direction.as_str(),
                list_type.as_str(),
                &address.ip().to_string(),
                address.port(),
            )
            .await
        {
            if let Err(rollback_err) = self.access_control.remove_ipv6_list(direction, list_type, address) {
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
        self.access_control.remove_ipv4_list(direction, list_type, address)?;
        if let Err(e) = self
            .db
            .delete_acl_rule(
                4,
                direction.as_str(),
                list_type.as_str(),
                &address.ip().to_string(),
                address.port(),
            )
            .await
        {
            if let Err(rollback_err) = self.access_control.add_ipv4_list(direction, list_type, address) {
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
        self.access_control.remove_ipv6_list(direction, list_type, address)?;
        if let Err(e) = self
            .db
            .delete_acl_rule(
                6,
                direction.as_str(),
                list_type.as_str(),
                &address.ip().to_string(),
                address.port(),
            )
            .await
        {
            if let Err(rollback_err) = self.access_control.add_ipv6_list(direction, list_type, address) {
                log!(EbpfError::RollbackFailed(rollback_err));
            }
            return Err(e);
        }
        Ok(())
    }

    pub async fn block_geo_countries(&self, codes: &[String]) -> Result<u64, Error> {
        let total = self.geo_block.block_countries(codes)?;
        for code in codes {
            if let Err(e) = self.db.insert_geo_country(code).await {
                let _ = self.geo_block.unblock_countries(codes);
                return Err(e);
            }
        }
        Ok(total)
    }

    pub async fn unblock_geo_countries(&self, codes: &[String]) -> Result<u64, Error> {
        let total = self.geo_block.unblock_countries(codes)?;
        for code in codes {
            if let Err(e) = self.db.delete_geo_country(code).await {
                let _ = self.geo_block.block_countries(codes);
                return Err(e);
            }
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
