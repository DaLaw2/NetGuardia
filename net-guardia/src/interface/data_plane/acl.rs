use async_trait::async_trait;

use crate::common::error::Error;
use crate::domain::data_plane::acl_rule::AclRuleView;
use crate::domain::data_plane::direction::FlowDirection;
use crate::domain::data_plane::ip_version::IpVersion;
use crate::domain::data_plane::list_type::ListType;

#[async_trait]
pub trait AclRepo: Send + Sync {
    async fn list_acl_rules(&self) -> Result<Vec<AclRuleView>, Error>;
    async fn has_manual_acl_rule(&self, ip_address: &str) -> Result<bool, Error>;
    async fn list_admin_whitelist(&self) -> Result<Vec<String>, Error>;

    async fn insert_acl_rule(
        &self,
        ip_version: IpVersion,
        direction: FlowDirection,
        list_type: ListType,
        ip_address: &str,
        port: u16,
        preserve_active_soar_blocks: bool,
    ) -> Result<(), Error>;

    async fn insert_admin_whitelist(&self, ip: &str) -> Result<(), Error>;

    async fn delete_acl_rule(
        &self,
        ip_version: IpVersion,
        direction: FlowDirection,
        list_type: ListType,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error>;
    async fn delete_admin_whitelist(&self, ip: &str) -> Result<(), Error>;
}
