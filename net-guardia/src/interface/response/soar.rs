use async_trait::async_trait;

use crate::common::error::Error;
use crate::domain::data_plane::ip_version::IpVersion;
use crate::interface::data_plane::acl::AclRepo;
use crate::interface::response::playbook_data::{
    ActionInput, ActiveBlockView, CreateConditionInput, CreatePlaybookInput, ExecutionView, PendingUnblock,
    PlaybookView, UpdatePlaybookInput,
};

#[async_trait]
pub trait PlaybookRepo: Send + Sync {
    async fn list_playbooks(&self) -> Result<Vec<PlaybookView>, Error>;
    async fn insert_playbook_atomic(
        &self,
        input: &CreatePlaybookInput,
        actions: &[ActionInput],
        conditions: &[CreateConditionInput],
    ) -> Result<i64, Error>;
    async fn update_playbook_enabled(&self, id: i64, enabled: bool) -> Result<bool, Error>;
    async fn update_playbook_atomic(
        &self,
        id: i64,
        row: &UpdatePlaybookInput,
        actions: &[ActionInput],
        conditions: &[CreateConditionInput],
    ) -> Result<bool, Error>;
    async fn delete_playbook(&self, id: i64) -> Result<bool, Error>;
}

#[async_trait]
pub trait SoarBlockRepo: Send + Sync {
    async fn count_active_soar_blocks(&self) -> Result<u32, Error>;
    async fn list_active_soar_blocks(&self) -> Result<Vec<ActiveBlockView>, Error>;
    async fn find_soar_block_by_id(&self, id: i64) -> Result<Option<ActiveBlockView>, Error>;
    async fn list_expired_soar_blocks(&self) -> Result<Vec<ActiveBlockView>, Error>;
    async fn list_pending_unblocks(&self) -> Result<Vec<PendingUnblock>, Error>;
    async fn list_soar_executions(&self, limit: i64) -> Result<Vec<ExecutionView>, Error>;
    async fn insert_pending_unblock(&self, source_ip: &str) -> Result<i64, Error>;
    async fn insert_soar_execution(
        &self,
        playbook_id: i64,
        source_ip: Option<&str>,
        trigger_event: &str,
        actions_json: &str,
    ) -> Result<i64, Error>;
    async fn mark_soar_block_unblocked(&self, id: i64) -> Result<(), Error>;
    async fn increment_pending_unblock_retry(&self, id: i64) -> Result<(), Error>;
    async fn mark_pending_unblock_exhausted(&self, id: i64, last_error: &str) -> Result<(), Error>;
    async fn delete_pending_unblock(&self, id: i64) -> Result<(), Error>;
    async fn commit_soar_block_to_db(
        &self,
        source_ip: &str,
        ip_version: IpVersion,
        playbook_id: i64,
        expires_at: &str,
    ) -> Result<i64, Error>;
    async fn commit_soar_unblock_to_db(
        &self,
        soar_block_id: i64,
        ip_version: IpVersion,
        source_ip: &str,
    ) -> Result<(), Error>;
}

pub trait SoarControlRepo: PlaybookRepo + SoarBlockRepo + AclRepo + Send + Sync {}

impl<T> SoarControlRepo for T where T: PlaybookRepo + SoarBlockRepo + AclRepo + Send + Sync + ?Sized {}
