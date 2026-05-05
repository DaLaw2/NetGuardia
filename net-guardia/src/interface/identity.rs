use async_trait::async_trait;

use crate::domain::common::error::Error;
use crate::domain::identity::user::{GroupMemberView, UserGroupView, UserView, UserWithGroupsView};

#[async_trait]
pub trait UserRepo: Send + Sync {
    async fn find_user(&self, username: &str) -> Result<Option<UserView>, Error>;
    async fn find_user_by_id(&self, user_id: i64) -> Result<Option<UserView>, Error>;
    async fn insert_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
        force_password_change: bool,
    ) -> Result<i64, Error>;
    async fn update_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error>;
    async fn list_users_with_groups(&self) -> Result<Vec<UserWithGroupsView>, Error>;
    async fn delete_user(&self, user_id: i64) -> Result<bool, Error>;
    async fn update_user_role(&self, user_id: i64, role: &str) -> Result<(), Error>;
    async fn reset_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error>;
}

#[async_trait]
pub trait UserGroupRepo: Send + Sync {
    async fn list_user_groups(&self) -> Result<Vec<UserGroupView>, Error>;
    async fn create_user_group(&self, name: &str, description: &str, permissions: &str) -> Result<i64, Error>;
    async fn update_user_group(&self, id: i64, name: &str, description: &str, permissions: &str) -> Result<(), Error>;
    async fn delete_user_group(&self, id: i64) -> Result<bool, Error>;
    async fn get_user_group(&self, id: i64) -> Result<Option<UserGroupView>, Error>;
    async fn list_groups_for_user(&self, user_id: i64) -> Result<Vec<UserGroupView>, Error>;
    async fn set_user_groups(&self, user_id: i64, group_ids: &[i64]) -> Result<(), Error>;
    async fn list_user_permissions(&self, user_id: i64) -> Result<Vec<String>, Error>;
    async fn list_group_member_ids(&self, group_id: i64) -> Result<Vec<i64>, Error>;
    async fn list_group_members(&self, group_id: i64) -> Result<Vec<GroupMemberView>, Error>;
}

#[async_trait]
pub trait LoginAttemptRepo: Send + Sync {
    async fn record_login_failure(&self, username: &str) -> Result<(u32, Option<u64>), Error>;
    async fn check_login_locked(&self, username: &str) -> Result<Option<u64>, Error>;
    async fn clear_login_failures(&self, username: &str) -> Result<(), Error>;
}
