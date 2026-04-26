use crate::domain::common::error::Error;
use crate::domain::identity::user::{GroupMemberView, UserGroupView, UserView, UserWithGroupsView};

pub trait UserRepo: Send + Sync {
    fn find_user(&self, username: &str) -> Result<Option<UserView>, Error>;
    fn find_user_by_id(&self, user_id: i64) -> Result<Option<UserView>, Error>;
    fn insert_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
        force_password_change: bool,
    ) -> Result<i64, Error>;
    fn update_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error>;
    fn list_users_with_groups(&self) -> Result<Vec<UserWithGroupsView>, Error>;
    fn delete_user(&self, user_id: i64) -> Result<bool, Error>;
    fn update_user_role(&self, user_id: i64, role: &str) -> Result<(), Error>;
    fn reset_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error>;
}

pub trait UserGroupRepo: Send + Sync {
    fn list_user_groups(&self) -> Result<Vec<UserGroupView>, Error>;
    fn create_user_group(&self, name: &str, description: &str, permissions: &str) -> Result<i64, Error>;
    fn update_user_group(&self, id: i64, name: &str, description: &str, permissions: &str) -> Result<(), Error>;
    fn delete_user_group(&self, id: i64) -> Result<bool, Error>;
    fn get_user_group(&self, id: i64) -> Result<Option<UserGroupView>, Error>;
    fn list_groups_for_user(&self, user_id: i64) -> Result<Vec<UserGroupView>, Error>;
    fn set_user_groups(&self, user_id: i64, group_ids: &[i64]) -> Result<(), Error>;
    fn list_user_permissions(&self, user_id: i64) -> Result<Vec<String>, Error>;
    fn list_group_member_ids(&self, group_id: i64) -> Result<Vec<i64>, Error>;
    fn list_group_members(&self, group_id: i64) -> Result<Vec<GroupMemberView>, Error>;
}

pub trait LoginAttemptRepo: Send + Sync {
    fn record_login_failure(&self, username: &str) -> Result<(u32, Option<u64>), Error>;
    fn check_login_locked(&self, username: &str) -> Result<Option<u64>, Error>;
    fn clear_login_failures(&self, username: &str) -> Result<(), Error>;
}
