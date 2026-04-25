use crate::domain::common::error::Error;
use crate::domain::identity::user::{UserGroupView, UserView, UserWithGroupsView};

/// Identity BC (generic) — users, groups, membership, and login rate-limit counter.
///
/// Kept as one aggregate because user lifecycle, group membership, permission
/// resolution and login-attempt counters all share the `users` table lifecycle
/// and are enforced together at login time.
pub trait IdentityRepo: Send + Sync {
    // --- Users ---
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

    // --- User Groups ---
    fn list_user_groups(&self) -> Result<Vec<UserGroupView>, Error>;
    fn create_user_group(&self, name: &str, description: &str, permissions: &str) -> Result<i64, Error>;
    fn update_user_group(&self, id: i64, name: &str, description: &str, permissions: &str) -> Result<(), Error>;
    fn delete_user_group(&self, id: i64) -> Result<bool, Error>;
    fn get_user_group(&self, id: i64) -> Result<Option<UserGroupView>, Error>;

    // --- Membership ---
    fn list_groups_for_user(&self, user_id: i64) -> Result<Vec<(i64, String, String, String)>, Error>;
    fn set_user_groups(&self, user_id: i64, group_ids: &[i64]) -> Result<(), Error>;
    fn list_user_permissions(&self, user_id: i64) -> Result<Vec<String>, Error>;
    fn list_group_member_ids(&self, group_id: i64) -> Result<Vec<i64>, Error>;
    fn list_group_members(&self, group_id: i64) -> Result<Vec<(i64, String)>, Error>;

    // --- Login Rate Limiting ---
    fn record_login_failure(&self, username: &str) -> Result<(u32, Option<u64>), Error>;
    fn check_login_locked(&self, username: &str) -> Result<Option<u64>, Error>;
    fn clear_login_failures(&self, username: &str) -> Result<(), Error>;
}
