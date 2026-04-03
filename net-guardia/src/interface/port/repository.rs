use crate::model::error::Error;

/// Type alias for ACL rule tuples: (ip_version, direction, list_type, ip_address, port)
pub type AclRuleTuple = (u8, String, String, String, u16);

/// Type alias for user record tuples: (id, username, password_hash, role, force_password_change)
pub type UserTuple = (i64, String, String, String, bool);

/// Type alias for user list items: (id, username, role, force_password_change, created_at)
pub type UserListItem = (i64, String, String, bool, String);

/// Type alias for user-with-groups: (id, username, role, force_password_change, created_at, groups: Vec<(group_id, group_name)>)
pub type UserWithGroups = (i64, String, String, bool, String, Vec<(i64, String)>);

/// Type alias for user group tuples: (id, name, description, permissions, created_at)
pub type UserGroupTuple = (i64, String, String, String, String);

/// Port for persistent storage operations.
/// Adapters: SQLite (current), could be Postgres, etc.
/// All methods are used via the concrete Database adapter; the trait
/// defines the hexagonal-architecture boundary.
#[allow(dead_code)]
pub trait RepositoryPort: Send + Sync {
    // --- ACL ---
    fn insert_acl_rule(
        &self,
        ip_version: u8,
        direction: &str,
        list_type: &str,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error>;
    fn delete_acl_rule(
        &self,
        ip_version: u8,
        direction: &str,
        list_type: &str,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error>;
    fn load_acl_rules(&self) -> Result<Vec<AclRuleTuple>, Error>;

    // --- Rate Limit ---
    fn set_rate_limit(&self, key: &str, value: u64) -> Result<(), Error>;
    fn load_rate_limit_config(&self) -> Result<Vec<(String, u64)>, Error>;

    // --- DNS ---
    fn insert_dns_domain(&self, domain: &str) -> Result<(), Error>;
    fn delete_dns_domain(&self, domain: &str) -> Result<(), Error>;
    fn load_dns_domains(&self) -> Result<Vec<String>, Error>;

    // --- Geo ---
    fn insert_geo_country(&self, code: &str) -> Result<(), Error>;
    fn delete_geo_country(&self, code: &str) -> Result<(), Error>;
    fn load_geo_countries(&self) -> Result<Vec<String>, Error>;

    // --- Settings ---
    fn get_setting(&self, key: &str) -> Result<Option<String>, Error>;
    fn set_setting(&self, key: &str, value: &str) -> Result<(), Error>;

    // --- Users ---
    fn find_user(&self, username: &str) -> Result<Option<UserTuple>, Error>;
    fn insert_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
        force_password_change: bool,
    ) -> Result<i64, Error>;
    fn update_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error>;
    fn user_count(&self) -> Result<i64, Error>;

    // --- User Management ---
    fn list_users(&self) -> Result<Vec<UserListItem>, Error>;
    fn list_users_with_groups(&self) -> Result<Vec<UserWithGroups>, Error>;
    fn delete_user(&self, user_id: i64) -> Result<bool, Error>;
    fn update_user_role(&self, user_id: i64, role: &str) -> Result<(), Error>;
    fn reset_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error>;
    fn find_user_by_id(&self, user_id: i64) -> Result<Option<UserTuple>, Error>;

    // --- User Groups ---
    fn list_user_groups(&self) -> Result<Vec<UserGroupTuple>, Error>;
    fn create_user_group(&self, name: &str, description: &str, permissions: &str) -> Result<i64, Error>;
    fn update_user_group(&self, id: i64, name: &str, description: &str, permissions: &str) -> Result<(), Error>;
    fn delete_user_group(&self, id: i64) -> Result<bool, Error>;
    fn get_user_group(&self, id: i64) -> Result<Option<UserGroupTuple>, Error>;

    // --- User Group Membership ---
    fn get_user_groups(&self, user_id: i64) -> Result<Vec<(i64, String, String, String)>, Error>;
    fn set_user_groups(&self, user_id: i64, group_ids: &[i64]) -> Result<(), Error>;
    fn get_user_permissions(&self, user_id: i64) -> Result<Vec<String>, Error>;
    fn cleanup_user_memberships(&self, user_id: i64) -> Result<(), Error>;
    fn get_group_member_ids(&self, group_id: i64) -> Result<Vec<i64>, Error>;
    fn get_group_members(&self, group_id: i64) -> Result<Vec<(i64, String)>, Error>;

    // --- Login Rate Limiting ---
    fn record_login_failure(&self, username: &str) -> Result<(u32, Option<u64>), Error>;
    fn check_login_locked(&self, username: &str) -> Result<Option<u64>, Error>;
    fn clear_login_failures(&self, username: &str) -> Result<(), Error>;
}
