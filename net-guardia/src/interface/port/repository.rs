use crate::model::error::Error;

/// Port for persistent storage operations.
/// Adapters: SQLite (current), could be Postgres, etc.
pub trait RepositoryPort: Send + Sync {
    // --- ACL ---
    fn insert_acl_rule(&self, ip_version: u8, direction: &str, list_type: &str, ip_address: &str, port: u16) -> Result<(), Error>;
    fn delete_acl_rule(&self, ip_version: u8, direction: &str, list_type: &str, ip_address: &str, port: u16) -> Result<(), Error>;
    fn load_acl_rules(&self) -> Result<Vec<(u8, String, String, String, u16)>, Error>;

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
    fn find_user(&self, username: &str) -> Result<Option<(i64, String, String, String, bool)>, Error>;
    fn insert_user(&self, username: &str, password_hash: &str, role: &str, force_password_change: bool) -> Result<(), Error>;
    fn update_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error>;
    fn user_count(&self) -> Result<i64, Error>;

    // --- Login Rate Limiting ---
    fn record_login_failure(&self, username: &str) -> Result<(u32, Option<u64>), Error>;
    fn check_login_locked(&self, username: &str) -> Result<Option<u64>, Error>;
    fn clear_login_failures(&self, username: &str) -> Result<(), Error>;
}
