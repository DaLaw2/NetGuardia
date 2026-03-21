use parking_lot::Mutex;
use rusqlite::{Connection, params};

use crate::model::error::database::DatabaseError;
use crate::model::error::Error;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self, Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Self { conn: Mutex::new(conn) };
        db.create_tables()?;
        Ok(db)
    }

    fn create_tables(&self) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                force_password_change INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS acl_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_version INTEGER NOT NULL,
                direction TEXT NOT NULL,
                list_type TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                UNIQUE(ip_version, direction, list_type, ip_address, port)
            );
            CREATE TABLE IF NOT EXISTS rate_limit_config (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dns_blacklist (
                domain TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS geo_blocked_countries (
                country_code TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        ")?;

        // Migration: add force_password_change column if missing (for existing DBs)
        let conn_ref = &*conn;
        let has_column: bool = conn_ref
            .prepare("SELECT force_password_change FROM users LIMIT 0")
            .is_ok();
        if !has_column {
            conn_ref.execute_batch(
                "ALTER TABLE users ADD COLUMN force_password_change INTEGER NOT NULL DEFAULT 0;"
            )?;
        }

        Ok(())
    }

    // --- ACL ---
    pub fn insert_acl_rule(&self, ip_version: u8, direction: &str, list_type: &str, ip_address: &str, port: u16) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR IGNORE INTO acl_rules (ip_version, direction, list_type, ip_address, port) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ip_version, direction, list_type, ip_address, port as i64],
        )?;
        Ok(())
    }

    pub fn delete_acl_rule(&self, ip_version: u8, direction: &str, list_type: &str, ip_address: &str, port: u16) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM acl_rules WHERE ip_version = ?1 AND direction = ?2 AND list_type = ?3 AND ip_address = ?4 AND port = ?5",
            params![ip_version, direction, list_type, ip_address, port as i64],
        )?;
        Ok(())
    }

    pub fn load_acl_rules(&self) -> Result<Vec<(u8, String, String, String, u16)>, Error> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT ip_version, direction, list_type, ip_address, port FROM acl_rules")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, u8>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)? as u16,
            ))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    // --- Rate Limit ---
    pub fn set_rate_limit(&self, key: &str, value: u64) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO rate_limit_config (key, value) VALUES (?1, ?2)",
            params![key, value as i64],
        )?;
        Ok(())
    }

    pub fn load_rate_limit_config(&self) -> Result<Vec<(String, u64)>, Error> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT key, value FROM rate_limit_config")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    // --- DNS ---
    pub fn insert_dns_domain(&self, domain: &str) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute("INSERT OR IGNORE INTO dns_blacklist (domain) VALUES (?1)", params![domain])?;
        Ok(())
    }

    pub fn delete_dns_domain(&self, domain: &str) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM dns_blacklist WHERE domain = ?1", params![domain])?;
        Ok(())
    }

    pub fn load_dns_domains(&self) -> Result<Vec<String>, Error> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT domain FROM dns_blacklist")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    // --- Geo ---
    pub fn insert_geo_country(&self, code: &str) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute("INSERT OR IGNORE INTO geo_blocked_countries (country_code) VALUES (?1)", params![code])?;
        Ok(())
    }

    pub fn delete_geo_country(&self, code: &str) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM geo_blocked_countries WHERE country_code = ?1", params![code])?;
        Ok(())
    }

    pub fn load_geo_countries(&self) -> Result<Vec<String>, Error> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT country_code FROM geo_blocked_countries")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    // --- Settings ---
    pub fn get_setting(&self, key: &str) -> Result<Option<String>, Error> {
        let conn = self.conn.lock();
        let result = conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        );
        match result {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    // --- Users ---
    pub fn find_user(&self, username: &str) -> Result<Option<(i64, String, String, String, bool)>, Error> {
        let conn = self.conn.lock();
        let result = conn.query_row(
            "SELECT id, username, password_hash, role, force_password_change FROM users WHERE username = ?1",
            params![username],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get::<_, i64>(4)? != 0)),
        );
        match result {
            Ok(user) => Ok(Some(user)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn insert_user(&self, username: &str, password_hash: &str, role: &str, force_password_change: bool) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO users (username, password_hash, role, force_password_change) VALUES (?1, ?2, ?3, ?4)",
            params![username, password_hash, role, force_password_change as i64],
        ).map_err(|e| -> Error {
            if e.to_string().contains("UNIQUE constraint") {
                DatabaseError::UserAlreadyExists { username: username.to_string() }.into()
            } else {
                e.into()
            }
        })?;
        Ok(())
    }

    pub fn update_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE users SET password_hash = ?1, force_password_change = 0 WHERE id = ?2",
            params![password_hash, user_id],
        )?;
        Ok(())
    }

    pub fn user_count(&self) -> Result<i64, Error> {
        let conn = self.conn.lock();
        Ok(conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?)
    }

    // --- Login Rate Limiting ---
    pub fn record_login_failure(&self, username: &str) -> Result<(u32, Option<u64>), Error> {
        let key_count = format!("login_failures:{}", username);
        let key_locked = format!("login_locked_until:{}", username);

        let count: u32 = self.get_setting(&key_count)?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0) + 1;

        self.set_setting(&key_count, &count.to_string())?;

        if count >= 5 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let locked_until = now + 900; // 15 minutes
            self.set_setting(&key_locked, &locked_until.to_string())?;
            Ok((count, Some(locked_until)))
        } else {
            Ok((count, None))
        }
    }

    pub fn check_login_locked(&self, username: &str) -> Result<Option<u64>, Error> {
        let key_locked = format!("login_locked_until:{}", username);
        if let Some(locked_str) = self.get_setting(&key_locked)? {
            if let Ok(locked_until) = locked_str.parse::<u64>() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now < locked_until {
                    return Ok(Some(locked_until - now));
                }
                // Lock expired, clear it
                self.clear_login_failures(username)?;
            }
        }
        Ok(None)
    }

    pub fn clear_login_failures(&self, username: &str) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM settings WHERE key = ?1", params![format!("login_failures:{}", username)])?;
        conn.execute("DELETE FROM settings WHERE key = ?1", params![format!("login_locked_until:{}", username)])?;
        Ok(())
    }
}

/// Implement the RepositoryPort trait, proving Database satisfies the port contract.
/// This enables adapter-level testing with mock implementations.
impl crate::interface::port::repository::RepositoryPort for Database {
    fn insert_acl_rule(&self, ip_version: u8, direction: &str, list_type: &str, ip_address: &str, port: u16) -> Result<(), Error> { self.insert_acl_rule(ip_version, direction, list_type, ip_address, port) }
    fn delete_acl_rule(&self, ip_version: u8, direction: &str, list_type: &str, ip_address: &str, port: u16) -> Result<(), Error> { self.delete_acl_rule(ip_version, direction, list_type, ip_address, port) }
    fn load_acl_rules(&self) -> Result<Vec<(u8, String, String, String, u16)>, Error> { self.load_acl_rules() }
    fn set_rate_limit(&self, key: &str, value: u64) -> Result<(), Error> { self.set_rate_limit(key, value) }
    fn load_rate_limit_config(&self) -> Result<Vec<(String, u64)>, Error> { self.load_rate_limit_config() }
    fn insert_dns_domain(&self, domain: &str) -> Result<(), Error> { self.insert_dns_domain(domain) }
    fn delete_dns_domain(&self, domain: &str) -> Result<(), Error> { self.delete_dns_domain(domain) }
    fn load_dns_domains(&self) -> Result<Vec<String>, Error> { self.load_dns_domains() }
    fn insert_geo_country(&self, code: &str) -> Result<(), Error> { self.insert_geo_country(code) }
    fn delete_geo_country(&self, code: &str) -> Result<(), Error> { self.delete_geo_country(code) }
    fn load_geo_countries(&self) -> Result<Vec<String>, Error> { self.load_geo_countries() }
    fn get_setting(&self, key: &str) -> Result<Option<String>, Error> { self.get_setting(key) }
    fn set_setting(&self, key: &str, value: &str) -> Result<(), Error> { self.set_setting(key, value) }
    fn find_user(&self, username: &str) -> Result<Option<(i64, String, String, String, bool)>, Error> { self.find_user(username) }
    fn insert_user(&self, username: &str, password_hash: &str, role: &str, force_password_change: bool) -> Result<(), Error> { self.insert_user(username, password_hash, role, force_password_change) }
    fn update_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error> { self.update_user_password(user_id, password_hash) }
    fn user_count(&self) -> Result<i64, Error> { self.user_count() }
    fn record_login_failure(&self, username: &str) -> Result<(u32, Option<u64>), Error> { self.record_login_failure(username) }
    fn check_login_locked(&self, username: &str) -> Result<Option<u64>, Error> { self.check_login_locked(username) }
    fn clear_login_failures(&self, username: &str) -> Result<(), Error> { self.clear_login_failures(username) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Database {
        Database::new(":memory:").expect("Failed to create test database")
    }

    #[test]
    fn test_create_tables() {
        let _db = test_db();
    }

    #[test]
    fn test_user_crud() {
        let db = test_db();
        assert_eq!(db.user_count().unwrap(), 0);

        db.insert_user("admin", "hash123", "admin", true).unwrap();
        assert_eq!(db.user_count().unwrap(), 1);

        let user = db.find_user("admin").unwrap().unwrap();
        assert_eq!(user.0, 1); // id
        assert_eq!(user.1, "admin"); // username
        assert_eq!(user.2, "hash123"); // password_hash
        assert_eq!(user.3, "admin"); // role
        assert!(user.4); // force_password_change
    }

    #[test]
    fn test_user_duplicate() {
        let db = test_db();
        db.insert_user("admin", "hash", "admin", false).unwrap();
        let result = db.insert_user("admin", "hash2", "admin", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_password_clears_force_change() {
        let db = test_db();
        db.insert_user("admin", "old_hash", "admin", true).unwrap();

        let user = db.find_user("admin").unwrap().unwrap();
        assert!(user.4); // force_password_change = true

        db.update_user_password(user.0, "new_hash").unwrap();

        let user = db.find_user("admin").unwrap().unwrap();
        assert!(!user.4); // force_password_change = false
        assert_eq!(user.2, "new_hash");
    }

    #[test]
    fn test_settings_crud() {
        let db = test_db();
        assert_eq!(db.get_setting("foo").unwrap(), None);

        db.set_setting("foo", "bar").unwrap();
        assert_eq!(db.get_setting("foo").unwrap(), Some("bar".to_string()));

        db.set_setting("foo", "baz").unwrap();
        assert_eq!(db.get_setting("foo").unwrap(), Some("baz".to_string()));
    }

    #[test]
    fn test_acl_crud() {
        let db = test_db();
        db.insert_acl_rule(4, "source", "blacklist", "192.168.1.1", 80).unwrap();
        let rules = db.load_acl_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0], (4, "source".to_string(), "blacklist".to_string(), "192.168.1.1".to_string(), 80));

        db.delete_acl_rule(4, "source", "blacklist", "192.168.1.1", 80).unwrap();
        let rules = db.load_acl_rules().unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn test_dns_crud() {
        let db = test_db();
        db.insert_dns_domain("evil.com").unwrap();
        let domains = db.load_dns_domains().unwrap();
        assert_eq!(domains, vec!["evil.com"]);

        db.delete_dns_domain("evil.com").unwrap();
        assert!(db.load_dns_domains().unwrap().is_empty());
    }

    #[test]
    fn test_geo_crud() {
        let db = test_db();
        db.insert_geo_country("CN").unwrap();
        let countries = db.load_geo_countries().unwrap();
        assert_eq!(countries, vec!["CN"]);

        db.delete_geo_country("CN").unwrap();
        assert!(db.load_geo_countries().unwrap().is_empty());
    }

    #[test]
    fn test_rate_limit_crud() {
        let db = test_db();
        db.set_rate_limit("packet_rate", 1000).unwrap();
        let configs = db.load_rate_limit_config().unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0], ("packet_rate".to_string(), 1000));
    }

    #[test]
    fn test_login_lockout() {
        let db = test_db();

        // First 4 failures don't lock
        for i in 1..5 {
            let (count, locked) = db.record_login_failure("admin").unwrap();
            assert_eq!(count, i);
            assert!(locked.is_none());
        }

        // 5th failure triggers lock
        let (count, locked) = db.record_login_failure("admin").unwrap();
        assert_eq!(count, 5);
        assert!(locked.is_some());

        // Check locked
        let remaining = db.check_login_locked("admin").unwrap();
        assert!(remaining.is_some());
        assert!(remaining.unwrap() > 0);

        // Clear and verify
        db.clear_login_failures("admin").unwrap();
        let remaining = db.check_login_locked("admin").unwrap();
        assert!(remaining.is_none());
    }

    #[test]
    fn test_find_nonexistent_user() {
        let db = test_db();
        assert!(db.find_user("nobody").unwrap().is_none());
    }

    /// Verify that Database satisfies the RepositoryPort trait contract.
    /// This test ensures the trait impl compiles and can be used via trait object.
    #[test]
    fn test_repository_port_trait_object() {
        use crate::interface::port::repository::RepositoryPort;

        let db = test_db();
        let repo: &dyn RepositoryPort = &db;

        // Use via trait object — proves the abstraction works
        repo.set_setting("test_key", "test_value").unwrap();
        assert_eq!(repo.get_setting("test_key").unwrap(), Some("test_value".to_string()));

        repo.insert_acl_rule(4, "source", "blacklist", "10.0.0.1", 443).unwrap();
        let rules = repo.load_acl_rules().unwrap();
        assert_eq!(rules.len(), 1);

        assert_eq!(repo.user_count().unwrap(), 0);
        repo.insert_user("test", "hash", "viewer", false).unwrap();
        assert_eq!(repo.user_count().unwrap(), 1);
    }
}
