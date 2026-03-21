use parking_lot::Mutex;
use rusqlite::{Connection, params};

use crate::model::error::database::DatabaseError;
use crate::model::error::Error;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self, Error> {
        let conn = Connection::open(path)
            .map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;

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
        ").map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        Ok(())
    }

    // --- ACL ---
    pub fn insert_acl_rule(&self, ip_version: u8, direction: &str, list_type: &str, ip_address: &str, port: u16) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR IGNORE INTO acl_rules (ip_version, direction, list_type, ip_address, port) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ip_version, direction, list_type, ip_address, port as i64],
        ).map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        Ok(())
    }

    pub fn delete_acl_rule(&self, ip_version: u8, direction: &str, list_type: &str, ip_address: &str, port: u16) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM acl_rules WHERE ip_version = ?1 AND direction = ?2 AND list_type = ?3 AND ip_address = ?4 AND port = ?5",
            params![ip_version, direction, list_type, ip_address, port as i64],
        ).map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        Ok(())
    }

    pub fn load_acl_rules(&self) -> Result<Vec<(u8, String, String, String, u16)>, Error> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT ip_version, direction, list_type, ip_address, port FROM acl_rules")
            .map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, u8>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)? as u16,
            ))
        }).map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?);
        }
        Ok(results)
    }

    // --- Rate Limit ---
    pub fn set_rate_limit(&self, key: &str, value: u64) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO rate_limit_config (key, value) VALUES (?1, ?2)",
            params![key, value as i64],
        ).map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        Ok(())
    }

    pub fn load_rate_limit_config(&self) -> Result<Vec<(String, u64)>, Error> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT key, value FROM rate_limit_config")
            .map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        }).map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?);
        }
        Ok(results)
    }

    // --- DNS ---
    pub fn insert_dns_domain(&self, domain: &str) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute("INSERT OR IGNORE INTO dns_blacklist (domain) VALUES (?1)", params![domain])
            .map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        Ok(())
    }

    pub fn delete_dns_domain(&self, domain: &str) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM dns_blacklist WHERE domain = ?1", params![domain])
            .map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        Ok(())
    }

    pub fn load_dns_domains(&self) -> Result<Vec<String>, Error> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT domain FROM dns_blacklist")
            .map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        let rows = stmt.query_map([], |row| row.get(0))
            .map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?);
        }
        Ok(results)
    }

    // --- Geo ---
    pub fn insert_geo_country(&self, code: &str) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute("INSERT OR IGNORE INTO geo_blocked_countries (country_code) VALUES (?1)", params![code])
            .map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        Ok(())
    }

    pub fn delete_geo_country(&self, code: &str) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM geo_blocked_countries WHERE country_code = ?1", params![code])
            .map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        Ok(())
    }

    pub fn load_geo_countries(&self) -> Result<Vec<String>, Error> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT country_code FROM geo_blocked_countries")
            .map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        let rows = stmt.query_map([], |row| row.get(0))
            .map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?);
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
            Err(e) => Err(DatabaseError::QueryFailed { reason: e.to_string() }.into()),
        }
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        ).map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;
        Ok(())
    }

    // --- Users ---
    pub fn find_user(&self, username: &str) -> Result<Option<(i64, String, String, String)>, Error> {
        let conn = self.conn.lock();
        let result = conn.query_row(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?1",
            params![username],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        );
        match result {
            Ok(user) => Ok(Some(user)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(DatabaseError::QueryFailed { reason: e.to_string() }.into()),
        }
    }

    pub fn insert_user(&self, username: &str, password_hash: &str, role: &str) -> Result<(), Error> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?1, ?2, ?3)",
            params![username, password_hash, role],
        ).map_err(|e| -> Error {
            if e.to_string().contains("UNIQUE constraint") {
                DatabaseError::UserAlreadyExists { username: username.to_string() }.into()
            } else {
                DatabaseError::QueryFailed { reason: e.to_string() }.into()
            }
        })?;
        Ok(())
    }

    pub fn user_count(&self) -> Result<i64, Error> {
        let conn = self.conn.lock();
        conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .map_err(|e| -> Error { DatabaseError::QueryFailed { reason: e.to_string() }.into() })
    }
}
