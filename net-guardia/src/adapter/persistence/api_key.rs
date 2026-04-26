use std::fmt::Write;

use hmac::{Hmac, Mac};
use rusqlite::{Error as RusqliteError, params};
use sha2::Sha256;

use super::Database;
use crate::domain::common::error::Error;
use crate::domain::identity::auth::{Claims, PermissionLevel};
use crate::domain::identity::user::ApiKeyView;
use crate::interface::api_key::ApiKeyRepo;

type HmacSha256 = Hmac<Sha256>;

impl Database {
    /// Compute HMAC-SHA256 of an API key using the derived secret.
    pub fn hmac_api_key(&self, raw_key: &str) -> String {
        // SAFETY: HMAC-SHA256 accepts keys of any length; the only error
        // `new_from_slice` returns (`InvalidLength`) is unreachable for this
        // algorithm. The unreachable!() is the correct sentinel.
        let mut mac = HmacSha256::new_from_slice(&self.api_key_hmac).unwrap_or_else(|_| unreachable!());
        mac.update(raw_key.as_bytes());
        let result = mac.finalize().into_bytes();

        let mut hex = String::with_capacity(64);
        for byte in result {
            let _ = write!(&mut hex, "{:02x}", byte);
        }
        hex
    }

    /// Validate an API key and return Claims if valid.
    /// Computes HMAC-SHA256 of the key and looks it up in api_keys table.
    pub fn validate_api_key(&self, api_key: &str) -> Result<Option<Claims>, Error> {
        let digest = self.hmac_api_key(api_key);

        let conn = self.conn()?;
        let result = conn.query_row(
            "SELECT id, name, permission_level FROM api_keys WHERE key_hash = ?1",
            params![digest],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        );

        match result {
            Ok((id, name, level)) => {
                // Update last_used_at
                let _ = conn.execute(
                    "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?1",
                    params![id],
                );

                let perm_level = PermissionLevel::from_str(&level).unwrap_or(PermissionLevel::ReadOnly);
                let permissions: Vec<String> = perm_level.permissions().iter().map(|s| (*s).to_string()).collect();

                Ok(Some(Claims {
                    sub: -id, // negative ID to distinguish from user IDs
                    username: format!("api:{}", name),
                    role: level,
                    permissions,
                    exp: usize::MAX, // API keys don't expire (revocation via DB deletion)
                }))
            }
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e)?,
        }
    }

    pub fn insert_api_key(&self, key_hash: &str, name: &str, permission_level: &str) -> Result<i64, Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO api_keys (key_hash, name, permission_level) VALUES (?1, ?2, ?3)",
            params![key_hash, name, permission_level],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_api_keys(&self) -> Result<Vec<ApiKeyView>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT id, name, permission_level, created_at, last_used_at FROM api_keys")?;
        let rows = stmt.query_map([], |row| {
            Ok(ApiKeyView {
                id: row.get(0)?,
                name: row.get(1)?,
                permission_level: row.get(2)?,
                created_at: row.get(3)?,
                last_used_at: row.get(4)?,
            })
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn delete_api_key(&self, id: i64) -> Result<bool, Error> {
        let conn = self.conn()?;
        let affected = conn.execute("DELETE FROM api_keys WHERE id = ?1", params![id])?;
        Ok(affected > 0)
    }
}

impl ApiKeyRepo for Database {
    fn validate_api_key(&self, api_key: &str) -> Result<Option<Claims>, Error> {
        self.validate_api_key(api_key)
    }

    fn hmac_api_key(&self, raw_key: &str) -> String {
        self.hmac_api_key(raw_key)
    }

    fn insert_api_key(&self, key_hash: &str, name: &str, permission_level: &str) -> Result<i64, Error> {
        self.insert_api_key(key_hash, name, permission_level)
    }

    fn list_api_keys(&self) -> Result<Vec<ApiKeyView>, Error> {
        self.list_api_keys()
    }

    fn delete_api_key(&self, id: i64) -> Result<bool, Error> {
        self.delete_api_key(id)
    }
}
