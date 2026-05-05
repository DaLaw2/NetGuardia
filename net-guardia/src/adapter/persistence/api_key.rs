use std::fmt::Write;

use async_trait::async_trait;
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
        let mut mac = HmacSha256::new_from_slice(&self.api_key_hmac).unwrap_or_else(|_| unreachable!());
        mac.update(raw_key.as_bytes());
        let result = mac.finalize().into_bytes();

        let mut hex = String::with_capacity(64);
        for byte in result {
            let _ = write!(&mut hex, "{:02x}", byte);
        }
        hex
    }

    pub async fn validate_api_key(&self, api_key: &str) -> Result<Option<Claims>, Error> {
        let digest = self.hmac_api_key(api_key);
        self.pool
            .conn_and_then(move |conn| {
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
                        let _ = conn.execute(
                            "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?1",
                            params![id],
                        );

                        let perm_level = PermissionLevel::from_str(&level).unwrap_or(PermissionLevel::ReadOnly);
                        let permissions: Vec<String> =
                            perm_level.permissions().iter().map(|s| (*s).to_string()).collect();

                        Ok(Some(Claims {
                            sub: -id,
                            username: format!("api:{}", name),
                            role: level,
                            permissions,
                            exp: usize::MAX,
                        }))
                    }
                    Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    pub async fn insert_api_key(&self, key_hash: &str, name: &str, permission_level: &str) -> Result<i64, Error> {
        let key_hash = key_hash.to_string();
        let name = name.to_string();
        let permission_level = permission_level.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT INTO api_keys (key_hash, name, permission_level) VALUES (?1, ?2, ?3)",
                    params![key_hash, name, permission_level],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await
    }

    pub async fn list_api_keys(&self) -> Result<Vec<ApiKeyView>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT id, name, permission_level, created_at, last_used_at FROM api_keys")?;
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
            })
            .await
    }

    pub async fn delete_api_key(&self, id: i64) -> Result<bool, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let affected = conn.execute("DELETE FROM api_keys WHERE id = ?1", params![id])?;
                Ok(affected > 0)
            })
            .await
    }
}

#[async_trait]
impl ApiKeyRepo for Database {
    async fn validate_api_key(&self, api_key: &str) -> Result<Option<Claims>, Error> {
        self.validate_api_key(api_key).await
    }

    fn hmac_api_key(&self, raw_key: &str) -> String {
        self.hmac_api_key(raw_key)
    }

    async fn insert_api_key(&self, key_hash: &str, name: &str, permission_level: &str) -> Result<i64, Error> {
        self.insert_api_key(key_hash, name, permission_level).await
    }

    async fn list_api_keys(&self) -> Result<Vec<ApiKeyView>, Error> {
        self.list_api_keys().await
    }

    async fn delete_api_key(&self, id: i64) -> Result<bool, Error> {
        self.delete_api_key(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::Database;

    #[tokio::test]
    async fn validate_full_access_api_key_grants_admin_permissions() {
        let db = Database::new(":memory:").await.expect("test db");
        let raw_key = "ng-test-full-access";
        let digest = db.hmac_api_key(raw_key);

        db.insert_api_key(&digest, "automation", "full_access").await.unwrap();

        let claims = db.validate_api_key(raw_key).await.unwrap().expect("claims");
        assert!(claims.permissions.contains(&"api_keys:admin".to_string()));
        assert!(claims.permissions.contains(&"system:admin".to_string()));
        assert!(claims.permissions.contains(&"users:admin".to_string()));
    }

    #[tokio::test]
    async fn validate_read_write_api_key_does_not_grant_admin_permissions() {
        let db = Database::new(":memory:").await.expect("test db");
        let raw_key = "ng-test-read-write";
        let digest = db.hmac_api_key(raw_key);

        db.insert_api_key(&digest, "automation", "read_write").await.unwrap();

        let claims = db.validate_api_key(raw_key).await.unwrap().expect("claims");
        assert!(!claims.permissions.contains(&"api_keys:admin".to_string()));
        assert!(!claims.permissions.contains(&"system:admin".to_string()));
        assert!(!claims.permissions.contains(&"users:admin".to_string()));
    }
}
