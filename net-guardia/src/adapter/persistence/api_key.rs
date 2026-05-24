use async_trait::async_trait;
use rusqlite::{Error as RusqliteError, params};

use super::Database;
use crate::common::error::Error;
use crate::common::error::database::DatabaseError;
use crate::domain::identity::auth::{Claims, PermissionLevel};
use crate::domain::identity::user::ApiKeyView;
use crate::interface::identity::api_key::ApiKeyRepo;

impl Database {
    pub async fn validate_api_key(&self, key_hash: &str) -> Result<Option<Claims>, Error> {
        let digest = key_hash.to_string();
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;

                let result = tx.query_row(
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
                        tx.execute(
                            "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?1",
                            params![id],
                        )?;
                        tx.commit()?;

                        let perm_level = PermissionLevel::from_str(&level).ok_or_else(|| {
                            DatabaseError::PersistedValueInvalid("api_keys", "permission_level", level.clone())
                        })?;
                        let permissions: Vec<String> =
                            perm_level.permissions().iter().map(|s| (*s).to_string()).collect();

                        Ok(Some(Claims {
                            sub: -id,
                            username: format!("api:{}", name),
                            role: level,
                            permissions,
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
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
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
    async fn validate_api_key(&self, key_hash: &str) -> Result<Option<Claims>, Error> {
        self.validate_api_key(key_hash).await
    }

    async fn list_api_keys(&self) -> Result<Vec<ApiKeyView>, Error> {
        self.list_api_keys().await
    }

    async fn insert_api_key(&self, key_hash: &str, name: &str, permission_level: &str) -> Result<i64, Error> {
        self.insert_api_key(key_hash, name, permission_level).await
    }

    async fn delete_api_key(&self, id: i64) -> Result<bool, Error> {
        self.delete_api_key(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::Database;
    use crate::adapter::identity::api_key_hasher::HmacApiKeyHasher;
    use crate::interface::identity::api_key_hasher::ApiKeyHasher;

    #[tokio::test]
    async fn validate_full_access_api_key_grants_admin_permissions() {
        let db = Database::new(":memory:").await.expect("test db");
        let hasher = HmacApiKeyHasher::new([0xAB; 32]);
        let raw_key = "ng-test-full-access";
        let digest = hasher.hash_api_key(raw_key);

        db.insert_api_key(&digest, "automation", "full_access").await.unwrap();

        let claims = db.validate_api_key(&digest).await.unwrap().expect("claims");
        assert!(claims.permissions.contains(&"api_keys:admin".to_string()));
        assert!(claims.permissions.contains(&"system:admin".to_string()));
        assert!(claims.permissions.contains(&"users:admin".to_string()));
    }

    #[tokio::test]
    async fn validate_read_write_api_key_does_not_grant_admin_permissions() {
        let db = Database::new(":memory:").await.expect("test db");
        let hasher = HmacApiKeyHasher::new([0xAB; 32]);
        let raw_key = "ng-test-read-write";
        let digest = hasher.hash_api_key(raw_key);

        db.insert_api_key(&digest, "automation", "read_write").await.unwrap();

        let claims = db.validate_api_key(&digest).await.unwrap().expect("claims");
        assert!(!claims.permissions.contains(&"api_keys:admin".to_string()));
        assert!(!claims.permissions.contains(&"system:admin".to_string()));
        assert!(!claims.permissions.contains(&"users:admin".to_string()));
    }

    #[tokio::test]
    async fn validate_api_key_rejects_invalid_persisted_permission_level() {
        let db = Database::new(":memory:").await.expect("test db");
        let hasher = HmacApiKeyHasher::new([0xAB; 32]);
        let raw_key = "ng-test-invalid-level";
        let digest = hasher.hash_api_key(raw_key);

        db.insert_api_key(&digest, "automation", "owner").await.unwrap();

        assert!(db.validate_api_key(&digest).await.is_err());
    }
}
