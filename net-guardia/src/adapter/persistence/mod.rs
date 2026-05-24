mod acl;
mod api_key;
mod audit;
mod config;
mod enforcement;
mod report_snapshot;
mod soar;
mod soar_block;
mod stats;
mod system_state;
mod user;

use std::env;

use async_sqlite::{Client, ClientBuilder};
use hkdf::Hkdf;
use macros::log;
use rusqlite::{self, Connection, params};
use sha2::Sha256;

use crate::common::error::Error;
use crate::common::error::codec::CodecError;
use crate::common::error::crypto::CryptoError;
use crate::common::error::database::DatabaseError;
use crate::common::log::crypto::CryptoLog;
use crate::domain::identity::auth::{ADMIN_PERMISSIONS, GROUP_ADMIN, GROUP_VIEWER, VIEWER_PERMISSIONS};

impl From<rusqlite::Error> for DatabaseError {
    fn from(e: rusqlite::Error) -> Self {
        DatabaseError::QueryFailed(e)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(DatabaseError::from(e))
    }
}

impl From<async_sqlite::Error> for Error {
    fn from(e: async_sqlite::Error) -> Self {
        Self::Database(DatabaseError::QueryFailed(e))
    }
}

fn db_encryption_key() -> Option<String> {
    match env::var("NETGUARDIA_DB_KEY") {
        Ok(k) if !k.is_empty() => Some(k),
        _ => None,
    }
}

pub struct Database {
    pool: Client,
}

impl Database {
    pub async fn new(path: &str) -> Result<Self, Error> {
        let encryption_key = db_encryption_key();

        if path != ":memory:" && encryption_key.is_none() {
            log!(CryptoLog::DbEncryptionDisabled);
        }

        let builder = if path == ":memory:" {
            ClientBuilder::new()
        } else {
            ClientBuilder::new().path(path)
        };

        let pool = builder.open().await.map_err(DatabaseError::QueryFailed)?;
        let key_for_pragmas = encryption_key.clone();
        pool.conn(move |conn| {
            if let Some(ref key) = key_for_pragmas {
                conn.pragma_update(None, "key", key)?;
            }
            conn.execute_batch(
                "PRAGMA journal_mode=WAL; \
                     PRAGMA synchronous=NORMAL; \
                     PRAGMA busy_timeout=5000; \
                     PRAGMA foreign_keys=ON;",
            )?;
            Ok(())
        })
        .await
        .map_err(DatabaseError::QueryFailed)?;
        pool.conn(|conn| conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(())))
            .await
            .map_err(|_| DatabaseError::EncryptionKeyInvalid)?;

        let db = Self { pool };
        db.create_tables().await?;
        Ok(db)
    }

    pub fn derive_api_key_hmac(path: &str) -> Result<[u8; 32], Error> {
        let encryption_key = db_encryption_key();
        let root_key = api_key_hmac_root_key(path, encryption_key.as_deref())?;
        let hk = Hkdf::<Sha256>::new(Some(b"netguardia-v1-salt"), root_key.as_bytes());
        let mut okm = [0u8; 32];
        if hk.expand(b"netguardia-apikey-hmac-v1", &mut okm).is_err() {
            // SAFETY: HKDF-SHA256 accepts 32-byte output keys.
            unreachable!("HKDF-SHA256 accepts 32-byte output keys");
        }
        Ok(okm)
    }

    pub fn decrypt_to_file(src_path: &str, key: &str, dest_path: &str) -> Result<(), Error> {
        let conn = Connection::open(src_path).map_err(DatabaseError::QueryFailed)?;
        conn.pragma_update(None, "key", key)
            .map_err(DatabaseError::QueryFailed)?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(|_| DatabaseError::DatabaseNotReadable)?;
        conn.execute("ATTACH DATABASE ?1 AS plaintext KEY '';", params![dest_path])
            .map_err(DatabaseError::QueryFailed)?;
        conn.query_row("SELECT sqlcipher_export('plaintext')", [], |_| Ok(()))
            .map_err(DatabaseError::QueryFailed)?;
        conn.execute_batch("DETACH DATABASE plaintext;")
            .map_err(DatabaseError::QueryFailed)?;
        Ok(())
    }

    pub fn encrypt_to_file(src_path: &str, key: &str, dest_path: &str) -> Result<(), Error> {
        let conn = Connection::open(src_path).map_err(DatabaseError::QueryFailed)?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(|_| DatabaseError::SourceDatabaseNotReadable)?;
        conn.execute("ATTACH DATABASE ?1 AS encrypted KEY ?2;", params![dest_path, key])
            .map_err(DatabaseError::QueryFailed)?;
        conn.query_row("SELECT sqlcipher_export('encrypted')", [], |_| Ok(()))
            .map_err(DatabaseError::QueryFailed)?;
        conn.execute_batch("DETACH DATABASE encrypted;")
            .map_err(DatabaseError::QueryFailed)?;
        Ok(())
    }

    async fn create_tables(&self) -> Result<(), Error> {
        self.pool
            .conn_mut_and_then(|conn| {
                conn.execute_batch(
                    "
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
            CREATE TABLE IF NOT EXISTS system_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS report_snapshots (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT PRIMARY KEY,
                failure_count INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER
            );
            CREATE TABLE IF NOT EXISTS user_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                permissions TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS user_group_members (
                user_id INTEGER NOT NULL,
                group_id INTEGER NOT NULL,
                PRIMARY KEY (user_id, group_id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (group_id) REFERENCES user_groups(id)
            );

            -- SOAR tables
            CREATE TABLE IF NOT EXISTS playbooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                trigger_event TEXT NOT NULL,
                condition_threshold REAL,
                condition_count INTEGER,
                condition_window_secs INTEGER,
                cooldown_secs INTEGER DEFAULT 300,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS playbook_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                playbook_id INTEGER NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
                action_order INTEGER NOT NULL,
                action_type TEXT NOT NULL,
                params TEXT NOT NULL DEFAULT '{}',
                UNIQUE(playbook_id, action_order)
            );
            CREATE TABLE IF NOT EXISTS playbook_conditions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                playbook_id INTEGER NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
                condition_type TEXT NOT NULL,
                operator TEXT NOT NULL DEFAULT '>=',
                value TEXT NOT NULL,
                value2 TEXT,
                UNIQUE(playbook_id, condition_type)
            );
            CREATE TABLE IF NOT EXISTS soar_block_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                playbook_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT NOT NULL,
                unblocked_at TEXT,
                created_acl_rule INTEGER NOT NULL DEFAULT 1,
                preserve_acl_on_unblock INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS soar_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                playbook_id INTEGER NOT NULL,
                source_ip TEXT,
                trigger_event TEXT NOT NULL,
                actions_executed TEXT NOT NULL DEFAULT '[]',
                executed_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS admin_whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- MCP API keys
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                permission_level TEXT NOT NULL DEFAULT 'read_only',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_used_at TEXT
            );

            -- Notification config (Telegram bot token, etc.)
            CREATE TABLE IF NOT EXISTS notification_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel TEXT NOT NULL UNIQUE,
                config_json TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- App secrets (encryption keys for sensitive data)
            CREATE TABLE IF NOT EXISTS app_secrets (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- Pending unblock queue for orphan eBPF block recovery
            CREATE TABLE IF NOT EXISTS pending_unblock (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                retry_count INTEGER NOT NULL DEFAULT 0,
                exhausted_at TEXT,
                last_error TEXT
            );

            -- Audit trail (WORM: hash-chained, triggers block UPDATE/DELETE)
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '{}',
                prev_hash TEXT NOT NULL DEFAULT '',
                row_hash TEXT NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_audit_log_action
                ON audit_log(action, id DESC);

            CREATE INDEX IF NOT EXISTS idx_audit_log_action_ts
                ON audit_log(action, ts);

            CREATE INDEX IF NOT EXISTS idx_audit_log_fusion_src_ip
                ON audit_log(json_extract(detail, '$.src_ip'), id ASC)
                WHERE action = 'fused_threat_emitted' AND json_valid(detail);

            CREATE INDEX IF NOT EXISTS idx_soar_block_active_expires
                ON soar_block_rules(expires_at)
                WHERE unblocked_at IS NULL;

            CREATE INDEX IF NOT EXISTS idx_soar_block_created_at
                ON soar_block_rules(created_at);

            CREATE INDEX IF NOT EXISTS idx_soar_block_unblocked_at
                ON soar_block_rules(unblocked_at)
                WHERE unblocked_at IS NOT NULL;

            CREATE INDEX IF NOT EXISTS idx_soar_block_source_created
                ON soar_block_rules(source_ip, created_at);

            CREATE INDEX IF NOT EXISTS idx_soar_executions_executed_at
                ON soar_executions(executed_at DESC);

            CREATE INDEX IF NOT EXISTS idx_soar_executions_trigger_executed
                ON soar_executions(trigger_event, executed_at);

            CREATE INDEX IF NOT EXISTS idx_user_group_members_group_id
                ON user_group_members(group_id, user_id);

            CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash
                ON api_keys(key_hash);

            CREATE TRIGGER IF NOT EXISTS audit_log_no_update
            BEFORE UPDATE ON audit_log BEGIN
                SELECT RAISE(ABORT, 'audit_log is append-only (WORM)');
            END;

            CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
            BEFORE DELETE ON audit_log BEGIN
                SELECT RAISE(ABORT, 'audit_log is append-only (WORM)');
            END;
        ",
                )?;

                let group_count: i64 = conn.query_row("SELECT COUNT(*) FROM user_groups", [], |row| row.get(0))?;
                if group_count == 0 {
                    let all_permissions =
                        serde_json::to_string(&ADMIN_PERMISSIONS).map_err(CodecError::SerializeFailed)?;
                    let viewer_permissions =
                        serde_json::to_string(&VIEWER_PERMISSIONS).map_err(CodecError::SerializeFailed)?;

                    conn.execute(
                        "INSERT INTO user_groups (name, description, permissions) VALUES (?1, ?2, ?3)",
                        params![GROUP_ADMIN, "Full system access with all permissions", &all_permissions],
                    )?;
                    conn.execute(
                        "INSERT INTO user_groups (name, description, permissions) VALUES (?1, ?2, ?3)",
                        params![GROUP_VIEWER, "Read-only access to all modules", &viewer_permissions],
                    )?;
                }

                Ok::<(), Error>(())
            })
            .await
    }
}

fn api_key_hmac_root_key(path: &str, encryption_key: Option<&str>) -> Result<String, Error> {
    if let Some(key) = env::var("NETGUARDIA_SECRETS_KEY").ok().filter(|k| !k.is_empty()) {
        return Ok(key);
    }
    if let Some(key) = encryption_key {
        log!(CryptoLog::ApiKeyHmacUsingDbKey);
        return Ok(key.to_string());
    }
    if path == ":memory:" {
        return Ok("netguardia-in-memory-test-api-key-secret".to_string());
    }
    Err(CryptoError::MasterKeyUnavailable)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::data_plane::direction::FlowDirection;
    use crate::domain::data_plane::ip_version::IpVersion;
    use crate::domain::data_plane::list_type::ListType;
    use crate::interface::data_plane::acl::AclRepo;
    use crate::interface::identity::auth_repo::UserRepo;
    use crate::interface::system::config_repo::ConfigRepo;

    pub async fn test_db() -> Database {
        Database::new(":memory:").await.expect("Failed to create test database")
    }

    #[tokio::test]
    async fn test_create_tables() {
        let _db = test_db().await;
    }

    #[tokio::test]
    async fn test_aggregate_repo_trait_objects() {
        let db = test_db().await;

        let setting: &dyn ConfigRepo = &db;
        setting.set_config_value("test_key", "test_value").await.unwrap();
        assert_eq!(
            setting.get_config_value("test_key").await.unwrap(),
            Some("test_value".to_string())
        );

        let acl: &dyn AclRepo = &db;
        acl.insert_acl_rule(
            IpVersion::V4,
            FlowDirection::Source,
            ListType::Black,
            "10.0.0.1",
            443,
            false,
        )
        .await
        .unwrap();
        let rules = db.list_acl_rules().await.unwrap();
        assert_eq!(rules.len(), 1);

        let identity: &dyn UserRepo = &db;
        assert_eq!(db.user_count().await.unwrap(), 0);
        identity.insert_user("test", "hash", "viewer", false).await.unwrap();
        assert_eq!(db.user_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn create_tables_installs_query_shape_indexes() {
        let db = test_db().await;
        let expected = [
            ("soar_block_rules", "idx_soar_block_active_expires"),
            ("soar_block_rules", "idx_soar_block_created_at"),
            ("soar_block_rules", "idx_soar_block_unblocked_at"),
            ("soar_block_rules", "idx_soar_block_source_created"),
            ("soar_executions", "idx_soar_executions_executed_at"),
            ("soar_executions", "idx_soar_executions_trigger_executed"),
            ("user_group_members", "idx_user_group_members_group_id"),
            ("api_keys", "idx_api_keys_key_hash"),
        ];

        db.pool
            .conn_and_then(move |conn| {
                for (table, index) in expected {
                    let count: i64 = conn.query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND tbl_name = ?1 AND name = ?2",
                        params![table, index],
                        |row| row.get(0),
                    )?;
                    assert_eq!(count, 1, "missing index {index} on {table}");
                }
                Ok::<(), Error>(())
            })
            .await
            .unwrap();
    }
}
