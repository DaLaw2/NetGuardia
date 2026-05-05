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
use macros::log;
use rusqlite::{self, Connection, params};

use crate::domain::common::error::Error;
use crate::domain::common::error::database::DatabaseError;
use crate::domain::common::log::misc::MiscLog;

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
use crate::domain::identity::auth::{ADMIN_PERMISSIONS, GROUP_ADMIN, GROUP_VIEWER, VIEWER_PERMISSIONS};

/// Reads the SQLCipher encryption key from the environment variable `NETGUARDIA_DB_KEY`.
/// Returns `Some(key)` if set and non-empty, `None` otherwise (dev / unencrypted mode).
fn db_encryption_key() -> Option<String> {
    match env::var("NETGUARDIA_DB_KEY") {
        Ok(k) if !k.is_empty() => Some(k),
        _ => None,
    }
}

pub struct Database {
    pool: Client,
    /// HMAC-SHA256 key for API key hashing, derived from NETGUARDIA_SECRETS_KEY.
    api_key_hmac: [u8; 32],
}

impl Database {
    pub async fn new(path: &str) -> Result<Self, Error> {
        let encryption_key = db_encryption_key();

        if path != ":memory:" && encryption_key.is_none() {
            log!(MiscLog::DbEncryptionDisabled);
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

        // Verify the pool is actually usable (catches wrong key / corrupt DB early).
        pool.conn(|conn| conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(())))
            .await
            .map_err(|_| DatabaseError::EncryptionKeyInvalid)?;

        let api_key_hmac = Self::derive_api_key_hmac();
        let db = Self { pool, api_key_hmac };
        db.create_tables().await?;
        Ok(db)
    }

    /// Derive HMAC-SHA256 key for API key hashing from NETGUARDIA_SECRETS_KEY.
    /// Falls back to a static dev key if the env var is unset.
    fn derive_api_key_hmac() -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let root_key = env::var("NETGUARDIA_SECRETS_KEY")
            .ok()
            .filter(|k| !k.is_empty())
            .or_else(|| env::var("NETGUARDIA_DB_KEY").ok().filter(|k| !k.is_empty()))
            .unwrap_or_else(|| "netguardia-dev-api-key-secret".to_string());

        let hk = Hkdf::<Sha256>::new(Some(b"netguardia-v1-salt"), root_key.as_bytes());
        let mut okm = [0u8; 32];
        // SAFETY: 32 bytes is a valid output length for HKDF-SHA256
        hk.expand(b"netguardia-apikey-hmac-v1", &mut okm).unwrap();
        okm
    }

    /// Export an encrypted database to a plaintext copy.
    /// The original file is NOT modified.
    pub fn decrypt_to_file(src_path: &str, key: &str, dest_path: &str) -> Result<(), Error> {
        let conn = Connection::open(src_path).map_err(DatabaseError::QueryFailed)?;
        conn.pragma_update(None, "key", key)
            .map_err(DatabaseError::QueryFailed)?;
        // Verify we can read the encrypted DB
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(|_| DatabaseError::DatabaseNotReadable)?;
        // Attach a plaintext destination (empty key = no encryption)
        conn.execute("ATTACH DATABASE ?1 AS plaintext KEY '';", params![dest_path])
            .map_err(DatabaseError::QueryFailed)?;
        conn.query_row("SELECT sqlcipher_export('plaintext')", [], |_| Ok(()))
            .map_err(DatabaseError::QueryFailed)?;
        conn.execute_batch("DETACH DATABASE plaintext;")
            .map_err(DatabaseError::QueryFailed)?;
        Ok(())
    }

    /// Encrypt a plaintext database to a new encrypted copy.
    /// The original file is NOT modified.
    pub fn encrypt_to_file(src_path: &str, key: &str, dest_path: &str) -> Result<(), Error> {
        let conn = Connection::open(src_path).map_err(DatabaseError::QueryFailed)?;
        // Verify it's readable as plaintext
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
                retry_count INTEGER NOT NULL DEFAULT 0
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

                if !Self::column_exists(conn, "soar_block_rules", "created_acl_rule")? {
                    conn.execute(
                        "ALTER TABLE soar_block_rules ADD COLUMN created_acl_rule INTEGER NOT NULL DEFAULT 1",
                        [],
                    )?;
                }
                if !Self::column_exists(conn, "soar_block_rules", "preserve_acl_on_unblock")? {
                    conn.execute(
                        "ALTER TABLE soar_block_rules ADD COLUMN preserve_acl_on_unblock INTEGER NOT NULL DEFAULT 0",
                        [],
                    )?;
                }

                Self::migrate_legacy_settings_state(conn)?;

                let group_count: i64 = conn.query_row("SELECT COUNT(*) FROM user_groups", [], |row| row.get(0))?;
                if group_count == 0 {
                    let all_permissions =
                        serde_json::to_string(&ADMIN_PERMISSIONS).unwrap_or_else(|_| "[]".to_string());
                    let viewer_permissions =
                        serde_json::to_string(&VIEWER_PERMISSIONS).unwrap_or_else(|_| "[]".to_string());

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

    fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool, Error> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
        for row in rows {
            if row? == column {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn migrate_legacy_settings_state(conn: &Connection) -> Result<(), Error> {
        conn.execute_batch(
            "
            INSERT OR IGNORE INTO system_state (key, value)
                SELECT key, value FROM settings WHERE key = 'setup_complete';

            INSERT OR IGNORE INTO report_snapshots (key, value)
                SELECT key, value FROM settings
                WHERE key IN (
                    'weekly_threats_count',
                    'weekly_top_ips',
                    'weekly_threat_breakdown',
                    'weekly_system_health',
                    'system_uptime_percent',
                    'active_rules_count',
                    'weekly_geo_distribution',
                    'weekly_soar_blocks',
                    'weekly_soar_triggers',
                    'weekly_soar_unblocks',
                    'weekly_blocked_count'
                );

            INSERT OR IGNORE INTO login_attempts (username, failure_count)
                SELECT substr(key, length('login_failures:') + 1), CAST(value AS INTEGER)
                FROM settings
                WHERE key LIKE 'login_failures:%';

            INSERT INTO login_attempts (username, locked_until)
                SELECT substr(key, length('login_locked_until:') + 1), CAST(value AS INTEGER)
                FROM settings
                WHERE key LIKE 'login_locked_until:%'
                ON CONFLICT(username) DO UPDATE SET
                    locked_until = COALESCE(login_attempts.locked_until, excluded.locked_until);

            DELETE FROM settings
            WHERE key = 'setup_complete'
               OR key IN (
                    'weekly_threats_count',
                    'weekly_top_ips',
                    'weekly_threat_breakdown',
                    'weekly_system_health',
                    'system_uptime_percent',
                    'active_rules_count',
                    'weekly_geo_distribution',
                    'weekly_soar_blocks',
                    'weekly_soar_triggers',
                    'weekly_soar_unblocks',
                    'weekly_blocked_count'
               )
               OR key LIKE 'login_failures:%'
               OR key LIKE 'login_locked_until:%';
            ",
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::interface::acl::AclRepo;
    use crate::interface::config_repo::ConfigRepo;
    use crate::interface::identity::UserRepo;

    pub(super) async fn test_db() -> Database {
        Database::new(":memory:").await.expect("Failed to create test database")
    }

    #[tokio::test]
    async fn test_create_tables() {
        let _db = test_db().await;
    }

    /// Verify that Database satisfies each aggregate Repo trait contract
    /// (AclRepo / ConfigRepo / UserRepo). Exercises the trait-object
    /// path so callers that take `Arc<dyn XxxRepo>` compile end-to-end.
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
        acl.insert_acl_rule(4, "source", "blacklist", "10.0.0.1", 443)
            .await
            .unwrap();
        // load_acl_rules is an inherent Database method (not on AclRepo),
        // so go through `&db` directly for this read-back assertion.
        let rules = db.list_acl_rules().await.unwrap();
        assert_eq!(rules.len(), 1);

        let identity: &dyn UserRepo = &db;
        // user_count is inherent — inserts still go through the trait so
        // the vtable has something to exercise.
        assert_eq!(db.user_count().await.unwrap(), 0);
        identity.insert_user("test", "hash", "viewer", false).await.unwrap();
        assert_eq!(db.user_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn legacy_non_config_settings_are_backfilled() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("netguardia-legacy-settings-{}-{unique}.db", std::process::id()));
        let locked_until = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600;

        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "
                CREATE TABLE settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                ",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)",
                params!["setup_complete", "true"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)",
                params!["weekly_threats_count", "7"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)",
                params!["login_failures:alice", "4"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)",
                params!["login_locked_until:alice", locked_until.to_string()],
            )
            .unwrap();
        }

        let db = Database::new(path.to_str().unwrap()).await.unwrap();

        assert_eq!(
            db.get_system_state("setup_complete").await.unwrap(),
            Some("true".to_string())
        );
        assert_eq!(
            db.get_report_snapshot("weekly_threats_count").await.unwrap(),
            Some("7".to_string())
        );
        assert_eq!(db.get_config_value("setup_complete").await.unwrap(), None);
        assert_eq!(db.get_config_value("weekly_threats_count").await.unwrap(), None);

        let remaining_lock = db.check_login_locked("alice").await.unwrap();
        assert!(remaining_lock.is_some_and(|remaining| remaining > 0));
        assert_eq!(db.get_config_value("login_failures:alice").await.unwrap(), None);

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
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
