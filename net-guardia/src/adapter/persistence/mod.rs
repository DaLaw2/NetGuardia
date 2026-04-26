mod acl;
mod api_key;
mod audit;
mod enforcement;
mod setting;
mod soar;
mod soar_block;
mod stats;
mod user;

use std::env;

use macros::log;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
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
use crate::domain::identity::auth::{ADMIN_PERMISSIONS, GROUP_ADMIN, GROUP_VIEWER, VIEWER_PERMISSIONS};

/// Reads the SQLCipher encryption key from the environment variable `NETGUARDIA_DB_KEY`.
/// Returns `Some(key)` if set and non-empty, `None` otherwise (dev / unencrypted mode).
fn db_encryption_key() -> Option<String> {
    match env::var("NETGUARDIA_DB_KEY") {
        Ok(k) if !k.is_empty() => Some(k),
        _ => None,
    }
}

/// Applies the SQLCipher PRAGMA key (if configured) and standard PRAGMAs
/// to every new connection obtained from the pool.
#[derive(Debug, Clone)]
struct SqlitePragmaCustomizer {
    /// `None` means no encryption (dev mode).
    encryption_key: Option<String>,
}

impl r2d2::CustomizeConnection<Connection, rusqlite::Error> for SqlitePragmaCustomizer {
    fn on_acquire(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        // SQLCipher: the very first statement on a connection MUST be PRAGMA key.
        if let Some(ref key) = self.encryption_key {
            // Use a parameterised query to avoid SQL-injection via the key value.
            conn.pragma_update(None, "key", key)?;
        }
        // PRAGMA tuning notes:
        // - `journal_mode=WAL`: many concurrent readers + one writer; the only
        //   journal mode that survives crashes without losing committed rows.
        // - `synchronous=NORMAL`: canonical pairing with WAL — `FULL` adds an
        //   extra fsync per commit that buys no durability guarantees beyond
        //   what WAL already provides for a power-loss event.
        // - `busy_timeout=5000`: WAL still serializes writers (SOAR, audit,
        //   drift, SQL hooks all share one DB), and the default 0ms returns
        //   SQLITE_BUSY immediately on any contention. 5s gives the loser
        //   enough time to wait out a normal commit (sub-ms) without masking
        //   genuine deadlocks.
        // - `foreign_keys=ON`: enforce FK constraints at the connection
        //   level (SQLite's default is OFF for backwards compatibility).
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; \
             PRAGMA synchronous=NORMAL; \
             PRAGMA busy_timeout=5000; \
             PRAGMA foreign_keys=ON;",
        )?;
        Ok(())
    }
}

pub struct Database {
    pool: Pool<SqliteConnectionManager>,
    /// HMAC-SHA256 key for API key hashing, derived from NETGUARDIA_SECRETS_KEY.
    api_key_hmac: [u8; 32],
}

impl Database {
    pub fn new(path: &str) -> Result<Self, Error> {
        let encryption_key = db_encryption_key();

        if path != ":memory:" && encryption_key.is_none() {
            log!(MiscLog::DbEncryptionDisabled);
        }

        let manager = if path == ":memory:" {
            SqliteConnectionManager::memory()
        } else {
            SqliteConnectionManager::file(path)
        };

        let customizer = SqlitePragmaCustomizer {
            encryption_key: encryption_key.clone(),
        };

        let pool = Pool::builder()
            .max_size(if path == ":memory:" { 1 } else { 6 })
            .connection_customizer(Box::new(customizer))
            .build(manager)
            .map_err(DatabaseError::QueryFailed)?;

        // Verify the pool is actually usable (catches wrong key / corrupt DB early).
        {
            let test_conn = pool.get().map_err(DatabaseError::QueryFailed)?;
            test_conn
                .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
                .map_err(|_| DatabaseError::EncryptionKeyInvalid)?;
        }

        let api_key_hmac = Self::derive_api_key_hmac();
        let db = Self { pool, api_key_hmac };
        db.create_tables()?;
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

    fn conn(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>, Error> {
        self.pool.get().map_err(|e| DatabaseError::QueryFailed(e).into())
    }

    fn create_tables(&self) -> Result<(), Error> {
        let conn = self.conn()?;
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
                unblocked_at TEXT
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

        let conn_ref = &*conn;

        // Seed default user groups on first install (empty table)
        let group_count: i64 = conn_ref.query_row("SELECT COUNT(*) FROM user_groups", [], |row| row.get(0))?;
        if group_count == 0 {
            let all_permissions = serde_json::to_string(&ADMIN_PERMISSIONS).unwrap_or_else(|_| "[]".to_string());
            let viewer_permissions = serde_json::to_string(&VIEWER_PERMISSIONS).unwrap_or_else(|_| "[]".to_string());

            conn_ref.execute(
                "INSERT INTO user_groups (name, description, permissions) VALUES (?1, ?2, ?3)",
                params![GROUP_ADMIN, "Full system access with all permissions", &all_permissions],
            )?;
            conn_ref.execute(
                "INSERT INTO user_groups (name, description, permissions) VALUES (?1, ?2, ?3)",
                params![GROUP_VIEWER, "Read-only access to all modules", &viewer_permissions],
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::acl::AclRepo;
    use crate::interface::identity::UserRepo;
    use crate::interface::setting::SettingRepo;

    pub(super) fn test_db() -> Database {
        Database::new(":memory:").expect("Failed to create test database")
    }

    #[test]
    fn test_create_tables() {
        let _db = test_db();
    }

    /// Verify that Database satisfies each aggregate Repo trait contract
    /// (AclRepo / SettingRepo / UserRepo). Exercises the trait-object
    /// path so callers that take `Arc<dyn XxxRepo>` compile end-to-end.
    #[test]
    fn test_aggregate_repo_trait_objects() {
        let db = test_db();

        let setting: &dyn SettingRepo = &db;
        setting.set_setting("test_key", "test_value").unwrap();
        assert_eq!(setting.get_setting("test_key").unwrap(), Some("test_value".to_string()));

        let acl: &dyn AclRepo = &db;
        acl.insert_acl_rule(4, "source", "blacklist", "10.0.0.1", 443).unwrap();
        // load_acl_rules is an inherent Database method (not on AclRepo),
        // so go through `&db` directly for this read-back assertion.
        let rules = db.list_acl_rules().unwrap();
        assert_eq!(rules.len(), 1);

        let identity: &dyn UserRepo = &db;
        // user_count is inherent — inserts still go through the trait so
        // the vtable has something to exercise.
        assert_eq!(db.user_count().unwrap(), 0);
        identity.insert_user("test", "hash", "viewer", false).unwrap();
        assert_eq!(db.user_count().unwrap(), 1);
    }
}
