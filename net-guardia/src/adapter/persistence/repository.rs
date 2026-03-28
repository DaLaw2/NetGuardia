use std::collections::HashMap;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;

use crate::model::error::database::DatabaseError;
use crate::model::error::Error;

/// Applies SQLite PRAGMAs to each new connection in the pool.
#[derive(Debug)]
struct SqlitePragmaCustomizer;

impl r2d2::CustomizeConnection<rusqlite::Connection, rusqlite::Error> for SqlitePragmaCustomizer {
    fn on_acquire(&self, conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        Ok(())
    }
}

pub struct Database {
    pool: Pool<SqliteConnectionManager>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self, Error> {
        let manager = if path == ":memory:" {
            SqliteConnectionManager::memory()
        } else {
            SqliteConnectionManager::file(path)
        };

        let pool = Pool::builder()
            .max_size(if path == ":memory:" { 1 } else { 6 })
            .connection_customizer(Box::new(SqlitePragmaCustomizer))
            .build(manager)
            .map_err(|e| DatabaseError::QueryFailed { reason: e.to_string() })?;

        let db = Self { pool };
        db.create_tables()?;
        Ok(db)
    }

    fn conn(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>, Error> {
        self.pool.get().map_err(|e| -> Error {
            DatabaseError::QueryFailed { reason: e.to_string() }.into()
        })
    }

    fn create_tables(&self) -> Result<(), Error> {
        let conn = self.conn()?;
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
            CREATE TABLE IF NOT EXISTS mcp_keys (
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

        // Migration: seed default user groups if table is empty
        let group_count: i64 = conn_ref.query_row(
            "SELECT COUNT(*) FROM user_groups", [], |row| row.get(0),
        )?;
        if group_count == 0 {
            let all_permissions = serde_json::json!([
                "dashboard:read", "statistics:read", "traffic_map:read", "drops:read",
                "ai_detection:read", "ai_detection:write",
                "access_control:read", "access_control:write",
                "geo_block:read", "geo_block:write",
                "dns_filter:read", "dns_filter:write",
                "rate_limit:read", "rate_limit:write",
                "protocol_filter:read", "protocol_filter:write",
                "system:read", "system:write",
                "users:read", "users:write", "users:admin"
            ]).to_string();
            let viewer_permissions = serde_json::json!([
                "dashboard:read", "statistics:read", "traffic_map:read", "drops:read",
                "ai_detection:read", "access_control:read", "geo_block:read",
                "dns_filter:read", "rate_limit:read", "protocol_filter:read",
                "system:read"
            ]).to_string();

            conn_ref.execute(
                "INSERT INTO user_groups (name, description, permissions) VALUES (?1, ?2, ?3)",
                params!["Administrator", "Full system access with all permissions", &all_permissions],
            )?;
            conn_ref.execute(
                "INSERT INTO user_groups (name, description, permissions) VALUES (?1, ?2, ?3)",
                params!["Viewer", "Read-only access to all modules", &viewer_permissions],
            )?;
        }

        // Migration: assign existing users to default groups if user_group_members is empty
        let member_count: i64 = conn_ref.query_row(
            "SELECT COUNT(*) FROM user_group_members", [], |row| row.get(0),
        )?;
        if member_count == 0 {
            // Get admin group id and viewer group id
            let admin_group_id: Option<i64> = conn_ref.query_row(
                "SELECT id FROM user_groups WHERE name = 'Administrator'", [],
                |row| row.get(0),
            ).ok();
            let viewer_group_id: Option<i64> = conn_ref.query_row(
                "SELECT id FROM user_groups WHERE name = 'Viewer'", [],
                |row| row.get(0),
            ).ok();

            if let Some(ag_id) = admin_group_id {
                let mut stmt = conn_ref.prepare("SELECT id FROM users WHERE role = 'admin'")?;
                let admin_ids: Vec<i64> = stmt.query_map([], |row| row.get(0))?
                    .filter_map(|r| r.ok()).collect();
                for uid in admin_ids {
                    conn_ref.execute(
                        "INSERT OR IGNORE INTO user_group_members (user_id, group_id) VALUES (?1, ?2)",
                        params![uid, ag_id],
                    )?;
                }
            }
            if let Some(vg_id) = viewer_group_id {
                let mut stmt = conn_ref.prepare("SELECT id FROM users WHERE role = 'viewer'")?;
                let viewer_ids: Vec<i64> = stmt.query_map([], |row| row.get(0))?
                    .filter_map(|r| r.ok()).collect();
                for uid in viewer_ids {
                    conn_ref.execute(
                        "INSERT OR IGNORE INTO user_group_members (user_id, group_id) VALUES (?1, ?2)",
                        params![uid, vg_id],
                    )?;
                }
            }
        }

        Ok(())
    }

    // --- ACL ---
    pub fn insert_acl_rule(&self, ip_version: u8, direction: &str, list_type: &str, ip_address: &str, port: u16) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO acl_rules (ip_version, direction, list_type, ip_address, port) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ip_version, direction, list_type, ip_address, port as i64],
        )?;
        Ok(())
    }

    pub fn delete_acl_rule(&self, ip_version: u8, direction: &str, list_type: &str, ip_address: &str, port: u16) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM acl_rules WHERE ip_version = ?1 AND direction = ?2 AND list_type = ?3 AND ip_address = ?4 AND port = ?5",
            params![ip_version, direction, list_type, ip_address, port as i64],
        )?;
        Ok(())
    }

    pub fn load_acl_rules(&self) -> Result<Vec<crate::interface::port::repository::AclRuleTuple>, Error> {
        let conn = self.conn()?;
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
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO rate_limit_config (key, value) VALUES (?1, ?2)",
            params![key, value as i64],
        )?;
        Ok(())
    }

    pub fn load_rate_limit_config(&self) -> Result<Vec<(String, u64)>, Error> {
        let conn = self.conn()?;
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
        let conn = self.conn()?;
        conn.execute("INSERT OR IGNORE INTO dns_blacklist (domain) VALUES (?1)", params![domain])?;
        Ok(())
    }

    pub fn delete_dns_domain(&self, domain: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM dns_blacklist WHERE domain = ?1", params![domain])?;
        Ok(())
    }

    pub fn load_dns_domains(&self) -> Result<Vec<String>, Error> {
        let conn = self.conn()?;
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
        let conn = self.conn()?;
        conn.execute("INSERT OR IGNORE INTO geo_blocked_countries (country_code) VALUES (?1)", params![code])?;
        Ok(())
    }

    pub fn delete_geo_country(&self, code: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM geo_blocked_countries WHERE country_code = ?1", params![code])?;
        Ok(())
    }

    pub fn load_geo_countries(&self) -> Result<Vec<String>, Error> {
        let conn = self.conn()?;
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
        let conn = self.conn()?;
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
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    // --- Users ---
    pub fn find_user(&self, username: &str) -> Result<Option<crate::interface::port::repository::UserTuple>, Error> {
        let conn = self.conn()?;
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

    pub fn insert_user(&self, username: &str, password_hash: &str, role: &str, force_password_change: bool) -> Result<i64, Error> {
        let conn = self.conn()?;
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
        Ok(conn.last_insert_rowid())
    }

    pub fn update_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE users SET password_hash = ?1, force_password_change = 0 WHERE id = ?2",
            params![password_hash, user_id],
        )?;
        Ok(())
    }

    pub fn user_count(&self) -> Result<i64, Error> {
        let conn = self.conn()?;
        Ok(conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?)
    }

    pub fn list_users(&self) -> Result<Vec<crate::interface::port::repository::UserListItem>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT id, username, role, force_password_change, created_at FROM users ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)? != 0,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn list_users_with_groups(&self) -> Result<Vec<crate::interface::port::repository::UserWithGroups>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT u.id, u.username, u.role, u.force_password_change, u.created_at, \
                    g.id, g.name \
             FROM users u \
             LEFT JOIN user_group_members m ON u.id = m.user_id \
             LEFT JOIN user_groups g ON g.id = m.group_id \
             ORDER BY u.id, g.id"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)? != 0,
                row.get::<_, String>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })?;

        let mut user_map: HashMap<i64, crate::interface::port::repository::UserWithGroups> = HashMap::new();
        let mut order: Vec<i64> = Vec::new();

        for row in rows {
            let (id, username, role, force_pw, created_at, group_id, group_name) = row?;
            let entry = user_map.entry(id).or_insert_with(|| {
                order.push(id);
                (id, username, role, force_pw, created_at, Vec::new())
            });
            if let (Some(gid), Some(gname)) = (group_id, group_name) {
                entry.5.push((gid, gname));
            }
        }

        Ok(order.into_iter().filter_map(|id| user_map.remove(&id)).collect())
    }

    pub fn delete_user(&self, user_id: i64) -> Result<bool, Error> {
        self.cleanup_user_memberships(user_id)?;
        let conn = self.conn()?;
        let affected = conn.execute("DELETE FROM users WHERE id = ?1", params![user_id])?;
        Ok(affected > 0)
    }

    pub fn update_user_role(&self, user_id: i64, role: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute("UPDATE users SET role = ?1 WHERE id = ?2", params![role, user_id])?;
        Ok(())
    }

    pub fn reset_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE users SET password_hash = ?1, force_password_change = 1 WHERE id = ?2",
            params![password_hash, user_id],
        )?;
        Ok(())
    }

    pub fn find_user_by_id(&self, user_id: i64) -> Result<Option<crate::interface::port::repository::UserTuple>, Error> {
        let conn = self.conn()?;
        let result = conn.query_row(
            "SELECT id, username, password_hash, role, force_password_change FROM users WHERE id = ?1",
            params![user_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get::<_, i64>(4)? != 0)),
        );
        match result {
            Ok(user) => Ok(Some(user)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // --- User Groups ---
    pub fn list_user_groups(&self) -> Result<Vec<crate::interface::port::repository::UserGroupTuple>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT id, name, description, permissions, created_at FROM user_groups ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn create_user_group(&self, name: &str, description: &str, permissions: &str) -> Result<i64, Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO user_groups (name, description, permissions) VALUES (?1, ?2, ?3)",
            params![name, description, permissions],
        ).map_err(|e| -> Error {
            if e.to_string().contains("UNIQUE constraint") {
                DatabaseError::QueryFailed { reason: format!("Group '{}' already exists", name) }.into()
            } else {
                e.into()
            }
        })?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_user_group(&self, id: i64, name: &str, description: &str, permissions: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE user_groups SET name = ?1, description = ?2, permissions = ?3 WHERE id = ?4",
            params![name, description, permissions, id],
        )?;
        Ok(())
    }

    pub fn delete_user_group(&self, id: i64) -> Result<bool, Error> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM user_group_members WHERE group_id = ?1", params![id])?;
        let affected = conn.execute("DELETE FROM user_groups WHERE id = ?1", params![id])?;
        Ok(affected > 0)
    }

    pub fn get_user_group(&self, id: i64) -> Result<Option<crate::interface::port::repository::UserGroupTuple>, Error> {
        let conn = self.conn()?;
        let result = conn.query_row(
            "SELECT id, name, description, permissions, created_at FROM user_groups WHERE id = ?1",
            params![id],
            |row| Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            )),
        );
        match result {
            Ok(group) => Ok(Some(group)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // --- User Group Membership ---
    pub fn get_user_groups(&self, user_id: i64) -> Result<Vec<(i64, String, String, String)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT g.id, g.name, g.description, g.permissions FROM user_groups g \
             INNER JOIN user_group_members m ON g.id = m.group_id \
             WHERE m.user_id = ?1 ORDER BY g.id"
        )?;
        let rows = stmt.query_map(params![user_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn set_user_groups(&self, user_id: i64, group_ids: &[i64]) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM user_group_members WHERE user_id = ?1", params![user_id])?;
        for &gid in group_ids {
            conn.execute(
                "INSERT INTO user_group_members (user_id, group_id) VALUES (?1, ?2)",
                params![user_id, gid],
            )?;
        }
        Ok(())
    }

    pub fn get_user_permissions(&self, user_id: i64) -> Result<Vec<String>, Error> {
        let groups = self.get_user_groups(user_id)?;
        let mut all_perms = std::collections::HashSet::new();
        for (_id, _name, _desc, perms_json) in groups {
            if let Ok(perms) = serde_json::from_str::<Vec<String>>(&perms_json) {
                for p in perms {
                    all_perms.insert(p);
                }
            }
        }
        let mut result: Vec<String> = all_perms.into_iter().collect();
        result.sort();
        Ok(result)
    }

    pub fn cleanup_user_memberships(&self, user_id: i64) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM user_group_members WHERE user_id = ?1", params![user_id])?;
        Ok(())
    }

    pub fn get_group_member_ids(&self, group_id: i64) -> Result<Vec<i64>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT user_id FROM user_group_members WHERE group_id = ?1")?;
        let rows = stmt.query_map(params![group_id], |row| row.get::<_, i64>(0))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn get_group_members(&self, group_id: i64) -> Result<Vec<(i64, String)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT u.id, u.username FROM users u \
             INNER JOIN user_group_members m ON u.id = m.user_id \
             WHERE m.group_id = ?1 ORDER BY u.username"
        )?;
        let rows = stmt.query_map(params![group_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
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
        if let Some(locked_str) = self.get_setting(&key_locked)?
            && let Ok(locked_until) = locked_str.parse::<u64>() {
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
        Ok(None)
    }

    pub fn clear_login_failures(&self, username: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM settings WHERE key = ?1", params![format!("login_failures:{}", username)])?;
        conn.execute("DELETE FROM settings WHERE key = ?1", params![format!("login_locked_until:{}", username)])?;
        Ok(())
    }

    // --- MCP API Keys ---

    /// Validate an API key and return Claims if valid.
    /// Computes SHA-256 hash of the key and looks it up in mcp_keys table.
    pub fn validate_api_key(&self, api_key: &str) -> Result<Option<crate::model::auth::Claims>, Error> {
        use std::fmt::Write;

        // SHA-256 hash the key
        let digest = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(api_key.as_bytes());
            let result = hasher.finalize();
            let mut hex = String::with_capacity(64);
            for byte in result {
                write!(&mut hex, "{:02x}", byte).unwrap();
            }
            hex
        };

        let conn = self.conn()?;
        let result = conn.query_row(
            "SELECT id, name, permission_level FROM mcp_keys WHERE key_hash = ?1",
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
                    "UPDATE mcp_keys SET last_used_at = datetime('now') WHERE id = ?1",
                    params![id],
                );

                // Build permissions based on permission level
                let permissions = match level.as_str() {
                    "read_write" => vec![
                        "dashboard:read".into(), "statistics:read".into(),
                        "ai_detection:read".into(), "ai_detection:write".into(),
                        "access_control:read".into(), "access_control:write".into(),
                        "geo_block:read".into(), "geo_block:write".into(),
                        "dns_filter:read".into(), "dns_filter:write".into(),
                        "rate_limit:read".into(), "rate_limit:write".into(),
                        "system:read".into(), "system:write".into(),
                    ],
                    _ => vec![
                        "dashboard:read".into(), "statistics:read".into(),
                        "ai_detection:read".into(), "access_control:read".into(),
                        "geo_block:read".into(), "dns_filter:read".into(),
                        "rate_limit:read".into(), "system:read".into(),
                    ],
                };

                Ok(Some(crate::model::auth::Claims {
                    sub: -id, // negative ID to distinguish from user IDs
                    username: format!("mcp:{}", name),
                    role: level,
                    permissions,
                    exp: usize::MAX, // API keys don't expire (revocation via DB deletion)
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // --- SOAR ---

    pub fn insert_playbook(&self, name: &str, trigger_event: &str, threshold: Option<f64>, count: Option<i64>, window: Option<i64>, cooldown: i64) -> Result<i64, Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO playbooks (name, trigger_event, condition_threshold, condition_count, condition_window_secs, cooldown_secs) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![name, trigger_event, threshold, count, window, cooldown],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn insert_playbook_action(&self, playbook_id: i64, action_order: i64, action_type: &str, params_json: &str) -> Result<i64, Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO playbook_actions (playbook_id, action_order, action_type, params) VALUES (?1, ?2, ?3, ?4)",
            params![playbook_id, action_order, action_type, params_json],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn insert_soar_block_rule(&self, source_ip: &str, playbook_id: i64, expires_at: &str) -> Result<i64, Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO soar_block_rules (source_ip, playbook_id, expires_at) VALUES (?1, ?2, ?3)",
            params![source_ip, playbook_id, expires_at],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn count_active_soar_blocks(&self) -> Result<u32, Error> {
        let conn = self.conn()?;
        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM soar_block_rules WHERE unblocked_at IS NULL AND expires_at > datetime('now')",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn get_expired_soar_blocks(&self) -> Result<Vec<(i64, String, i64)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, source_ip, playbook_id FROM soar_block_rules WHERE expires_at <= datetime('now') AND unblocked_at IS NULL"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
        })?;
        let mut result = Vec::new();
        for row in rows { result.push(row?); }
        Ok(result)
    }

    /// Get a single SOAR block rule by ID, returning (id, source_ip, playbook_id, expires_at).
    pub fn get_soar_block_by_id(&self, id: i64) -> Result<Option<(i64, String, i64, String)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, source_ip, playbook_id, expires_at FROM soar_block_rules WHERE id = ?1"
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, String>(3)?))
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Load all playbooks with their actions in a single JOIN query (avoids N+1).
    /// Returns Vec of (playbook fields..., action fields...).
    #[allow(clippy::type_complexity)]
    pub fn load_playbooks_with_actions(&self) -> Result<Vec<(i64, String, bool, String, Option<f64>, Option<i64>, Option<i64>, i64, Option<i64>, Option<i64>, Option<String>, Option<String>)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT p.id, p.name, p.enabled, p.trigger_event, p.condition_threshold, \
                    p.condition_count, p.condition_window_secs, p.cooldown_secs, \
                    a.id, a.action_order, a.action_type, a.params \
             FROM playbooks p \
             LEFT JOIN playbook_actions a ON a.playbook_id = p.id \
             ORDER BY p.id, a.action_order"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<f64>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows { result.push(row?); }
        Ok(result)
    }

    pub fn mark_soar_block_unblocked(&self, id: i64) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE soar_block_rules SET unblocked_at = datetime('now') WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn get_active_soar_blocks(&self) -> Result<Vec<(i64, String, i64, String)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, source_ip, playbook_id, expires_at FROM soar_block_rules WHERE unblocked_at IS NULL AND expires_at > datetime('now')"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, String>(3)?))
        })?;
        let mut result = Vec::new();
        for row in rows { result.push(row?); }
        Ok(result)
    }

    pub fn insert_soar_execution(&self, playbook_id: i64, source_ip: Option<&str>, trigger_event: &str, actions_json: &str) -> Result<i64, Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO soar_executions (playbook_id, source_ip, trigger_event, actions_executed) VALUES (?1, ?2, ?3, ?4)",
            params![playbook_id, source_ip, trigger_event, actions_json],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn delete_playbook(&self, id: i64) -> Result<bool, Error> {
        let conn = self.conn()?;
        let rows = conn.execute(
            "DELETE FROM playbooks WHERE id = ?1",
            params![id],
        )?;
        Ok(rows > 0)
    }

    #[allow(clippy::type_complexity)]
    pub fn list_soar_executions(&self, limit: i64) -> Result<Vec<(i64, i64, Option<String>, String, String, String)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, playbook_id, source_ip, trigger_event, actions_executed, executed_at FROM soar_executions ORDER BY executed_at DESC LIMIT ?1"
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows { result.push(row?); }
        Ok(result)
    }

    pub fn has_manual_acl_rule(&self, ip_address: &str) -> Result<bool, Error> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM acl_rules WHERE ip_address = ?1 AND list_type = 'blacklist'",
            params![ip_address],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    // --- Admin Whitelist ---

    pub fn load_admin_whitelist(&self) -> Result<Vec<String>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT ip FROM admin_whitelist")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut result = Vec::new();
        for row in rows { result.push(row?); }
        Ok(result)
    }

    pub fn insert_admin_whitelist(&self, ip: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute("INSERT OR IGNORE INTO admin_whitelist (ip) VALUES (?1)", params![ip])?;
        Ok(())
    }

    pub fn delete_admin_whitelist(&self, ip: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM admin_whitelist WHERE ip = ?1", params![ip])?;
        Ok(())
    }

    // --- Notification Config ---

    pub fn get_notification_config(&self, channel: &str) -> Result<Option<String>, Error> {
        let conn = self.conn()?;
        match conn.query_row(
            "SELECT config_json FROM notification_config WHERE channel = ?1 AND enabled = 1",
            params![channel],
            |row| row.get::<_, String>(0),
        ) {
            Ok(json) => Ok(Some(json)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn set_notification_config(&self, channel: &str, config_json: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO notification_config (channel, config_json) VALUES (?1, ?2) \
             ON CONFLICT(channel) DO UPDATE SET config_json = ?2, updated_at = datetime('now')",
            params![channel, config_json],
        )?;
        Ok(())
    }

    // --- MCP Key Management ---

    pub fn insert_mcp_key(&self, key_hash: &str, name: &str, permission_level: &str) -> Result<i64, Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO mcp_keys (key_hash, name, permission_level) VALUES (?1, ?2, ?3)",
            params![key_hash, name, permission_level],
        )?;
        Ok(conn.last_insert_rowid())
    }

    #[allow(clippy::type_complexity)]
    pub fn list_mcp_keys(&self) -> Result<Vec<(i64, String, String, String, Option<String>)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT id, name, permission_level, created_at, last_used_at FROM mcp_keys")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows { result.push(row?); }
        Ok(result)
    }

    pub fn delete_mcp_key(&self, id: i64) -> Result<bool, Error> {
        let conn = self.conn()?;
        let affected = conn.execute("DELETE FROM mcp_keys WHERE id = ?1", params![id])?;
        Ok(affected > 0)
    }

    // --- Stats Aggregation ---

    /// Count SOAR executions in the last N days.
    pub fn count_weekly_executions(&self, days: i64) -> Result<u64, Error> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM soar_executions WHERE executed_at >= datetime('now', ?1)",
            params![format!("-{} days", days)],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Count SOAR blocks created in the last N days.
    pub fn count_weekly_blocks(&self, days: i64) -> Result<u64, Error> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM soar_block_rules WHERE created_at >= datetime('now', ?1)",
            params![format!("-{} days", days)],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Count SOAR unblocks in the last N days.
    pub fn count_weekly_unblocks(&self, days: i64) -> Result<u64, Error> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM soar_block_rules WHERE unblocked_at IS NOT NULL AND unblocked_at >= datetime('now', ?1)",
            params![format!("-{} days", days)],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Get threat breakdown by trigger_event in the last N days.
    pub fn weekly_threat_breakdown(&self, days: i64) -> Result<Vec<(String, u64)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT trigger_event, COUNT(*) FROM soar_executions WHERE executed_at >= datetime('now', ?1) GROUP BY trigger_event ORDER BY COUNT(*) DESC"
        )?;
        let rows = stmt.query_map(params![format!("-{} days", days)], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        let mut result = Vec::new();
        for row in rows { result.push(row?); }
        Ok(result)
    }

    /// Get top blocked IPs in the last N days.
    pub fn weekly_top_ips(&self, days: i64, limit: i64) -> Result<Vec<(String, u64)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT source_ip, COUNT(*) as cnt FROM soar_block_rules WHERE created_at >= datetime('now', ?1) GROUP BY source_ip ORDER BY cnt DESC LIMIT ?2"
        )?;
        let rows = stmt.query_map(params![format!("-{} days", days), limit], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        let mut result = Vec::new();
        for row in rows { result.push(row?); }
        Ok(result)
    }

    /// Count current ACL rules.
    pub fn count_acl_rules(&self) -> Result<u64, Error> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM acl_rules", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    // --- Default Playbooks ---

    pub fn seed_default_playbooks(&self) -> Result<(), Error> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM playbooks", [], |row| row.get(0))?;
        if count > 0 {
            return Ok(());
        }
        drop(conn);

        // 1. default_block: threat_detected, threshold 0.85 → block_ip(1800s) + log
        let pb1 = self.insert_playbook("default_block", "threat_detected", Some(0.85), None, None, 300)?;
        self.insert_playbook_action(pb1, 1, "block_ip", r#"{"ttl_secs": 1800}"#)?;
        self.insert_playbook_action(pb1, 2, "log", r#"{"level": "warn"}"#)?;

        // 2. brute_force_block: brute_force, count 5 in 60s → block_ip(3600s) + send_telegram + log
        let pb2 = self.insert_playbook("brute_force_block", "brute_force", None, Some(5), Some(60), 600)?;
        self.insert_playbook_action(pb2, 1, "block_ip", r#"{"ttl_secs": 3600}"#)?;
        self.insert_playbook_action(pb2, 2, "send_telegram", "{}")?;
        self.insert_playbook_action(pb2, 3, "log", r#"{"level": "warn"}"#)?;

        // 3. port_scan_alert: port_scan, threshold 0.7 → send_telegram + log (no block)
        let pb3 = self.insert_playbook("port_scan_alert", "port_scan", Some(0.7), None, None, 300)?;
        self.insert_playbook_action(pb3, 1, "send_telegram", "{}")?;
        self.insert_playbook_action(pb3, 2, "log", r#"{"level": "warn"}"#)?;

        Ok(())
    }
}

/// Implement the RepositoryPort trait, proving Database satisfies the port contract.
/// This enables adapter-level testing with mock implementations.
impl crate::interface::port::repository::RepositoryPort for Database {
    fn insert_acl_rule(&self, ip_version: u8, direction: &str, list_type: &str, ip_address: &str, port: u16) -> Result<(), Error> { self.insert_acl_rule(ip_version, direction, list_type, ip_address, port) }
    fn delete_acl_rule(&self, ip_version: u8, direction: &str, list_type: &str, ip_address: &str, port: u16) -> Result<(), Error> { self.delete_acl_rule(ip_version, direction, list_type, ip_address, port) }
    fn load_acl_rules(&self) -> Result<Vec<crate::interface::port::repository::AclRuleTuple>, Error> { self.load_acl_rules() }
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
    fn find_user(&self, username: &str) -> Result<Option<crate::interface::port::repository::UserTuple>, Error> { self.find_user(username) }
    fn insert_user(&self, username: &str, password_hash: &str, role: &str, force_password_change: bool) -> Result<i64, Error> { self.insert_user(username, password_hash, role, force_password_change) }
    fn update_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error> { self.update_user_password(user_id, password_hash) }
    fn user_count(&self) -> Result<i64, Error> { self.user_count() }
    fn list_users(&self) -> Result<Vec<crate::interface::port::repository::UserListItem>, Error> { self.list_users() }
    fn list_users_with_groups(&self) -> Result<Vec<crate::interface::port::repository::UserWithGroups>, Error> { self.list_users_with_groups() }
    fn delete_user(&self, user_id: i64) -> Result<bool, Error> { self.delete_user(user_id) }
    fn update_user_role(&self, user_id: i64, role: &str) -> Result<(), Error> { self.update_user_role(user_id, role) }
    fn reset_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error> { self.reset_user_password(user_id, password_hash) }
    fn find_user_by_id(&self, user_id: i64) -> Result<Option<crate::interface::port::repository::UserTuple>, Error> { self.find_user_by_id(user_id) }
    fn list_user_groups(&self) -> Result<Vec<crate::interface::port::repository::UserGroupTuple>, Error> { self.list_user_groups() }
    fn create_user_group(&self, name: &str, description: &str, permissions: &str) -> Result<i64, Error> { self.create_user_group(name, description, permissions) }
    fn update_user_group(&self, id: i64, name: &str, description: &str, permissions: &str) -> Result<(), Error> { self.update_user_group(id, name, description, permissions) }
    fn delete_user_group(&self, id: i64) -> Result<bool, Error> { self.delete_user_group(id) }
    fn get_user_group(&self, id: i64) -> Result<Option<crate::interface::port::repository::UserGroupTuple>, Error> { self.get_user_group(id) }
    fn get_user_groups(&self, user_id: i64) -> Result<Vec<(i64, String, String, String)>, Error> { self.get_user_groups(user_id) }
    fn set_user_groups(&self, user_id: i64, group_ids: &[i64]) -> Result<(), Error> { self.set_user_groups(user_id, group_ids) }
    fn get_user_permissions(&self, user_id: i64) -> Result<Vec<String>, Error> { self.get_user_permissions(user_id) }
    fn cleanup_user_memberships(&self, user_id: i64) -> Result<(), Error> { self.cleanup_user_memberships(user_id) }
    fn get_group_member_ids(&self, group_id: i64) -> Result<Vec<i64>, Error> { self.get_group_member_ids(group_id) }
    fn get_group_members(&self, group_id: i64) -> Result<Vec<(i64, String)>, Error> { self.get_group_members(group_id) }
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
