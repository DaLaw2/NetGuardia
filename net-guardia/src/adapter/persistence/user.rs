use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Error as RusqliteError, params};

use super::Database;
use crate::interface::port::identity::{IdentityRepo, UserGroupTuple, UserTuple, UserWithGroups};
use crate::model::error::Error;
use crate::model::error::database::DatabaseError;

impl Database {
    pub fn find_user(&self, username: &str) -> Result<Option<UserTuple>, Error> {
        let conn = self.conn()?;
        let result = conn.query_row(
            "SELECT id, username, password_hash, role, force_password_change FROM users WHERE username = ?1",
            params![username],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get::<_, i64>(4)? != 0,
                ))
            },
        );
        match result {
            Ok(user) => Ok(Some(user)),
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e)?,
        }
    }

    pub fn insert_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
        force_password_change: bool,
    ) -> Result<i64, Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO users (username, password_hash, role, force_password_change) VALUES (?1, ?2, ?3, ?4)",
            params![username, password_hash, role, force_password_change as i64],
        )
        .map_err(|e| -> Error {
            if e.to_string().contains("UNIQUE constraint") {
                DatabaseError::UserAlreadyExists(username.to_string()).into()
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

    pub fn list_users_with_groups(&self) -> Result<Vec<UserWithGroups>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT u.id, u.username, u.role, u.force_password_change, u.created_at, \
                    g.id, g.name \
             FROM users u \
             LEFT JOIN user_group_members m ON u.id = m.user_id \
             LEFT JOIN user_groups g ON g.id = m.group_id \
             ORDER BY u.id, g.id",
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

        let mut user_map: HashMap<i64, UserWithGroups> = HashMap::new();
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

    pub fn find_user_by_id(&self, user_id: i64) -> Result<Option<UserTuple>, Error> {
        let conn = self.conn()?;
        let result = conn.query_row(
            "SELECT id, username, password_hash, role, force_password_change FROM users WHERE id = ?1",
            params![user_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get::<_, i64>(4)? != 0,
                ))
            },
        );
        match result {
            Ok(user) => Ok(Some(user)),
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e)?,
        }
    }

    pub fn list_user_groups(&self) -> Result<Vec<UserGroupTuple>, Error> {
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare("SELECT id, name, description, permissions, created_at FROM user_groups ORDER BY id")?;
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
        )
        .map_err(|e| -> Error {
            if e.to_string().contains("UNIQUE constraint") {
                DatabaseError::GroupAlreadyExists(name).into()
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

    pub fn get_user_group(&self, id: i64) -> Result<Option<UserGroupTuple>, Error> {
        let conn = self.conn()?;
        let result = conn.query_row(
            "SELECT id, name, description, permissions, created_at FROM user_groups WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        );
        match result {
            Ok(group) => Ok(Some(group)),
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e)?,
        }
    }

    pub fn list_groups_for_user(&self, user_id: i64) -> Result<Vec<(i64, String, String, String)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT g.id, g.name, g.description, g.permissions FROM user_groups g \
             INNER JOIN user_group_members m ON g.id = m.group_id \
             WHERE m.user_id = ?1 ORDER BY g.id",
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

    pub fn list_user_permissions(&self, user_id: i64) -> Result<Vec<String>, Error> {
        let groups = self.list_groups_for_user(user_id)?;
        let mut all_perms = HashSet::new();
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

    pub fn list_group_member_ids(&self, group_id: i64) -> Result<Vec<i64>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT user_id FROM user_group_members WHERE group_id = ?1")?;
        let rows = stmt.query_map(params![group_id], |row| row.get::<_, i64>(0))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn list_group_members(&self, group_id: i64) -> Result<Vec<(i64, String)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT u.id, u.username FROM users u \
             INNER JOIN user_group_members m ON u.id = m.user_id \
             WHERE m.group_id = ?1 ORDER BY u.username",
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

    pub fn record_login_failure(&self, username: &str) -> Result<(u32, Option<u64>), Error> {
        let key_count = format!("login_failures:{}", username);
        let key_locked = format!("login_locked_until:{}", username);

        let count: u32 = self.get_setting(&key_count)?.and_then(|v| v.parse().ok()).unwrap_or(0) + 1;

        self.set_setting(&key_count, &count.to_string())?;

        if count >= 5 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
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
            && let Ok(locked_until) = locked_str.parse::<u64>()
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
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
        conn.execute(
            "DELETE FROM settings WHERE key = ?1",
            params![format!("login_failures:{}", username)],
        )?;
        conn.execute(
            "DELETE FROM settings WHERE key = ?1",
            params![format!("login_locked_until:{}", username)],
        )?;
        Ok(())
    }
}

impl IdentityRepo for Database {
    fn find_user(&self, username: &str) -> Result<Option<UserTuple>, Error> {
        self.find_user(username)
    }

    fn find_user_by_id(&self, user_id: i64) -> Result<Option<UserTuple>, Error> {
        self.find_user_by_id(user_id)
    }

    fn insert_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
        force_password_change: bool,
    ) -> Result<i64, Error> {
        self.insert_user(username, password_hash, role, force_password_change)
    }

    fn update_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error> {
        self.update_user_password(user_id, password_hash)
    }

    fn list_users_with_groups(&self) -> Result<Vec<UserWithGroups>, Error> {
        self.list_users_with_groups()
    }

    fn delete_user(&self, user_id: i64) -> Result<bool, Error> {
        self.delete_user(user_id)
    }

    fn update_user_role(&self, user_id: i64, role: &str) -> Result<(), Error> {
        self.update_user_role(user_id, role)
    }

    fn reset_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error> {
        self.reset_user_password(user_id, password_hash)
    }

    fn list_user_groups(&self) -> Result<Vec<UserGroupTuple>, Error> {
        self.list_user_groups()
    }

    fn create_user_group(&self, name: &str, description: &str, permissions: &str) -> Result<i64, Error> {
        self.create_user_group(name, description, permissions)
    }

    fn update_user_group(&self, id: i64, name: &str, description: &str, permissions: &str) -> Result<(), Error> {
        self.update_user_group(id, name, description, permissions)
    }

    fn delete_user_group(&self, id: i64) -> Result<bool, Error> {
        self.delete_user_group(id)
    }

    fn get_user_group(&self, id: i64) -> Result<Option<UserGroupTuple>, Error> {
        self.get_user_group(id)
    }

    fn list_groups_for_user(&self, user_id: i64) -> Result<Vec<(i64, String, String, String)>, Error> {
        self.list_groups_for_user(user_id)
    }

    fn set_user_groups(&self, user_id: i64, group_ids: &[i64]) -> Result<(), Error> {
        self.set_user_groups(user_id, group_ids)
    }

    fn list_user_permissions(&self, user_id: i64) -> Result<Vec<String>, Error> {
        self.list_user_permissions(user_id)
    }

    fn list_group_member_ids(&self, group_id: i64) -> Result<Vec<i64>, Error> {
        self.list_group_member_ids(group_id)
    }

    fn list_group_members(&self, group_id: i64) -> Result<Vec<(i64, String)>, Error> {
        self.list_group_members(group_id)
    }

    fn record_login_failure(&self, username: &str) -> Result<(u32, Option<u64>), Error> {
        self.record_login_failure(username)
    }

    fn check_login_locked(&self, username: &str) -> Result<Option<u64>, Error> {
        self.check_login_locked(username)
    }

    fn clear_login_failures(&self, username: &str) -> Result<(), Error> {
        self.clear_login_failures(username)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_db;

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
    fn test_find_nonexistent_user() {
        let db = test_db();
        assert!(db.find_user("nobody").unwrap().is_none());
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
}
