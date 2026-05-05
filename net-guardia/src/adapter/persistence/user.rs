use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use rusqlite::{Error as RusqliteError, params};

use super::Database;
use crate::domain::common::error::Error;
use crate::domain::common::error::database::DatabaseError;
use crate::domain::identity::auth::{GROUP_ADMIN, GROUP_VIEWER, LOGIN_LOCKOUT_SECS, LOGIN_MAX_FAILURES, ROLE_ADMIN};
use crate::domain::identity::user::{
    GroupMemberView, UserGroupMembership, UserGroupView, UserView, UserWithGroupsView,
};
use crate::interface::identity::{LoginAttemptRepo, UserGroupRepo, UserRepo};

fn user_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserView> {
    Ok(UserView {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        force_password_change: row.get::<_, i64>(3)? != 0,
    })
}

fn group_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserGroupView> {
    Ok(UserGroupView {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        permissions: row.get(3)?,
        created_at: row.get(4)?,
    })
}

impl Database {
    pub async fn find_user(&self, username: &str) -> Result<Option<UserView>, Error> {
        let username = username.to_string();
        self.pool
            .conn_and_then(move |conn| {
                match conn.query_row(
                    "SELECT id, username, password_hash, force_password_change FROM users WHERE username = ?1",
                    params![username],
                    user_from_row,
                ) {
                    Ok(user) => Ok(Some(user)),
                    Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    pub async fn insert_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
        force_password_change: bool,
    ) -> Result<i64, Error> {
        let username = username.to_string();
        let password_hash = password_hash.to_string();
        let role = role.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, force_password_change) VALUES (?1, ?2, ?3, ?4)",
                    params![username, password_hash, role, force_password_change as i64],
                )
                .map_err(|e| -> Error {
                    if e.to_string().contains("UNIQUE constraint") {
                        DatabaseError::UserAlreadyExists(username.clone()).into()
                    } else {
                        e.into()
                    }
                })?;
                Ok(conn.last_insert_rowid())
            })
            .await
    }

    pub async fn update_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error> {
        let password_hash = password_hash.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "UPDATE users SET password_hash = ?1, force_password_change = 0 WHERE id = ?2",
                    params![password_hash, user_id],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn user_count(&self) -> Result<i64, Error> {
        self.pool
            .conn_and_then(move |conn| Ok(conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?))
            .await
    }

    pub async fn list_users_with_groups(&self) -> Result<Vec<UserWithGroupsView>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT u.id, u.username, u.force_password_change, u.created_at, \
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
                        row.get::<_, i64>(2)? != 0,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                })?;

                let mut user_map: HashMap<i64, UserWithGroupsView> = HashMap::new();
                let mut order: Vec<i64> = Vec::new();
                for row in rows {
                    let (id, username, force_pw, created_at, group_id, group_name) = row?;
                    let entry = user_map.entry(id).or_insert_with(|| {
                        order.push(id);
                        UserWithGroupsView {
                            id,
                            username,
                            force_password_change: force_pw,
                            created_at,
                            groups: Vec::new(),
                        }
                    });
                    if let (Some(gid), Some(gname)) = (group_id, group_name) {
                        entry.groups.push(UserGroupMembership {
                            group_id: gid,
                            group_name: gname,
                        });
                    }
                }
                Ok(order.into_iter().filter_map(|id| user_map.remove(&id)).collect())
            })
            .await
    }

    pub async fn delete_user(&self, user_id: i64) -> Result<bool, Error> {
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                tx.execute("DELETE FROM user_group_members WHERE user_id = ?1", params![user_id])?;
                let affected = tx.execute("DELETE FROM users WHERE id = ?1", params![user_id])?;
                tx.commit()?;
                Ok(affected > 0)
            })
            .await
    }

    pub async fn update_user_role(&self, user_id: i64, role: &str) -> Result<(), Error> {
        let role = role.to_string();
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                tx.execute("UPDATE users SET role = ?1 WHERE id = ?2", params![role, user_id])?;
                let group_name = if role == ROLE_ADMIN { GROUP_ADMIN } else { GROUP_VIEWER };
                let group_id: i64 = tx.query_row(
                    "SELECT id FROM user_groups WHERE name = ?1",
                    params![group_name],
                    |row| row.get(0),
                )?;
                tx.execute("DELETE FROM user_group_members WHERE user_id = ?1", params![user_id])?;
                tx.execute(
                    "INSERT INTO user_group_members (user_id, group_id) VALUES (?1, ?2)",
                    params![user_id, group_id],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    pub async fn reset_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error> {
        let password_hash = password_hash.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "UPDATE users SET password_hash = ?1, force_password_change = 1 WHERE id = ?2",
                    params![password_hash, user_id],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn find_user_by_id(&self, user_id: i64) -> Result<Option<UserView>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                match conn.query_row(
                    "SELECT id, username, password_hash, force_password_change FROM users WHERE id = ?1",
                    params![user_id],
                    user_from_row,
                ) {
                    Ok(user) => Ok(Some(user)),
                    Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    pub async fn list_user_groups(&self) -> Result<Vec<UserGroupView>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT id, name, description, permissions, created_at FROM user_groups ORDER BY id")?;
                let rows = stmt.query_map([], group_from_row)?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            })
            .await
    }

    pub async fn create_user_group(&self, name: &str, description: &str, permissions: &str) -> Result<i64, Error> {
        let name = name.to_string();
        let description = description.to_string();
        let permissions = permissions.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT INTO user_groups (name, description, permissions) VALUES (?1, ?2, ?3)",
                    params![name, description, permissions],
                )
                .map_err(|e| -> Error {
                    if e.to_string().contains("UNIQUE constraint") {
                        DatabaseError::GroupAlreadyExists(name.clone()).into()
                    } else {
                        e.into()
                    }
                })?;
                Ok(conn.last_insert_rowid())
            })
            .await
    }

    pub async fn update_user_group(
        &self,
        id: i64,
        name: &str,
        description: &str,
        permissions: &str,
    ) -> Result<(), Error> {
        let name = name.to_string();
        let description = description.to_string();
        let permissions = permissions.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "UPDATE user_groups SET name = ?1, description = ?2, permissions = ?3 WHERE id = ?4",
                    params![name, description, permissions, id],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn delete_user_group(&self, id: i64) -> Result<bool, Error> {
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                tx.execute("DELETE FROM user_group_members WHERE group_id = ?1", params![id])?;
                let affected = tx.execute("DELETE FROM user_groups WHERE id = ?1", params![id])?;
                tx.commit()?;
                Ok(affected > 0)
            })
            .await
    }

    pub async fn get_user_group(&self, id: i64) -> Result<Option<UserGroupView>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                match conn.query_row(
                    "SELECT id, name, description, permissions, created_at FROM user_groups WHERE id = ?1",
                    params![id],
                    group_from_row,
                ) {
                    Ok(group) => Ok(Some(group)),
                    Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    pub async fn list_groups_for_user(&self, user_id: i64) -> Result<Vec<UserGroupView>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT g.id, g.name, g.description, g.permissions, g.created_at FROM user_groups g \
                     INNER JOIN user_group_members m ON g.id = m.group_id \
                     WHERE m.user_id = ?1 ORDER BY g.id",
                )?;
                let rows = stmt.query_map(params![user_id], group_from_row)?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            })
            .await
    }

    pub async fn set_user_groups(&self, user_id: i64, group_ids: &[i64]) -> Result<(), Error> {
        let group_ids = group_ids.to_vec();
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                for &gid in &group_ids {
                    tx.query_row("SELECT id FROM user_groups WHERE id = ?1", params![gid], |row| {
                        row.get::<_, i64>(0)
                    })?;
                }
                tx.execute("DELETE FROM user_group_members WHERE user_id = ?1", params![user_id])?;
                for &gid in &group_ids {
                    tx.execute(
                        "INSERT INTO user_group_members (user_id, group_id) VALUES (?1, ?2)",
                        params![user_id, gid],
                    )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
    }

    pub async fn list_user_permissions(&self, user_id: i64) -> Result<Vec<String>, Error> {
        let groups = self.list_groups_for_user(user_id).await?;
        let mut all_perms = HashSet::new();
        for g in groups {
            if let Ok(perms) = serde_json::from_str::<Vec<String>>(&g.permissions) {
                for p in perms {
                    all_perms.insert(p);
                }
            }
        }
        let mut result: Vec<String> = all_perms.into_iter().collect();
        result.sort();
        Ok(result)
    }

    pub async fn list_group_member_ids(&self, group_id: i64) -> Result<Vec<i64>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare("SELECT user_id FROM user_group_members WHERE group_id = ?1")?;
                let rows = stmt.query_map(params![group_id], |row| row.get::<_, i64>(0))?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            })
            .await
    }

    pub async fn list_group_members(&self, group_id: i64) -> Result<Vec<GroupMemberView>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT u.id, u.username FROM users u \
                     INNER JOIN user_group_members m ON u.id = m.user_id \
                     WHERE m.group_id = ?1 ORDER BY u.username",
                )?;
                let rows = stmt.query_map(params![group_id], |row| {
                    Ok(GroupMemberView {
                        id: row.get(0)?,
                        username: row.get(1)?,
                    })
                })?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            })
            .await
    }

    pub async fn record_login_failure(&self, username: &str) -> Result<(u32, Option<u64>), Error> {
        let username = username.to_string();
        let count: u32 = self
            .pool
            .conn_and_then({
                let username = username.clone();
                move |conn| {
                    let count = conn
                        .query_row(
                            "SELECT failure_count FROM login_attempts WHERE username = ?1",
                            params![username],
                            |row| row.get::<_, u32>(0),
                        )
                        .unwrap_or(0)
                        + 1;
                    conn.execute(
                        "INSERT INTO login_attempts (username, failure_count) VALUES (?1, ?2) \
                         ON CONFLICT(username) DO UPDATE SET failure_count = ?2",
                        params![username, count],
                    )?;
                    Ok::<u32, Error>(count)
                }
            })
            .await?;
        if count >= LOGIN_MAX_FAILURES {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs();
            let locked_until = now + LOGIN_LOCKOUT_SECS;
            let locked_until_db = locked_until as i64;
            self.pool
                .conn_and_then(move |conn| {
                    conn.execute(
                        "UPDATE login_attempts SET locked_until = ?2 WHERE username = ?1",
                        params![username, locked_until_db],
                    )?;
                    Ok::<(), Error>(())
                })
                .await?;
            Ok((count, Some(locked_until)))
        } else {
            Ok((count, None))
        }
    }

    pub async fn check_login_locked(&self, username: &str) -> Result<Option<u64>, Error> {
        let username = username.to_string();
        if let Some(locked_until) = self
            .pool
            .conn_and_then({
                let username = username.clone();
                move |conn| {
                    let result = conn.query_row(
                        "SELECT locked_until FROM login_attempts WHERE username = ?1",
                        params![username],
                        |row| row.get::<_, Option<i64>>(0),
                    );
                    match result {
                        Ok(value) => Ok::<Option<u64>, Error>(value.and_then(|v| u64::try_from(v).ok())),
                        Err(rusqlite::Error::QueryReturnedNoRows) => Ok::<Option<u64>, Error>(None),
                        Err(e) => Err(Error::from(e)),
                    }
                }
            })
            .await?
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs();
            if now < locked_until {
                return Ok(Some(locked_until - now));
            }
            self.clear_login_failures(&username).await?;
        }
        Ok(None)
    }

    pub async fn clear_login_failures(&self, username: &str) -> Result<(), Error> {
        let username = username.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute("DELETE FROM login_attempts WHERE username = ?1", params![username])?;
                Ok(())
            })
            .await
    }
}

#[async_trait]
impl UserRepo for Database {
    async fn find_user(&self, username: &str) -> Result<Option<UserView>, Error> {
        self.find_user(username).await
    }

    async fn find_user_by_id(&self, user_id: i64) -> Result<Option<UserView>, Error> {
        self.find_user_by_id(user_id).await
    }

    async fn insert_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
        force_password_change: bool,
    ) -> Result<i64, Error> {
        self.insert_user(username, password_hash, role, force_password_change)
            .await
    }

    async fn update_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error> {
        self.update_user_password(user_id, password_hash).await
    }

    async fn list_users_with_groups(&self) -> Result<Vec<UserWithGroupsView>, Error> {
        self.list_users_with_groups().await
    }

    async fn delete_user(&self, user_id: i64) -> Result<bool, Error> {
        self.delete_user(user_id).await
    }

    async fn update_user_role(&self, user_id: i64, role: &str) -> Result<(), Error> {
        self.update_user_role(user_id, role).await
    }

    async fn reset_user_password(&self, user_id: i64, password_hash: &str) -> Result<(), Error> {
        self.reset_user_password(user_id, password_hash).await
    }
}

#[async_trait]
impl UserGroupRepo for Database {
    async fn list_user_groups(&self) -> Result<Vec<UserGroupView>, Error> {
        self.list_user_groups().await
    }

    async fn create_user_group(&self, name: &str, description: &str, permissions: &str) -> Result<i64, Error> {
        self.create_user_group(name, description, permissions).await
    }

    async fn update_user_group(&self, id: i64, name: &str, description: &str, permissions: &str) -> Result<(), Error> {
        self.update_user_group(id, name, description, permissions).await
    }

    async fn delete_user_group(&self, id: i64) -> Result<bool, Error> {
        self.delete_user_group(id).await
    }

    async fn get_user_group(&self, id: i64) -> Result<Option<UserGroupView>, Error> {
        self.get_user_group(id).await
    }

    async fn list_groups_for_user(&self, user_id: i64) -> Result<Vec<UserGroupView>, Error> {
        self.list_groups_for_user(user_id).await
    }

    async fn set_user_groups(&self, user_id: i64, group_ids: &[i64]) -> Result<(), Error> {
        self.set_user_groups(user_id, group_ids).await
    }

    async fn list_user_permissions(&self, user_id: i64) -> Result<Vec<String>, Error> {
        self.list_user_permissions(user_id).await
    }

    async fn list_group_member_ids(&self, group_id: i64) -> Result<Vec<i64>, Error> {
        self.list_group_member_ids(group_id).await
    }

    async fn list_group_members(&self, group_id: i64) -> Result<Vec<GroupMemberView>, Error> {
        self.list_group_members(group_id).await
    }
}

#[async_trait]
impl LoginAttemptRepo for Database {
    async fn record_login_failure(&self, username: &str) -> Result<(u32, Option<u64>), Error> {
        self.record_login_failure(username).await
    }

    async fn check_login_locked(&self, username: &str) -> Result<Option<u64>, Error> {
        self.check_login_locked(username).await
    }

    async fn clear_login_failures(&self, username: &str) -> Result<(), Error> {
        self.clear_login_failures(username).await
    }
}
