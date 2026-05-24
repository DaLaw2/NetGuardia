use async_trait::async_trait;
use rusqlite::{Error as RusqliteError, params};

use super::Database;
use crate::common::error::Error;
use crate::common::error::system::SystemError;
use crate::domain::identity::auth::{GROUP_ADMIN, ROLE_ADMIN};
use crate::interface::system::config_repo::ConfigRepo;
use crate::interface::system::setup::SetupRepo;

impl Database {
    pub async fn get_config_value(&self, key: &str) -> Result<Option<String>, Error> {
        let key = key.to_string();
        self.pool
            .conn_and_then(move |conn| {
                let result = conn.query_row("SELECT value FROM settings WHERE key = ?1", params![key], |row| {
                    row.get(0)
                });
                match result {
                    Ok(val) => Ok(Some(val)),
                    Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    pub async fn set_config_value(&self, key: &str, value: &str) -> Result<(), Error> {
        let key = key.to_string();
        let value = value.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
                    params![key, value],
                )?;
                Ok(())
            })
            .await
    }

    async fn get_app_secret(&self, key: &str) -> Result<Option<String>, Error> {
        let key = key.to_string();
        self.pool
            .conn_and_then(move |conn| {
                let result = conn.query_row("SELECT value FROM app_secrets WHERE key = ?1", params![key], |row| {
                    row.get(0)
                });
                match result {
                    Ok(val) => Ok(Some(val)),
                    Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    async fn set_app_secret(&self, key: &str, value: &str) -> Result<(), Error> {
        let key = key.to_string();
        let value = value.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO app_secrets (key, value) VALUES (?1, ?2)",
                    params![key, value],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn get_notification_config(&self, channel: &str) -> Result<Option<String>, Error> {
        let channel = channel.to_string();
        self.pool
            .conn_and_then(move |conn| {
                match conn.query_row(
                    "SELECT config_json FROM notification_config WHERE channel = ?1 AND enabled = 1",
                    params![channel],
                    |row| row.get::<_, String>(0),
                ) {
                    Ok(json) => Ok(Some(json)),
                    Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    pub async fn set_notification_config(&self, channel: &str, config_json: &str) -> Result<(), Error> {
        let channel = channel.to_string();
        let config_json = config_json.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT INTO notification_config (channel, config_json) VALUES (?1, ?2) \
                     ON CONFLICT(channel) DO UPDATE SET config_json = ?2, enabled = 1, updated_at = datetime('now')",
                    params![channel, config_json],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn complete_setup_atomically(
        &self,
        config_values: Vec<(String, String)>,
        secrets: Vec<(String, String)>,
        notification_configs: Vec<(String, String)>,
        admin_username: &str,
        password_hash: &str,
    ) -> Result<(), Error> {
        let admin_username = admin_username.to_string();
        let password_hash = password_hash.to_string();
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                let setup_complete = tx.query_row(
                    "SELECT value FROM system_state WHERE key = 'setup_complete'",
                    [],
                    |row| row.get::<_, String>(0),
                );
                match setup_complete {
                    Ok(value) if value == "true" => Err(SystemError::SetupAlreadyComplete)?,
                    Ok(_) | Err(RusqliteError::QueryReturnedNoRows) => {}
                    Err(e) => Err(e)?,
                }
                for (key, value) in config_values {
                    tx.execute(
                        "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
                        params![key, value],
                    )?;
                }
                for (key, value) in secrets {
                    tx.execute(
                        "INSERT OR REPLACE INTO app_secrets (key, value) VALUES (?1, ?2)",
                        params![key, value],
                    )?;
                }
                for (channel, config_json) in notification_configs {
                    tx.execute(
                        "INSERT INTO notification_config (channel, config_json) VALUES (?1, ?2) \
                         ON CONFLICT(channel) DO UPDATE SET config_json = ?2, enabled = 1, updated_at = datetime('now')",
                        params![channel, config_json],
                    )?;
                }
                tx.execute(
                    "INSERT INTO users (username, password_hash, role, force_password_change) \
                     VALUES (?1, ?2, ?3, 0) \
                     ON CONFLICT(username) DO UPDATE SET password_hash = ?2, force_password_change = 0",
                    params![admin_username, password_hash, ROLE_ADMIN],
                )?;
                let admin_id = tx.query_row(
                    "SELECT id FROM users WHERE username = ?1",
                    params![admin_username],
                    |row| row.get::<_, i64>(0),
                )?;
                let admin_group_id = tx.query_row(
                    "SELECT id FROM user_groups WHERE name = ?1",
                    params![GROUP_ADMIN],
                    |row| row.get::<_, i64>(0),
                )?;
                tx.execute(
                    "INSERT OR IGNORE INTO user_group_members (user_id, group_id) VALUES (?1, ?2)",
                    params![admin_id, admin_group_id],
                )?;
                tx.execute(
                    "INSERT OR REPLACE INTO system_state (key, value) VALUES ('setup_complete', 'true')",
                    [],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }
}

#[async_trait]
impl ConfigRepo for Database {
    async fn get_config_value(&self, key: &str) -> Result<Option<String>, Error> {
        self.get_config_value(key).await
    }

    async fn set_config_value(&self, key: &str, value: &str) -> Result<(), Error> {
        self.set_config_value(key, value).await
    }

    async fn get_app_secret(&self, key: &str) -> Result<Option<String>, Error> {
        self.get_app_secret(key).await
    }

    async fn set_app_secret(&self, key: &str, plaintext: &str) -> Result<(), Error> {
        self.set_app_secret(key, plaintext).await
    }

    async fn get_notification_config(&self, channel: &str) -> Result<Option<String>, Error> {
        self.get_notification_config(channel).await
    }

    async fn set_notification_config(&self, channel: &str, config_json: &str) -> Result<(), Error> {
        self.set_notification_config(channel, config_json).await
    }

    async fn update_config_values_atomically(
        &self,
        config_values: Vec<(String, String)>,
        secrets: Vec<(String, String)>,
    ) -> Result<(), Error> {
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                for (key, value) in config_values {
                    tx.execute(
                        "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
                        params![key, value],
                    )?;
                }
                for (key, value) in secrets {
                    tx.execute(
                        "INSERT OR REPLACE INTO app_secrets (key, value) VALUES (?1, ?2)",
                        params![key, value],
                    )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
    }
}

#[async_trait]
impl SetupRepo for Database {
    async fn complete_setup_atomically(
        &self,
        config_values: Vec<(String, String)>,
        secrets: Vec<(String, String)>,
        notification_configs: Vec<(String, String)>,
        admin_username: &str,
        password_hash: &str,
    ) -> Result<(), Error> {
        self.complete_setup_atomically(
            config_values,
            secrets,
            notification_configs,
            admin_username,
            password_hash,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::adapter::persistence::Database;
    use crate::common::error::Error;
    use crate::domain::identity::auth::{DEFAULT_ADMIN_USERNAME, ROLE_ADMIN};

    #[tokio::test]
    async fn complete_setup_atomically_commits_all_setup_state() {
        let db = Database::new(":memory:").await.expect("database");

        db.complete_setup_atomically(
            vec![("ingress_interface".to_string(), "eth0".to_string())],
            vec![("smtp_password".to_string(), "encrypted-secret".to_string())],
            vec![("telegram".to_string(), "{}".to_string())],
            DEFAULT_ADMIN_USERNAME,
            "new-hash",
        )
        .await
        .expect("setup commit");

        assert_eq!(
            db.get_config_value("ingress_interface").await.unwrap().as_deref(),
            Some("eth0")
        );
        assert_eq!(
            db.get_app_secret("smtp_password").await.unwrap().as_deref(),
            Some("encrypted-secret")
        );
        assert_eq!(
            db.get_notification_config("telegram").await.unwrap().as_deref(),
            Some("{}")
        );
        assert_eq!(
            db.get_system_state("setup_complete").await.unwrap().as_deref(),
            Some("true")
        );
        let admin = db
            .find_user(DEFAULT_ADMIN_USERNAME)
            .await
            .expect("find admin")
            .expect("admin exists");
        assert_eq!(admin.password_hash, "new-hash");
        assert!(!admin.force_password_change);
    }

    #[tokio::test]
    async fn complete_setup_atomically_rejects_second_completion() {
        let db = Database::new(":memory:").await.expect("database");
        db.insert_user(DEFAULT_ADMIN_USERNAME, "old-hash", ROLE_ADMIN, true)
            .await
            .expect("insert admin");

        db.complete_setup_atomically(
            vec![("ingress_interface".to_string(), "eth0".to_string())],
            Vec::new(),
            Vec::new(),
            DEFAULT_ADMIN_USERNAME,
            "first-hash",
        )
        .await
        .expect("first setup commit");

        let err = db
            .complete_setup_atomically(
                vec![("ingress_interface".to_string(), "eth1".to_string())],
                Vec::new(),
                Vec::new(),
                DEFAULT_ADMIN_USERNAME,
                "second-hash",
            )
            .await
            .expect_err("second setup completion should be rejected");

        assert!(err.to_string().contains("Setup already completed"));
        assert_eq!(
            db.get_config_value("ingress_interface").await.unwrap().as_deref(),
            Some("eth0")
        );
        let admin = db
            .find_user(DEFAULT_ADMIN_USERNAME)
            .await
            .expect("find admin")
            .expect("admin exists");
        assert_eq!(admin.password_hash, "first-hash");
    }

    #[tokio::test]
    async fn set_notification_config_reenables_existing_channel() {
        let db = Database::new(":memory:").await.expect("database");
        db.pool
            .conn_and_then(|conn| {
                conn.execute(
                    "INSERT INTO notification_config (channel, config_json, enabled) VALUES (?1, ?2, 0)",
                    rusqlite::params!["telegram", r#"{"chat_id":"old"}"#],
                )?;
                Ok::<(), Error>(())
            })
            .await
            .expect("seed disabled channel");

        db.set_notification_config("telegram", r#"{"chat_id":"new"}"#)
            .await
            .expect("set config");

        assert_eq!(
            db.get_notification_config("telegram").await.unwrap().as_deref(),
            Some(r#"{"chat_id":"new"}"#)
        );
    }
}
