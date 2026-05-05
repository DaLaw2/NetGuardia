use async_trait::async_trait;
use rusqlite::{Error as RusqliteError, params};

use super::Database;
use crate::domain::common::error::Error;
use crate::interface::config_repo::ConfigRepo;

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
                     ON CONFLICT(channel) DO UPDATE SET config_json = ?2, updated_at = datetime('now')",
                    params![channel, config_json],
                )?;
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
