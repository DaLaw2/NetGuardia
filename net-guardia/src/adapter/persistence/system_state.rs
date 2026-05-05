use async_trait::async_trait;
use rusqlite::{Error as RusqliteError, params};

use super::Database;
use crate::domain::common::error::Error;
use crate::interface::system_state::SystemStateRepo;

impl Database {
    pub async fn get_system_state(&self, key: &str) -> Result<Option<String>, Error> {
        let key = key.to_string();
        self.pool
            .conn_and_then(move |conn| {
                let result = conn.query_row("SELECT value FROM system_state WHERE key = ?1", params![key], |row| {
                    row.get(0)
                });
                match result {
                    Ok(value) => Ok(Some(value)),
                    Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    pub async fn set_system_state(&self, key: &str, value: &str) -> Result<(), Error> {
        let key = key.to_string();
        let value = value.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO system_state (key, value) VALUES (?1, ?2)",
                    params![key, value],
                )?;
                Ok(())
            })
            .await
    }
}

#[async_trait]
impl SystemStateRepo for Database {
    async fn get_system_state(&self, key: &str) -> Result<Option<String>, Error> {
        self.get_system_state(key).await
    }

    async fn set_system_state(&self, key: &str, value: &str) -> Result<(), Error> {
        self.set_system_state(key, value).await
    }
}
