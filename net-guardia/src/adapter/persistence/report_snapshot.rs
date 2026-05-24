use async_trait::async_trait;
use rusqlite::{Error as RusqliteError, params};

use super::Database;
use crate::common::error::Error;
use crate::interface::reporting::report_snapshot::ReportSnapshotRepo;

impl Database {
    pub async fn get_report_snapshot(&self, key: &str) -> Result<Option<String>, Error> {
        let key = key.to_string();
        self.pool
            .conn_and_then(move |conn| {
                let result = conn.query_row(
                    "SELECT value FROM report_snapshots WHERE key = ?1",
                    params![key],
                    |row| row.get(0),
                );
                match result {
                    Ok(value) => Ok(Some(value)),
                    Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    pub async fn set_report_snapshot(&self, key: &str, value: &str) -> Result<(), Error> {
        let key = key.to_string();
        let value = value.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO report_snapshots (key, value) VALUES (?1, ?2)",
                    params![key, value],
                )?;
                Ok(())
            })
            .await
    }
}

#[async_trait]
impl ReportSnapshotRepo for Database {
    async fn get_report_snapshot(&self, key: &str) -> Result<Option<String>, Error> {
        self.get_report_snapshot(key).await
    }

    async fn set_report_snapshot(&self, key: &str, value: &str) -> Result<(), Error> {
        self.set_report_snapshot(key, value).await
    }
}
