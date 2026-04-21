use rusqlite::{Error as RusqliteError, params};

use super::Database;
use crate::interface::port::setting::SettingRepo;
use crate::model::error::Error;

impl Database {
    pub fn get_setting(&self, key: &str) -> Result<Option<String>, Error> {
        let conn = self.conn()?;
        let result = conn.query_row("SELECT value FROM settings WHERE key = ?1", params![key], |row| {
            row.get(0)
        });
        match result {
            Ok(val) => Ok(Some(val)),
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e)?,
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

    pub fn get_app_secret(&self, key: &str) -> Result<Option<String>, Error> {
        let conn = self.conn()?;
        let result = conn.query_row("SELECT value FROM app_secrets WHERE key = ?1", params![key], |row| {
            row.get(0)
        });
        match result {
            Ok(val) => Ok(Some(val)),
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e)?,
        }
    }

    pub fn set_app_secret(&self, key: &str, value: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO app_secrets (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_notification_config(&self, channel: &str) -> Result<Option<String>, Error> {
        let conn = self.conn()?;
        match conn.query_row(
            "SELECT config_json FROM notification_config WHERE channel = ?1 AND enabled = 1",
            params![channel],
            |row| row.get::<_, String>(0),
        ) {
            Ok(json) => Ok(Some(json)),
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e)?,
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
}

impl SettingRepo for Database {
    fn get_setting(&self, key: &str) -> Result<Option<String>, Error> {
        self.get_setting(key)
    }

    fn set_setting(&self, key: &str, value: &str) -> Result<(), Error> {
        self.set_setting(key, value)
    }

    fn get_app_secret(&self, key: &str) -> Result<Option<String>, Error> {
        self.get_app_secret(key)
    }

    fn set_app_secret(&self, key: &str, plaintext: &str) -> Result<(), Error> {
        self.set_app_secret(key, plaintext)
    }

    fn get_notification_config(&self, channel: &str) -> Result<Option<String>, Error> {
        self.get_notification_config(channel)
    }

    fn set_notification_config(&self, channel: &str, config_json: &str) -> Result<(), Error> {
        self.set_notification_config(channel, config_json)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_db;

    #[test]
    fn test_settings_crud() {
        let db = test_db();
        assert_eq!(db.get_setting("foo").unwrap(), None);

        db.set_setting("foo", "bar").unwrap();
        assert_eq!(db.get_setting("foo").unwrap(), Some("bar".to_string()));

        db.set_setting("foo", "baz").unwrap();
        assert_eq!(db.get_setting("foo").unwrap(), Some("baz".to_string()));
    }
}
