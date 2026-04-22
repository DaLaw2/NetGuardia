use rusqlite::{Error as RusqliteError, Transaction, params};

use super::Database;
use crate::domain::common::error::Error;
use crate::interface::port::setting::SettingRepo;

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

    fn transaction(&self, f: &mut dyn FnMut(&dyn SettingRepo) -> Result<(), Error>) -> Result<(), Error> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let view = SettingTxView { tx: &tx };
        match f(&view) {
            Ok(()) => {
                tx.commit()?;
                Ok(())
            }
            Err(e) => {
                let _ = tx.rollback();
                Err(e)
            }
        }
    }
}

struct SettingTxView<'a> {
    tx: &'a Transaction<'a>,
}

impl SettingRepo for SettingTxView<'_> {
    fn transaction(&self, f: &mut dyn FnMut(&dyn SettingRepo) -> Result<(), Error>) -> Result<(), Error> {
        f(self)
    }

    fn get_setting(&self, key: &str) -> Result<Option<String>, Error> {
        let result = self
            .tx
            .query_row("SELECT value FROM settings WHERE key = ?1", params![key], |row| {
                row.get(0)
            });
        match result {
            Ok(val) => Ok(Some(val)),
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e)?,
        }
    }

    fn set_setting(&self, key: &str, value: &str) -> Result<(), Error> {
        self.tx.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    fn get_app_secret(&self, key: &str) -> Result<Option<String>, Error> {
        let result = self
            .tx
            .query_row("SELECT value FROM app_secrets WHERE key = ?1", params![key], |row| {
                row.get(0)
            });
        match result {
            Ok(val) => Ok(Some(val)),
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e)?,
        }
    }

    fn set_app_secret(&self, key: &str, plaintext: &str) -> Result<(), Error> {
        self.tx.execute(
            "INSERT OR REPLACE INTO app_secrets (key, value) VALUES (?1, ?2)",
            params![key, plaintext],
        )?;
        Ok(())
    }

    fn get_notification_config(&self, channel: &str) -> Result<Option<String>, Error> {
        match self.tx.query_row(
            "SELECT config_json FROM notification_config WHERE channel = ?1 AND enabled = 1",
            params![channel],
            |row| row.get::<_, String>(0),
        ) {
            Ok(json) => Ok(Some(json)),
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e)?,
        }
    }

    fn set_notification_config(&self, channel: &str, config_json: &str) -> Result<(), Error> {
        self.tx.execute(
            "INSERT INTO notification_config (channel, config_json) VALUES (?1, ?2) \
             ON CONFLICT(channel) DO UPDATE SET config_json = ?2, updated_at = datetime('now')",
            params![channel, config_json],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_db;
    use crate::domain::common::error::Error;
    use crate::domain::common::error::misc::MiscError;
    use crate::interface::port::setting::SettingRepo;

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
    fn tx_commits_on_ok() {
        let db = test_db();
        db.transaction(&mut |repo| {
            repo.set_setting("a", "1")?;
            repo.set_setting("b", "2")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(db.get_setting("a").unwrap().as_deref(), Some("1"));
        assert_eq!(db.get_setting("b").unwrap().as_deref(), Some("2"));
    }

    #[test]
    fn tx_rolls_back_on_err() {
        let db = test_db();
        db.set_setting("a", "initial").unwrap();
        let result: Result<(), Error> = db.transaction(&mut |repo| {
            repo.set_setting("a", "changed")?;
            repo.set_setting("b", "new")?;
            Err(MiscError::ValidationError("bail".to_string()))?
        });
        assert!(result.is_err());
        assert_eq!(db.get_setting("a").unwrap().as_deref(), Some("initial"));
        assert_eq!(db.get_setting("b").unwrap(), None);
    }

    #[test]
    fn tx_reads_see_pending_writes() {
        let db = test_db();
        db.transaction(&mut |repo| {
            repo.set_setting("k", "v")?;
            assert_eq!(repo.get_setting("k")?.as_deref(), Some("v"));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tx_covers_app_secrets_table() {
        let db = test_db();
        db.transaction(&mut |repo| {
            repo.set_app_secret("smtp_password", "envelope_blob")?;
            repo.set_setting("smtp_password", "")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            db.get_app_secret("smtp_password").unwrap().as_deref(),
            Some("envelope_blob")
        );
        assert_eq!(db.get_setting("smtp_password").unwrap().as_deref(), Some(""));
    }
}
