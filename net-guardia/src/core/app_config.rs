use std::fs;
use std::sync::OnceLock;
use std::sync::RwLock as SyncRwLock;

use macros::log;
use tokio::sync::RwLock as AsyncRwLock;

use crate::model::config::{Config, ConfigTable};
use crate::model::error::system::SystemError;
use crate::model::error::Error;
use crate::model::log::system::SystemLog;

static SYNC_CONFIG: OnceLock<SyncRwLock<Config>> = OnceLock::new();
static ASYNC_CONFIG: OnceLock<AsyncRwLock<Config>> = OnceLock::new();

pub struct AppConfig;

impl AppConfig {
    pub async fn initialization() -> Result<(), Error> {
        log!(SystemLog::Initializing);
        let config = Self::load_config()?;
        SYNC_CONFIG.get_or_init(|| SyncRwLock::new(config.clone()));
        ASYNC_CONFIG.get_or_init(move || AsyncRwLock::new(config));
        log!(SystemLog::InitializeComplete);
        Ok(())
    }

    fn load_config() -> Result<Config, Error> {
        let toml_string = fs::read_to_string("./config.toml").map_err(SystemError::ConfigNotFound)?;
        let config_table = toml::from_str::<ConfigTable>(&toml_string).map_err(|_| SystemError::InvalidConfig)?;
        let config = config_table.config;
        if !Self::validate(&config) {
            Err(SystemError::InvalidConfig)?
        } else {
            Ok(config)
        }
    }

    pub fn now_blocking() -> Config {
        // Initialization has been ensured
        let once_lock = SYNC_CONFIG.get().unwrap();
        // There is no lock acquired multiple times, so this is safe
        once_lock.read().unwrap().clone()
    }

    pub async fn now() -> Config {
        // Initialization has been ensured
        let once_lock = ASYNC_CONFIG.get().unwrap();
        // There is no lock acquired multiple times, so this is safe
        once_lock.read().await.clone()
    }

    fn validate(config: &Config) -> bool {
        Self::validate_second(config.refresh_interval)
    }

    fn validate_second(second: u64) -> bool {
        second <= 3600
    }
}
