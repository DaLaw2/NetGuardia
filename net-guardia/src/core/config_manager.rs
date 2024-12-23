use crate::model::config::{Config, ConfigTable};
use crate::utils::log_entry::system::SystemEntry;
use std::sync::OnceLock;
use std::fs;
use std::sync::RwLock as SyncRwLock;
use anyhow::anyhow;
use tokio::sync::RwLock as AsyncRwLock;
use tracing::{error, info};

static SYNC_CONFIG: OnceLock<SyncRwLock<Config>> = OnceLock::new();
static ASYNC_CONFIG: OnceLock<AsyncRwLock<Config>> = OnceLock::new();

pub struct ConfigManager;

impl ConfigManager {
    pub async fn initialization() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Initializing);
        let config = Self::load_config()?;
        SYNC_CONFIG.get_or_init(|| SyncRwLock::new(config.clone()));
        ASYNC_CONFIG.get_or_init(move || AsyncRwLock::new(config));
        info!("{}", SystemEntry::InitializeComplete);
        Ok(())
    }

    fn load_config() -> anyhow::Result<Config> {
        let parse_result = (|| {
            let toml_string = fs::read_to_string("./config.toml")
                .map_err(|_| anyhow!(SystemEntry::ConfigNotFound))?;
            let config_table = toml::from_str::<ConfigTable>(&toml_string)
                .map_err(|_| anyhow!(SystemEntry::InvalidConfig))?;
            let config = config_table.config;
            if !Self::validate(&config) {
                Err(anyhow!(SystemEntry::InvalidConfig))
            } else {
                Ok(config)
            }
        })();
        match parse_result {
            Ok(config) => Ok(config),
            Err(err) => {
                error!("{}", SystemEntry::InvalidConfig);
                Err(err)
            }
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

    #[allow(dead_code)]
    pub async fn update(config: Config) {
        // Initialization has been ensured
        let lock = SYNC_CONFIG.get().unwrap();
        // There is no lock acquired multiple times, so this is safe
        *lock.write().unwrap() = config.clone();
        // Initialization has been ensured
        let lock = ASYNC_CONFIG.get().unwrap();
        *lock.write().await = config;
    }

    fn validate(config: &Config) -> bool {
        Self::validate_second(config.refresh_interval)
    }

    fn validate_second(second: u64) -> bool {
        second <= 3600
    }
}
