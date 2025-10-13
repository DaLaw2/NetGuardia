use std::fs;
use std::ops::Deref;

use crate::model::config::{Config, ConfigTable};
use crate::model::error::system::SystemError;
use crate::model::error::Error;

pub struct AppConfig {
    pub config: Config,
}

impl AppConfig {
    pub fn new() -> Result<Self, Error> {
        let toml_string = fs::read_to_string("./config.toml").map_err(SystemError::ConfigNotFound)?;
        let config_table = toml::from_str::<ConfigTable>(&toml_string).map_err(|_| SystemError::InvalidConfig)?;
        let config = config_table.config;
        if !Self::validate(&config) {
            Err(SystemError::InvalidConfig)?
        } else {
            Ok(Self { config })
        }
    }

    fn validate(config: &Config) -> bool {
        Self::validate_second(config.refresh_interval)
    }

    fn validate_second(second: u64) -> bool {
        second <= 3600
    }
}

impl Deref for AppConfig {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}
