use super::helpers::{override_parsed, override_string, seed_key};
use crate::interface::port::setting::SettingRepo;
use crate::model::error::Error;

#[derive(Debug, Clone)]
pub struct TelegramConfig {
    pub rate_limit_max_messages: u32,
    pub rate_limit_window_secs: u32,
    pub max_retries: u32,
}

impl TelegramConfig {
    pub fn defaults() -> Self {
        Self {
            rate_limit_max_messages: 20,
            rate_limit_window_secs: 60,
            max_retries: 2,
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_parsed(
            &mut cfg.rate_limit_max_messages,
            repo,
            "telegram_rate_limit_max_messages",
        )?;
        override_parsed(&mut cfg.rate_limit_window_secs, repo, "telegram_rate_limit_window_secs")?;
        override_parsed(&mut cfg.max_retries, repo, "telegram_max_retries")?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "telegram_rate_limit_max_messages", "20")?;
        seed_key(repo, "telegram_rate_limit_window_secs", "60")?;
        seed_key(repo, "telegram_max_retries", "2")?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub sender: String,
    pub recipient: String,
}

impl SmtpConfig {
    pub fn defaults() -> Self {
        Self {
            host: String::new(),
            port: 587,
            username: String::new(),
            sender: String::new(),
            recipient: String::new(),
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_string(&mut cfg.host, repo, "smtp_host")?;
        override_parsed(&mut cfg.port, repo, "smtp_port")?;
        override_string(&mut cfg.username, repo, "smtp_username")?;
        override_string(&mut cfg.sender, repo, "smtp_sender")?;
        override_string(&mut cfg.recipient, repo, "smtp_recipient")?;
        Ok(cfg)
    }

    pub fn seed_defaults(_repo: &dyn SettingRepo) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct NotificationConfig {
    pub telegram: TelegramConfig,
    pub smtp: SmtpConfig,
}

impl NotificationConfig {
    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        Ok(Self {
            telegram: TelegramConfig::from_settings(repo)?,
            smtp: SmtpConfig::from_settings(repo)?,
        })
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        TelegramConfig::seed_defaults(repo)?;
        SmtpConfig::seed_defaults(repo)?;
        Ok(())
    }
}
