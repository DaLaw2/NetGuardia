use std::fs;
use tracing::Level;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::model::error::io::IOError;
use crate::model::error::Error;

pub struct Logging;

impl Logging {
    pub fn initialize() -> Result<(), Error> {
        let log_directory = "logs";
        fs::create_dir_all(log_directory)
            .map_err(|err| IOError::CreateDirectoryFailed(log_directory, err))?;

        let file_appender = RollingFileAppender::new(Rotation::DAILY, log_directory, "NetGuardia");

        let stdout_layer = tracing_subscriber::fmt::layer()
            .with_file(true)
            .with_line_number(true)
            .with_thread_ids(true)
            .with_target(false)
            .with_ansi(true);

        let file_layer = tracing_subscriber::fmt::layer()
            .with_file(false)
            .with_line_number(false)
            .with_thread_ids(false)
            .with_target(true)
            .with_ansi(false)
            .with_writer(file_appender);

        let level = std::env::var("RUST_LOG")
            .ok()
            .and_then(|s| s.parse::<Level>().ok())
            .unwrap_or(if cfg!(debug_assertions) { Level::DEBUG } else { Level::INFO });

        tracing_subscriber::registry()
            .with(stdout_layer)
            .with(file_layer)
            .with(EnvFilter::from_default_env().add_directive(level.into()))
            .init();

        Ok(())
    }
}
