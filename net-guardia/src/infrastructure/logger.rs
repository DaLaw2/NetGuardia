use std::fs;
use std::{env, io};

use tracing::Level;
use tracing::level_filters::LevelFilter;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::Directive;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::layer as fmt_layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, filter, reload};

use crate::domain::common::config::AppConfig;
use crate::domain::common::error::Error;
use crate::domain::common::error::io::IOError;
use crate::infrastructure::log_buffer::{LogBuffer, LogBufferLayer};
pub trait FilterControl: Send + Sync {
    fn reload_filter(&self, filter: EnvFilter) -> Result<(), String>;
    fn current_filter(&self) -> String;
}

pub struct Logger {
    filter_handle: Box<dyn FilterControl>,
    preserved_directives: Vec<String>,
}

impl Logger {
    pub fn initialize(config: &AppConfig) -> Result<(Self, LogBuffer), Error> {
        let observability = &config.observability;
        let log_directory = &config.system.log_dir;
        fs::create_dir_all(log_directory).map_err(|err| IOError::CreateDirectoryFailed(log_directory.clone(), err))?;

        let file_appender = RollingFileAppender::new(Rotation::DAILY, log_directory, "NetGuardia");

        let stdout_layer = fmt_layer()
            .with_file(true)
            .with_line_number(true)
            .with_thread_ids(true)
            .with_target(false)
            .with_ansi(true);

        let file_layer = fmt_layer()
            .with_file(false)
            .with_line_number(false)
            .with_thread_ids(false)
            .with_target(true)
            .with_ansi(false)
            .with_writer(file_appender);

        let level: Level = observability
            .log_level
            .parse()
            .ok()
            .or_else(|| env::var("RUST_LOG").ok().and_then(|s| s.parse().ok()))
            .unwrap_or(Level::INFO);

        let mut preserved: Vec<String> = env::var("RUST_LOG")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|d| !d.is_empty() && d.contains('='))
                    .collect()
            })
            .unwrap_or_default();
        if !preserved.iter().any(|d| d == "maxminddb=warn") {
            preserved.push("maxminddb=warn".to_string());
        }

        let mut filter = EnvFilter::new(level.to_string());
        filter = Self::apply_directives(filter, &preserved);
        let (filter_layer, reload_handle) = reload::Layer::new(filter);

        let (log_buffer_layer, log_buffer) = LogBufferLayer::new(
            observability.log_buffer_capacity,
            observability.log_buffer_max_message_bytes,
        );

        tracing_subscriber::registry()
            .with(filter_layer)
            .with(stdout_layer)
            .with(file_layer)
            .with(log_buffer_layer)
            .init();

        let logger = Self {
            filter_handle: Box::new(reload_handle),
            preserved_directives: preserved,
        };
        Ok((logger, log_buffer))
    }

    pub fn initialize_cli() -> Result<(), Error> {
        let stdout_layer = fmt_layer()
            .without_time()
            .with_level(false)
            .with_target(false)
            .with_file(false)
            .with_line_number(false)
            .with_thread_ids(false)
            .with_ansi(false)
            .with_writer(io::stdout)
            .with_filter(LevelFilter::INFO);

        let stderr_layer = fmt_layer()
            .without_time()
            .with_level(false)
            .with_target(false)
            .with_writer(io::stderr)
            .with_filter(filter::filter_fn(|m| m.level() <= &Level::WARN));

        tracing_subscriber::registry()
            .with(stdout_layer)
            .with(stderr_layer)
            .init();
        Ok(())
    }

    fn apply_directives(mut filter: EnvFilter, directives: &[String]) -> EnvFilter {
        for d in directives {
            if let Ok(parsed) = d.parse::<Directive>() {
                filter = filter.add_directive(parsed);
            }
        }
        filter
    }

    pub fn current_level(&self) -> String {
        extract_main_level(&self.filter_handle.current_filter())
    }

    pub fn set_level(&self, level: &str) -> Result<String, String> {
        let parsed_level: Level = level.parse().map_err(|_| {
            format!(
                "Invalid log level '{}'. Valid levels: trace, debug, info, warn, error",
                level
            )
        })?;

        let filter = EnvFilter::new(parsed_level.to_string());
        let filter = Self::apply_directives(filter, &self.preserved_directives);
        self.filter_handle.reload_filter(filter)?;

        Ok(parsed_level.to_string().to_lowercase())
    }
}

impl<L> FilterControl for reload::Handle<EnvFilter, L> {
    fn reload_filter(&self, filter: EnvFilter) -> Result<(), String> {
        self.reload(filter).map_err(|e| e.to_string())
    }

    fn current_filter(&self) -> String {
        self.with_current(|f| f.to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }
}

fn extract_main_level(raw: &str) -> String {
    raw.split(',')
        .map(str::trim)
        .find(|d| !d.is_empty() && !d.contains('='))
        .unwrap_or(raw)
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_per_target_directives() {
        assert_eq!(extract_main_level("maxminddb=warn,debug"), "debug");
        assert_eq!(extract_main_level("info,maxminddb=warn"), "info");
        assert_eq!(extract_main_level("DEBUG"), "debug");
    }

    #[test]
    fn falls_back_when_no_bare_level() {
        assert_eq!(extract_main_level("maxminddb=warn"), "maxminddb=warn");
    }
}
