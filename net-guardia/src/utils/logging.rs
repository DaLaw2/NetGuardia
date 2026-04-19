use std::env;
use std::fs;
use std::sync::OnceLock;

use tracing::Level;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::layer as fmt_layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;

use crate::core::observability::log_buffer::LogBufferLayer;
use crate::model::error::Error;
use crate::model::error::io::IOError;

/// Type-erased reload handle stored as a trait object.
/// We erase the complex layered type by boxing the modify closure.
static FILTER_HANDLE: OnceLock<Box<dyn FilterControl>> = OnceLock::new();

/// Trait to erase the complex generic type of reload::Handle.
trait FilterControl: Send + Sync {
    fn reload_filter(&self, filter: EnvFilter) -> Result<(), String>;
    fn current_filter(&self) -> String;
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

pub struct Logging;

impl Logging {
    pub fn initialize() -> Result<(), Error> {
        let log_directory = "logs";
        fs::create_dir_all(log_directory).map_err(|err| IOError::CreateDirectoryFailed(log_directory, err))?;

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

        let level = env::var("RUST_LOG")
            .ok()
            .and_then(|s| s.parse::<Level>().ok())
            .unwrap_or(if cfg!(debug_assertions) {
                Level::DEBUG
            } else {
                Level::INFO
            });

        let filter = EnvFilter::from_default_env()
            .add_directive(level.into())
            // SAFETY: "maxminddb=warn" is a valid tracing directive literal
            .add_directive("maxminddb=warn".parse().unwrap_or_else(|_| unreachable!()));

        let (filter_layer, reload_handle) = reload::Layer::new(filter);

        tracing_subscriber::registry()
            .with(filter_layer)
            .with(stdout_layer)
            .with(file_layer)
            .with(LogBufferLayer::new())
            .init();

        // Store type-erased handle for runtime log level changes
        let _ = FILTER_HANDLE.set(Box::new(reload_handle));

        Ok(())
    }

    /// Change the global log level at runtime.
    pub fn set_level(level: &str) -> Result<String, String> {
        let handle = FILTER_HANDLE.get().ok_or("Logging not initialized")?;

        let parsed_level: Level = level.parse().map_err(|_| {
            format!(
                "Invalid log level '{}'. Valid levels: trace, debug, info, warn, error",
                level
            )
        })?;

        let new_filter = EnvFilter::new(parsed_level.to_string())
            .add_directive("maxminddb=warn".parse().unwrap_or_else(|_| unreachable!()));

        handle.reload_filter(new_filter)?;

        Ok(parsed_level.to_string().to_lowercase())
    }

    /// Get the current global log level as a bare lowercase directive —
    /// e.g. `"info"`, not the full `"maxminddb=warn,info"` EnvFilter string.
    /// Per-target overrides (like `maxminddb=warn`) are internal tuning and
    /// would break the frontend `<select>` that only knows five options.
    pub fn current_level() -> String {
        FILTER_HANDLE
            .get()
            .map(|h| extract_main_level(&h.current_filter()))
            .unwrap_or_else(|| "unknown".to_string())
    }
}

/// Strip per-target directives out of an EnvFilter string and return the
/// bare level directive in lowercase. Falls back to the raw string if no
/// bare directive is present.
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
        // Only per-target directives → return lowercased raw so the UI at
        // least shows *something* rather than silently misleading.
        assert_eq!(extract_main_level("maxminddb=warn"), "maxminddb=warn");
    }
}
