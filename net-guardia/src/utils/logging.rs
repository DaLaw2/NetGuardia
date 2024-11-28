use tokio::fs;
use tracing::Level;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub struct Logging {}

impl Logging {
    pub async fn initialize() -> anyhow::Result<()> {
        let log_directory = "logs";
        fs::create_dir_all(log_directory).await?;

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

        tracing_subscriber::registry()
            .with(stdout_layer)
            .with(file_layer)
            .with(EnvFilter::from_default_env().add_directive(Level::DEBUG.into()))
            .init();

        Ok(())
    }
}
