use tracing_subscriber::EnvFilter;

pub trait FilterControl: Send + Sync {
    fn reload_filter(&self, filter: EnvFilter) -> Result<(), String>;
    fn current_filter(&self) -> String;
}
