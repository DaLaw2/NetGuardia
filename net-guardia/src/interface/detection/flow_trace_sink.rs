use std::path::Path;

pub trait FlowTraceSink: Send + Sync {
    fn log_row(&self, csv_line: String);
    fn directory(&self) -> &Path;
}
