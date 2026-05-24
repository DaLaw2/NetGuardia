use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    pub id: u64,
    pub ts_ms: u64,
    pub level: &'static str,
    pub target: String,
    pub message: String,
}

pub struct LogSnapshot {
    pub entries: Vec<LogEntry>,
    pub latest_id: u64,
    pub total: usize,
}

pub trait LiveLogQuery: Send + Sync {
    fn snapshot(&self, since_id: u64, min_severity: u8, limit: usize) -> LogSnapshot;
}
