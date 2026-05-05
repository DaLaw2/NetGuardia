use std::collections::VecDeque;
use std::fmt::{Arguments, Debug, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    pub id: u64,
    pub ts_ms: u64,
    pub level: &'static str,
    pub target: String,
    pub message: String,
}

/// `Mutex<VecDeque>` rather than a lock-free ring because `snapshot()` needs
/// an internally-consistent view: it filters by `since_id` + severity, then
/// clones matching entries. A seqlock / `ArrayQueue`-based design would
/// either require a retry loop that tears across concurrent writes or would
/// lose the snapshot API entirely (`ArrayQueue` only supports push/pop, not
/// iteration). The write path holds the lock for one `pop_front` +
/// `push_back` — micros under load — which the tracing subscriber can
/// comfortably pay on the event-emit hot path. Revisit if log volume grows
/// past ~10k events/sec per writer, not before.
struct LogRingBuffer {
    entries: Mutex<VecDeque<LogEntry>>,
    capacity: usize,
    max_message_bytes: usize,
    next_id: AtomicU64,
}

impl LogRingBuffer {
    fn new(capacity: usize, max_message_bytes: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            entries: Mutex::new(VecDeque::with_capacity(cap)),
            capacity: cap,
            max_message_bytes: max_message_bytes.max(64),
            next_id: AtomicU64::new(1),
        }
    }

    fn push(&self, entry: LogEntry) {
        let mut guard = self.entries.lock();
        if guard.len() >= self.capacity {
            guard.pop_front();
        }
        guard.push_back(entry);
    }

    fn snapshot(&self, since_id: u64, min_severity: u8, limit: usize) -> Snapshot {
        let guard = self.entries.lock();
        let total = guard.len();
        let latest_id = guard.back().map(|e| e.id).unwrap_or(0);
        let entries: Vec<LogEntry> = guard
            .iter()
            .filter(|e| e.id > since_id && level_severity(e.level) <= min_severity)
            .take(limit)
            .cloned()
            .collect();
        Snapshot {
            entries,
            latest_id,
            total,
        }
    }
}

pub struct Snapshot {
    pub entries: Vec<LogEntry>,
    pub latest_id: u64,
    pub total: usize,
}

/// Handle for reading from the log ring buffer.
pub struct LogBuffer {
    inner: Arc<LogRingBuffer>,
}

impl LogBuffer {
    pub fn snapshot(&self, since_id: u64, min_severity: u8, limit: usize) -> Snapshot {
        self.inner.snapshot(since_id, min_severity, limit)
    }
}

/// Map a level string to severity rank. Unknown strings sort as TRACE so
/// they are only visible when the caller asks for everything.
pub fn level_severity(level: &str) -> u8 {
    match level {
        "ERROR" => 1,
        "WARN" => 2,
        "INFO" => 3,
        "DEBUG" => 4,
        _ => 5,
    }
}

fn level_str(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN",
        Level::INFO => "INFO",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// [`Layer`] that appends each formatted event into the in-memory ring
/// buffer so the UI can tail logs without round-tripping the filesystem.
pub struct LogBufferLayer {
    inner: Arc<LogRingBuffer>,
}

impl LogBufferLayer {
    pub fn new(capacity: usize, max_message_bytes: usize) -> (Self, LogBuffer) {
        let inner = Arc::new(LogRingBuffer::new(capacity, max_message_bytes));
        let handle = LogBuffer { inner: inner.clone() };
        (Self { inner }, handle)
    }
}

impl<S: Subscriber> Layer<S> for LogBufferLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let mut message = visitor.into_message();
        if message.len() > self.inner.max_message_bytes {
            message.truncate(self.inner.max_message_bytes);
            message.push_str("…[truncated]");
        }
        let entry = LogEntry {
            id: self.inner.next_id.fetch_add(1, Ordering::Relaxed),
            ts_ms: now_unix_ms(),
            level: level_str(metadata.level()),
            target: metadata.target().to_string(),
            message,
        };
        self.inner.push(entry);
    }
}

/// Collects `message` plus remaining fields as `key=value` pairs. `tracing`
/// macros emit the format-args body under the `message` field; structured
/// fields come through [`Visit::record_*`] for the respective primitive.
#[derive(Default)]
struct MessageVisitor {
    message: String,
    extra: String,
}

impl MessageVisitor {
    fn into_message(mut self) -> String {
        if self.extra.is_empty() {
            self.message
        } else if self.message.is_empty() {
            self.extra
        } else {
            self.message.push(' ');
            self.message.push_str(&self.extra);
            self.message
        }
    }

    fn push_extra(&mut self, name: &str, value: Arguments<'_>) {
        if !self.extra.is_empty() {
            self.extra.push(' ');
        }
        let _ = write!(self.extra, "{}={}", name, value);
    }
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{:?}", value);
        } else {
            self.push_extra(field.name(), format_args!("{:?}", value));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            self.push_extra(field.name(), format_args!("{}", value));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push_extra(field.name(), format_args!("{}", value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push_extra(field.name(), format_args!("{}", value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.push_extra(field.name(), format_args!("{}", value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push_extra(field.name(), format_args!("{}", value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(id: u64, level: &'static str, message: &str) -> LogEntry {
        LogEntry {
            id,
            ts_ms: 0,
            level,
            target: "test".into(),
            message: message.into(),
        }
    }

    #[test]
    fn severity_ordering() {
        assert!(level_severity("ERROR") < level_severity("WARN"));
        assert!(level_severity("WARN") < level_severity("INFO"));
        assert!(level_severity("INFO") < level_severity("DEBUG"));
        assert!(level_severity("DEBUG") < level_severity("TRACE"));
        assert_eq!(level_severity("unknown"), 5);
    }

    #[test]
    fn ring_buffer_drops_oldest_at_capacity() {
        let buf = LogRingBuffer::new(3, 8192);
        for id in 1..=5 {
            buf.push(make_entry(id, "INFO", "m"));
        }
        let snap = buf.snapshot(0, level_severity("TRACE"), 100);
        let ids: Vec<u64> = snap.entries.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![3, 4, 5]);
        assert_eq!(snap.latest_id, 5);
        assert_eq!(snap.total, 3);
    }

    #[test]
    fn snapshot_filters_since_id_and_severity() {
        let buf = LogRingBuffer::new(16, 8192);
        buf.push(make_entry(1, "INFO", "first"));
        buf.push(make_entry(2, "DEBUG", "noisy"));
        buf.push(make_entry(3, "ERROR", "boom"));

        let snap = buf.snapshot(1, level_severity("INFO"), 100);
        let levels: Vec<&str> = snap.entries.iter().map(|e| e.level).collect();
        assert_eq!(levels, vec!["ERROR"]);
        assert_eq!(snap.latest_id, 3);
    }

    #[test]
    fn snapshot_respects_limit() {
        let buf = LogRingBuffer::new(16, 8192);
        for id in 1..=10 {
            buf.push(make_entry(id, "INFO", "m"));
        }
        let snap = buf.snapshot(0, level_severity("TRACE"), 4);
        assert_eq!(snap.entries.len(), 4);
        assert_eq!(snap.latest_id, 10);
    }

    #[test]
    fn visitor_concatenates_message_and_structured_fields() {
        let mut v = MessageVisitor::default();
        v.push_extra("count", format_args!("{}", 42u64));
        v.push_extra("ok", format_args!("{}", true));
        v.message.push_str("hello");
        let out = v.into_message();
        assert!(out.contains("hello"));
        assert!(out.contains("count=42"));
        assert!(out.contains("ok=true"));
    }
}
