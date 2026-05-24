use std::fmt::{Arguments, Debug, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crossbeam::queue::ArrayQueue;
use parking_lot::Mutex;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use crate::common::utils::log_level::level_severity;
use crate::interface::system::live_logs::{LiveLogQuery, LogEntry, LogSnapshot};

struct LogRingBuffer {
    queue: ArrayQueue<LogEntry>,
    snapshot_lock: Mutex<()>,
    max_message_bytes: usize,
    next_id: AtomicU64,
    latest_id: AtomicU64,
}

impl LogRingBuffer {
    fn new(capacity: usize, max_message_bytes: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            queue: ArrayQueue::new(cap),
            snapshot_lock: Mutex::new(()),
            max_message_bytes: max_message_bytes.max(64),
            next_id: AtomicU64::new(1),
            latest_id: AtomicU64::new(0),
        }
    }

    fn push(&self, entry: LogEntry) {
        self.latest_id.store(entry.id, Ordering::Release);
        match self.queue.push(entry) {
            Ok(()) => {}
            Err(entry) => {
                let _ = self.queue.pop();
                let _ = self.queue.push(entry);
            }
        }
    }

    fn snapshot(&self, since_id: u64, min_severity: u8, limit: usize) -> LogSnapshot {
        let _guard = self.snapshot_lock.lock();
        let cap = self.queue.capacity();
        let mut entries = Vec::with_capacity(cap.min(limit));
        let mut drained = Vec::with_capacity(cap);

        while let Some(entry) = self.queue.pop() {
            drained.push(entry);
        }

        let total = drained.len();
        let latest_id = drained.last().map(|e| e.id).unwrap_or(0);

        for entry in &drained {
            if entries.len() >= limit {
                break;
            }
            if entry.id > since_id && level_severity(entry.level) <= min_severity {
                entries.push(entry.clone());
            }
        }

        for entry in drained {
            let _ = self.queue.push(entry);
        }

        LogSnapshot {
            entries,
            latest_id,
            total,
        }
    }
}

pub struct LogBuffer {
    inner: Arc<LogRingBuffer>,
}

impl LiveLogQuery for LogBuffer {
    fn snapshot(&self, since_id: u64, min_severity: u8, limit: usize) -> LogSnapshot {
        self.inner.snapshot(since_id, min_severity, limit)
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
            truncate_message(&mut message, self.inner.max_message_bytes);
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

fn truncate_message(message: &mut String, max_message_bytes: usize) {
    if message.len() <= max_message_bytes {
        return;
    }

    const TRUNCATION_SUFFIX: &str = "...[truncated]";

    if max_message_bytes <= TRUNCATION_SUFFIX.len() {
        message.truncate(0);
        message.push_str(&TRUNCATION_SUFFIX[..max_message_bytes]);
        return;
    }

    let mut truncate_at = max_message_bytes - TRUNCATION_SUFFIX.len();
    while truncate_at > 0 && !message.is_char_boundary(truncate_at) {
        truncate_at -= 1;
    }
    message.truncate(truncate_at);
    message.push_str(TRUNCATION_SUFFIX);
}

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

    #[test]
    fn truncate_message_preserves_utf8_boundaries() {
        let mut message = "abcdef測試0123456789".to_string();

        truncate_message(&mut message, 20);

        assert_eq!(message, "abcdef...[truncated]");
        assert!(message.len() <= 20);
    }

    #[test]
    fn truncate_message_keeps_suffix_within_small_limit() {
        let mut message = "abcdefghi".to_string();

        truncate_message(&mut message, 7);

        assert_eq!(message, "...[tru");
        assert_eq!(message.len(), 7);
    }
}
