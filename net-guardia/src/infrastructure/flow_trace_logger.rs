use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam::channel::{Receiver, Sender, TrySendError, bounded};
use macros::log;
use tokio::sync::broadcast;

use crate::common::log::audit::AuditLog;
use crate::domain::common::event::AuditEvent;
use crate::domain::detection::error::MLError;
use crate::domain::detection::log::MLLog;
use crate::interface::detection::flow_trace_sink::FlowTraceSink;
use crate::interface::detection::flow_trace_store::{FlowTraceStore, FlowTraceWriter};

pub const DEFAULT_MAX_FILE_BYTES: u64 = 500 * 1024 * 1024;
pub const DEFAULT_MAX_FILE_AGE: Duration = Duration::from_secs(3600);
pub const DEFAULT_TOTAL_BUDGET_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const AUDIT_ACTOR_SYSTEM: &str = "system";
const AUDIT_ACTION_FLOW_TRACE_STOPPED: &str = "flow_trace_stopped";

#[derive(Debug, Clone)]
pub struct RotationPolicy {
    pub max_file_bytes: u64,
    pub max_file_age: Duration,
    pub total_budget_bytes: u64,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_file_age: DEFAULT_MAX_FILE_AGE,
            total_budget_bytes: DEFAULT_TOTAL_BUDGET_BYTES,
        }
    }
}

pub struct TrafficLogger {
    sender: Sender<String>,
    directory: Arc<PathBuf>,
}

impl TrafficLogger {
    pub fn new(
        base_path: &Path,
        header: Vec<String>,
        policy: RotationPolicy,
        channel_capacity: usize,
        audit_tx: Option<broadcast::Sender<AuditEvent>>,
        store: Arc<dyn FlowTraceStore>,
    ) -> Result<Self, io::Error> {
        let directory = base_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        store.ensure_directory(&directory)?;

        let (sender, receiver) = bounded::<String>(channel_capacity.max(1));

        let writer_dir = directory.clone();
        let writer_header = header;
        let writer_policy = policy;
        let writer_store = store.clone();
        thread::Builder::new()
            .name("traffic-logger".to_string())
            .spawn(move || {
                writer_loop(
                    receiver,
                    writer_dir,
                    writer_header,
                    writer_policy,
                    audit_tx,
                    writer_store,
                );
            })?;

        Ok(Self {
            sender,
            directory: Arc::new(directory),
        })
    }
}

impl FlowTraceSink for TrafficLogger {
    fn log_row(&self, csv_line: String) {
        match self.sender.try_send(csv_line) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                log!(MLLog::TrafficLogChannelBackpressure);
            }
            Err(TrySendError::Disconnected(_)) => {
                log!(MLLog::TrafficLogChannelDisconnected);
            }
        }
    }

    fn directory(&self) -> &Path {
        self.directory.as_ref()
    }
}

fn writer_loop(
    receiver: Receiver<String>,
    directory: PathBuf,
    header: Vec<String>,
    policy: RotationPolicy,
    audit_tx: Option<broadcast::Sender<AuditEvent>>,
    store: Arc<dyn FlowTraceStore>,
) {
    let mut active = match open_active_file(store.as_ref(), &directory, &header) {
        Ok(a) => a,
        Err(e) => {
            let reason = e.to_string();
            log!(MLLog::FlowTraceStopped(reason.clone()));
            emit_flow_trace_stop_audit(audit_tx.as_ref(), &reason, &directory);
            return;
        }
    };

    while let Ok(csv_line) = receiver.recv() {
        if active.bytes_written >= policy.max_file_bytes || active.opened_at.elapsed() >= policy.max_file_age {
            if let Err(e) = active.writer.flush() {
                log!(MLLog::TrafficLogWriteError(e.to_string()));
            }
            drop(active.writer);
            if let Err(e) = store.enforce_retention_budget(&directory, policy.total_budget_bytes) {
                let reason = format!("FIFO sweep failed: {e}");
                log!(MLLog::FlowTraceStopped(reason.clone()));
                emit_flow_trace_stop_audit(audit_tx.as_ref(), &reason, &directory);
                return;
            }
            active = match open_active_file(store.as_ref(), &directory, &header) {
                Ok(a) => a,
                Err(e) => {
                    let reason = format!("rotate failed: {e}");
                    log!(MLLog::FlowTraceStopped(reason.clone()));
                    emit_flow_trace_stop_audit(audit_tx.as_ref(), &reason, &directory);
                    return;
                }
            };
        }

        if let Err(e) = active.writer.write_all(csv_line.as_bytes()) {
            log!(MLLog::TrafficLogWriteError(e.to_string()));
            continue;
        }
        if let Err(e) = active.writer.write_all(b"\n") {
            log!(MLLog::TrafficLogWriteError(e.to_string()));
            continue;
        }
        active.bytes_written = active.bytes_written.saturating_add(csv_line.len() as u64 + 1);
    }

    if let Err(e) = active.writer.flush() {
        log!(MLError::TrafficLogFlushFailed(e));
    }
}

fn emit_flow_trace_stop_audit(audit_tx: Option<&broadcast::Sender<AuditEvent>>, reason: &str, directory: &Path) {
    let Some(tx) = audit_tx else {
        return;
    };
    let detail = serde_json::json!({
        "reason": reason,
        "directory": directory.display().to_string(),
    })
    .to_string();
    let audit = AuditEvent {
        actor: AUDIT_ACTOR_SYSTEM.to_string(),
        action: AUDIT_ACTION_FLOW_TRACE_STOPPED.to_string(),
        detail,
    };
    if let Err(err) = tx.send(audit) {
        let event = err.0;
        log!(AuditLog::AuditPublishFailed(
            "no active audit receivers",
            event.actor,
            event.action
        ));
    }
}

struct ActiveFile {
    writer: BufWriter<FlowTraceWriter>,
    opened_at: Instant,
    bytes_written: u64,
}

fn open_active_file(store: &dyn FlowTraceStore, directory: &Path, header: &[String]) -> io::Result<ActiveFile> {
    let opened = store.create_rotated_writer(directory, header)?;
    Ok(ActiveFile {
        writer: BufWriter::new(opened.writer),
        opened_at: Instant::now(),
        bytes_written: opened.bytes_written,
    })
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;

    use uuid::Uuid;

    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("nguardia-flow-trace-{tag}-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn stop_audit_reaches_subscriber_when_sender_provided() {
        let (tx, mut rx) = broadcast::channel::<AuditEvent>(256);

        let dir = scratch_dir("audit-emit");
        emit_flow_trace_stop_audit(Some(&tx), "FIFO sweep failed: perm denied", &dir);

        let event = rx.recv().await.expect("audit event must be delivered");
        assert_eq!(event.actor, "system");
        assert_eq!(event.action, "flow_trace_stopped");
        let parsed: serde_json::Value = serde_json::from_str(&event.detail).unwrap();
        assert_eq!(parsed["reason"], "FIFO sweep failed: perm denied");
        assert_eq!(parsed["directory"], dir.display().to_string());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stop_audit_noop_when_sender_absent() {
        emit_flow_trace_stop_audit(None, "any reason", Path::new("/tmp/anywhere"));
    }
}
