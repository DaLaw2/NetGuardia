//! Flow Trace recording — rotating CSV writer for per-flow feature
//! vectors. Consumers drop rows through a bounded channel; a dedicated
//! writer thread manages the currently-open file, rotates on size or
//! age, and enforces a FIFO total-bytes budget so a long-running
//! recording session can't eat the disk.
//!
//! On FIFO failure (permissions, I/O error) the writer shuts down
//! cleanly, leaves inference untouched, logs through `MLLog`, and
//! (when a `CommunicationManager` is wired in) also publishes a WORM
//! `AuditEvent` so the chain records an auditor-visible reason the
//! recording stopped, not just a tracing line that may be lost.
//! Callers see the channel disconnect and stop sending rows.

use std::fs as std_fs;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossbeam::channel::{Receiver, Sender, TrySendError, bounded};
use macros::log;

use crate::infrastructure::communication_manager::CommunicationManager;
use crate::model::error::ml::MLError;
use crate::model::event::AuditEvent;
use crate::model::log::ml::MLLog;

/// Default per-file size cap. A single CSV file won't grow past this
/// before the writer rolls to a fresh one.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 500 * 1024 * 1024;

/// Default per-file age cap. Forces a roll even if the size cap
/// hasn't been hit so analysts have bounded-age shards to download.
pub const DEFAULT_MAX_FILE_AGE: Duration = Duration::from_secs(3600);

/// Default retained-bytes budget across every `flow-trace-*.csv` in
/// the directory. When the total exceeds this, the writer FIFO-deletes
/// the oldest files to bring the sum back under the cap.
pub const DEFAULT_TOTAL_BUDGET_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Lossy-drop channel capacity. Inference throughput is spiky; if the
/// writer falls behind, callers get a `TrySendError::Full` back rather
/// than blocking the hot path. The lost rows are observable in logs.
const CHANNEL_CAPACITY: usize = 65_536;

/// Prefix literal baked into every rotated file's name so the HTTP
/// file-list handler can recognize ours and skip unrelated files.
pub const FLOW_TRACE_FILE_MARKER: &str = "flow-trace-";
/// Suffix literal appended to every rotated file.
pub const FLOW_TRACE_FILE_EXT: &str = ".csv";

/// Actor recorded on the WORM `flow_trace_stopped` audit entry. Stable
/// wire string — auditors filter on it to separate system-internal
/// recording stoppages from administrator-initiated actions. Matches
/// the "system" value the drift-detector audit path already uses.
const AUDIT_ACTOR_SYSTEM: &str = "system";
/// Action string on the WORM audit entry emitted when Flow Trace
/// recording goes dormant for any of the three writer-thread stop
/// reasons. Stable across releases.
const AUDIT_ACTION_FLOW_TRACE_STOPPED: &str = "flow_trace_stopped";

/// Rotation thresholds. Immutable after logger construction — change
/// requires a full logger restart through `AppServices`.
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
    sender: Sender<Vec<String>>,
    directory: Arc<PathBuf>,
}

impl TrafficLogger {
    /// Build a rotating writer rooted at `base_path`'s parent. Any
    /// existing `flow-trace-*.csv` in that directory participates in
    /// the FIFO budget. `comm` is optional so tests (and paths where
    /// the bus isn't wired yet) can exercise the rotation logic without
    /// the event-bus dependency; production code always passes `Some`.
    pub fn new(
        base_path: &Path,
        header: Vec<String>,
        policy: RotationPolicy,
        comm: Option<Arc<CommunicationManager>>,
    ) -> Result<Self, io::Error> {
        let directory = base_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        std_fs::create_dir_all(&directory)?;

        let (sender, receiver) = bounded::<Vec<String>>(CHANNEL_CAPACITY);

        let writer_dir = directory.clone();
        let writer_header = header;
        let writer_policy = policy;
        thread::Builder::new()
            .name("traffic-logger".to_string())
            .spawn(move || {
                writer_loop(receiver, writer_dir, writer_header, writer_policy, comm);
            })?;

        Ok(Self {
            sender,
            directory: Arc::new(directory),
        })
    }

    pub fn log_row(&self, record: Vec<String>) {
        match self.sender.try_send(record) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // Writer thread is behind; dropping is preferable to
                // stalling inference. The counter is bumped inside the
                // logger so the dashboard can surface slow-disk pressure.
                log!(MLLog::TrafficLogChannelBackpressure);
            }
            Err(TrySendError::Disconnected(_)) => {
                log!(MLLog::TrafficLogChannelDisconnected);
            }
        }
    }

    /// Absolute path to the directory holding rotated CSV files. The
    /// HTTP file-list / download handlers read this to resolve
    /// user-supplied filenames.
    pub fn directory(&self) -> &Path {
        self.directory.as_ref()
    }
}

/// Lightweight descriptor for a single rotated file on disk. Used by
/// `list_flow_trace_files` and by the FIFO sweep.
#[derive(Debug, Clone)]
pub struct FlowTraceFile {
    pub name: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub modified_unix_secs: u64,
}

/// Scan `directory` for `flow-trace-*.csv` entries, sorted oldest-first
/// by numeric suffix (so FIFO deletion and the file-list endpoint both
/// use the same deterministic order).
pub fn list_flow_trace_files(directory: &Path) -> io::Result<Vec<FlowTraceFile>> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for dirent in std_fs::read_dir(directory)? {
        let dirent = dirent?;
        let path = dirent.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.starts_with(FLOW_TRACE_FILE_MARKER) || !name.ends_with(FLOW_TRACE_FILE_EXT) {
            continue;
        }
        let metadata = dirent.metadata()?;
        let size_bytes = metadata.len();
        let modified_unix_secs = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        entries.push(FlowTraceFile {
            name: name.to_string(),
            path: path.clone(),
            size_bytes,
            modified_unix_secs,
        });
    }
    entries.sort_by_key(|e| parse_timestamp_suffix(&e.name).unwrap_or(u64::MAX));
    Ok(entries)
}

/// Parse the numeric timestamp from `flow-trace-<ns>.csv`. Unknown
/// suffixes return `None` so the caller can skip them from the
/// oldest-first ordering.
fn parse_timestamp_suffix(name: &str) -> Option<u64> {
    let without_prefix = name.strip_prefix(FLOW_TRACE_FILE_MARKER)?;
    let without_ext = without_prefix.strip_suffix(FLOW_TRACE_FILE_EXT)?;
    without_ext.parse::<u64>().ok()
}

fn writer_loop(
    receiver: Receiver<Vec<String>>,
    directory: PathBuf,
    header: Vec<String>,
    policy: RotationPolicy,
    comm: Option<Arc<CommunicationManager>>,
) {
    let mut active = match open_new_file(&directory, &header) {
        Ok(a) => a,
        Err(e) => {
            let reason = e.to_string();
            log!(MLLog::FlowTraceStopped(reason.clone()));
            emit_flow_trace_stop_audit(comm.as_ref(), &reason, &directory);
            return;
        }
    };

    while let Ok(record) = receiver.recv() {
        if active.bytes_written >= policy.max_file_bytes || active.opened_at.elapsed() >= policy.max_file_age {
            // Close current, enforce budget, open a fresh file.
            if let Err(e) = active.writer.flush() {
                log!(MLLog::TrafficLogWriteError(e.to_string()));
            }
            drop(active.writer);
            if let Err(e) = enforce_fifo_budget(&directory, policy.total_budget_bytes) {
                // FIFO failure is the documented "stop Flow Trace, keep
                // inference running" path. Drop the channel so callers
                // see the disconnect and stop trying.
                let reason = format!("FIFO sweep failed: {e}");
                log!(MLLog::FlowTraceStopped(reason.clone()));
                emit_flow_trace_stop_audit(comm.as_ref(), &reason, &directory);
                return;
            }
            active = match open_new_file(&directory, &header) {
                Ok(a) => a,
                Err(e) => {
                    let reason = format!("rotate failed: {e}");
                    log!(MLLog::FlowTraceStopped(reason.clone()));
                    emit_flow_trace_stop_audit(comm.as_ref(), &reason, &directory);
                    return;
                }
            };
        }

        let line = format!("{}\n", record.join(","));
        if let Err(e) = active.writer.write_all(line.as_bytes()) {
            log!(MLLog::TrafficLogWriteError(e.to_string()));
            continue;
        }
        active.bytes_written = active.bytes_written.saturating_add(line.len() as u64);
    }

    if let Err(e) = active.writer.flush() {
        log!(MLError::TrafficLogFlushFailed(e));
    }
}

/// Publish a WORM `flow_trace_stopped` audit entry so an auditor can
/// later see why Flow Trace recording went dormant without grepping
/// process logs. A `None` bus (tests, or pre-wiring paths) is a
/// deliberate no-op — the sibling `MLLog::FlowTraceStopped` tracing
/// line still fires in both cases.
///
/// Extracted as a free function so tests can cover the emit path
/// without driving a full writer-loop + failing-disk fixture.
fn emit_flow_trace_stop_audit(comm: Option<&Arc<CommunicationManager>>, reason: &str, directory: &Path) {
    let Some(c) = comm else {
        return;
    };
    let detail = serde_json::json!({
        "reason": reason,
        "directory": directory.display().to_string(),
    })
    .to_string();
    let _ = c.publish_event_sync(AuditEvent {
        actor: AUDIT_ACTOR_SYSTEM.to_string(),
        action: AUDIT_ACTION_FLOW_TRACE_STOPPED.to_string(),
        detail,
    });
}

struct ActiveFile {
    writer: BufWriter<File>,
    opened_at: Instant,
    bytes_written: u64,
}

fn open_new_file(directory: &Path, header: &[String]) -> io::Result<ActiveFile> {
    let ts_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let filename = format!("{FLOW_TRACE_FILE_MARKER}{ts_ns:020}{FLOW_TRACE_FILE_EXT}");
    let path = directory.join(filename);
    let file = OpenOptions::new().create(true).write(true).truncate(true).open(&path)?;
    let mut writer = BufWriter::new(file);
    let header_line = format!("{}\n", header.join(","));
    writer.write_all(header_line.as_bytes())?;
    writer.flush()?;
    Ok(ActiveFile {
        writer,
        opened_at: Instant::now(),
        bytes_written: header_line.len() as u64,
    })
}

/// Bring the sum of all `flow-trace-*.csv` byte counts back under
/// `budget` by deleting oldest-first. Exposed to tests; the writer
/// thread calls this after each rotation.
pub fn enforce_fifo_budget(directory: &Path, budget: u64) -> io::Result<()> {
    let files = list_flow_trace_files(directory)?;
    let total: u64 = files.iter().map(|f| f.size_bytes).sum();
    if total <= budget {
        return Ok(());
    }
    let mut remaining = total;
    for file in files {
        if remaining <= budget {
            break;
        }
        std_fs::remove_file(&file.path)?;
        remaining = remaining.saturating_sub(file.size_bytes);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::io::Write as _;

    use uuid::Uuid;

    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("nguardia-flow-trace-{tag}-{}", Uuid::new_v4()));
        std_fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_fake_trace(dir: &Path, ts_ns: u64, bytes: usize) -> PathBuf {
        let path = dir.join(format!("{FLOW_TRACE_FILE_MARKER}{ts_ns:020}{FLOW_TRACE_FILE_EXT}"));
        let mut f = File::create(&path).unwrap();
        f.write_all(&vec![b'a'; bytes]).unwrap();
        path
    }

    #[test]
    fn parse_timestamp_suffix_accepts_padded_ns() {
        assert_eq!(parse_timestamp_suffix("flow-trace-00000000000000000042.csv"), Some(42));
    }

    #[test]
    fn parse_timestamp_suffix_rejects_unrelated_names() {
        assert!(parse_timestamp_suffix("random.csv").is_none());
        assert!(parse_timestamp_suffix("flow-trace-hello.csv").is_none());
        assert!(parse_timestamp_suffix("flow-trace-42.txt").is_none());
    }

    #[test]
    fn list_returns_files_sorted_oldest_first() {
        let dir = scratch_dir("list-order");
        write_fake_trace(&dir, 200, 10);
        write_fake_trace(&dir, 100, 10);
        write_fake_trace(&dir, 300, 10);
        let files = list_flow_trace_files(&dir).unwrap();
        let suffixes: Vec<_> = files.iter().map(|f| parse_timestamp_suffix(&f.name).unwrap()).collect();
        assert_eq!(suffixes, vec![100, 200, 300]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn list_skips_non_flow_trace_files() {
        let dir = scratch_dir("skip");
        write_fake_trace(&dir, 42, 10);
        std::fs::write(dir.join("not-ours.csv"), b"foo").unwrap();
        std::fs::write(dir.join("flow-trace-bad-suffix.txt"), b"foo").unwrap();
        let files = list_flow_trace_files(&dir).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(parse_timestamp_suffix(&files[0].name), Some(42));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn enforce_budget_removes_oldest_until_under_cap() {
        let dir = scratch_dir("budget");
        write_fake_trace(&dir, 100, 1024);
        write_fake_trace(&dir, 200, 1024);
        write_fake_trace(&dir, 300, 1024);
        // Budget 1500 bytes against 3072 total -> must drop oldest two.
        enforce_fifo_budget(&dir, 1500).unwrap();
        let remaining = list_flow_trace_files(&dir).unwrap();
        let suffixes: Vec<_> = remaining
            .iter()
            .map(|f| parse_timestamp_suffix(&f.name).unwrap())
            .collect();
        assert_eq!(suffixes, vec![300]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn enforce_budget_is_noop_when_under_cap() {
        let dir = scratch_dir("budget-noop");
        write_fake_trace(&dir, 100, 512);
        write_fake_trace(&dir, 200, 512);
        enforce_fifo_budget(&dir, 8192).unwrap();
        assert_eq!(list_flow_trace_files(&dir).unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn list_on_missing_dir_returns_empty() {
        let missing = PathBuf::from("/nonexistent/flow-trace/dir");
        assert!(list_flow_trace_files(&missing).unwrap().is_empty());
    }

    #[tokio::test]
    async fn stop_audit_reaches_subscriber_when_comm_provided() {
        let comm = Arc::new(CommunicationManager::new());
        comm.register_event_type::<AuditEvent>();
        let mut rx = comm.subscribe_event::<AuditEvent>().unwrap();

        let dir = scratch_dir("audit-emit");
        emit_flow_trace_stop_audit(Some(&comm), "FIFO sweep failed: perm denied", &dir);

        let event = rx.recv().await.expect("audit event must be delivered");
        assert_eq!(event.actor, "system");
        assert_eq!(event.action, "flow_trace_stopped");
        let parsed: serde_json::Value = serde_json::from_str(&event.detail).unwrap();
        assert_eq!(parsed["reason"], "FIFO sweep failed: perm denied");
        assert_eq!(parsed["directory"], dir.display().to_string());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stop_audit_noop_when_comm_absent() {
        // Passing None is the explicit test-mode path — must not panic.
        emit_flow_trace_stop_audit(None, "any reason", Path::new("/tmp/anywhere"));
    }
}
