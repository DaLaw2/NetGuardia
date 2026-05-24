use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::interface::detection::flow_trace_store::{
    FLOW_TRACE_FILE_EXT, FLOW_TRACE_FILE_MARKER, FlowTraceFile, FlowTraceOpenFile, FlowTraceStore, FlowTraceWriter,
};

const FLOW_TRACE_CREATE_ATTEMPTS: u64 = 16;

#[derive(Default)]
pub struct FsFlowTraceStore;

impl FlowTraceStore for FsFlowTraceStore {
    fn ensure_directory(&self, directory: &Path) -> io::Result<()> {
        fs::create_dir_all(directory)
    }

    fn create_rotated_writer(&self, directory: &Path, header: &[String]) -> io::Result<FlowTraceOpenFile> {
        let ts_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        create_rotated_writer_at(directory, header, ts_ns)
    }

    fn list_files(&self, directory: &Path) -> io::Result<Vec<FlowTraceFile>> {
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for dirent in fs::read_dir(directory)? {
            let dirent = dirent?;
            let path = dirent.path();
            if !dirent.file_type()?.is_file() {
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

    fn enforce_retention_budget(&self, directory: &Path, budget: u64) -> io::Result<()> {
        let files = self.list_files(directory)?;
        let total: u64 = files.iter().map(|f| f.size_bytes).sum();
        if total <= budget {
            return Ok(());
        }
        let mut remaining = total;
        for file in files {
            if remaining <= budget {
                break;
            }
            fs::remove_file(&file.path)?;
            remaining = remaining.saturating_sub(file.size_bytes);
        }
        Ok(())
    }
}

fn create_rotated_writer_at(directory: &Path, header: &[String], ts_ns: u64) -> io::Result<FlowTraceOpenFile> {
    for offset in 0..FLOW_TRACE_CREATE_ATTEMPTS {
        let candidate_ts = ts_ns.saturating_add(offset);
        let path = directory.join(format!(
            "{FLOW_TRACE_FILE_MARKER}{candidate_ts:020}{FLOW_TRACE_FILE_EXT}"
        ));
        match create_writer(&path, header) {
            Ok(opened) => return Ok(opened),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "flow trace filename collision budget exhausted",
    ))
}

fn create_writer(path: &Path, header: &[String]) -> io::Result<FlowTraceOpenFile> {
    let file = OpenOptions::new().create_new(true).write(true).open(path)?;
    let mut writer: FlowTraceWriter = Box::new(file);
    let header_line = format!("{}\n", header.join(","));
    writer.write_all(header_line.as_bytes())?;
    writer.flush()?;
    Ok(FlowTraceOpenFile {
        writer,
        bytes_written: header_line.len() as u64,
    })
}

fn parse_timestamp_suffix(name: &str) -> Option<u64> {
    let without_prefix = name.strip_prefix(FLOW_TRACE_FILE_MARKER)?;
    let without_ext = without_prefix.strip_suffix(FLOW_TRACE_FILE_EXT)?;
    without_ext.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::io::Write as _;
    use std::path::PathBuf;

    use uuid::Uuid;

    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("nguardia-flow-trace-store-{tag}-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_fake_trace(dir: &Path, ts_ns: u64, bytes: usize) -> PathBuf {
        let path = dir.join(format!("{FLOW_TRACE_FILE_MARKER}{ts_ns:020}{FLOW_TRACE_FILE_EXT}"));
        let mut f = fs::File::create(&path).unwrap();
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
        let store = FsFlowTraceStore;
        let files = store.list_files(&dir).unwrap();
        let suffixes: Vec<_> = files.iter().map(|f| parse_timestamp_suffix(&f.name).unwrap()).collect();
        assert_eq!(suffixes, vec![100, 200, 300]);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn list_skips_non_flow_trace_files() {
        let dir = scratch_dir("skip");
        write_fake_trace(&dir, 42, 10);
        fs::write(dir.join("not-ours.csv"), b"foo").unwrap();
        fs::write(dir.join("flow-trace-bad-suffix.txt"), b"foo").unwrap();
        let store = FsFlowTraceStore;
        let files = store.list_files(&dir).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(parse_timestamp_suffix(&files[0].name), Some(42));
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn list_skips_flow_trace_symlinks() {
        let dir = scratch_dir("skip-symlink");
        let target = write_fake_trace(&dir, 42, 10);
        let link = dir.join(format!("{FLOW_TRACE_FILE_MARKER}{:020}{FLOW_TRACE_FILE_EXT}", 43));
        std::os::unix::fs::symlink(&target, link).unwrap();

        let files = FsFlowTraceStore.list_files(&dir).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(parse_timestamp_suffix(&files[0].name), Some(42));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn list_on_missing_dir_returns_empty() {
        let missing = Path::new("/nonexistent/flow-trace/dir");
        let store = FsFlowTraceStore;
        assert!(store.list_files(missing).unwrap().is_empty());
    }

    #[test]
    fn retention_budget_removes_oldest_until_under_cap() {
        let dir = scratch_dir("budget");
        write_fake_trace(&dir, 100, 1024);
        write_fake_trace(&dir, 200, 1024);
        write_fake_trace(&dir, 300, 1024);
        let store = FsFlowTraceStore;
        store.enforce_retention_budget(&dir, 1500).unwrap();
        let remaining = store.list_files(&dir).unwrap();
        let suffixes: Vec<_> = remaining
            .iter()
            .map(|f| parse_timestamp_suffix(&f.name).unwrap())
            .collect();
        assert_eq!(suffixes, vec![300]);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retention_budget_is_noop_when_under_cap() {
        let dir = scratch_dir("budget-noop");
        write_fake_trace(&dir, 100, 512);
        write_fake_trace(&dir, 200, 512);
        let store = FsFlowTraceStore;
        store.enforce_retention_budget(&dir, 8192).unwrap();
        assert_eq!(store.list_files(&dir).unwrap().len(), 2);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotated_writer_creates_canonical_trace_file_with_header() {
        let dir = scratch_dir("rotated-writer");
        let store = FsFlowTraceStore;
        let opened = store
            .create_rotated_writer(&dir, &["duration".to_string(), "bytes".to_string()])
            .unwrap();
        drop(opened.writer);
        assert_eq!(opened.bytes_written, "duration,bytes\n".len() as u64);
        let files = store.list_files(&dir).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].name.starts_with(FLOW_TRACE_FILE_MARKER));
        assert!(files[0].name.ends_with(FLOW_TRACE_FILE_EXT));
        assert_eq!(fs::read_to_string(&files[0].path).unwrap(), "duration,bytes\n");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotated_writer_does_not_truncate_existing_trace_on_name_collision() {
        let dir = scratch_dir("rotated-writer-collision");
        let existing = write_fake_trace(&dir, 42, 5);

        let opened = create_rotated_writer_at(&dir, &["duration".to_string()], 42).unwrap();
        drop(opened.writer);

        assert_eq!(fs::read(&existing).unwrap(), vec![b'a'; 5]);
        let files = FsFlowTraceStore.list_files(&dir).unwrap();
        let suffixes: Vec<_> = files.iter().map(|f| parse_timestamp_suffix(&f.name).unwrap()).collect();
        assert_eq!(suffixes, vec![42, 43]);
        let collision_path = dir.join(format!("{FLOW_TRACE_FILE_MARKER}{:020}{FLOW_TRACE_FILE_EXT}", 43));
        assert!(matches!(
            fs::read_to_string(collision_path).as_deref(),
            Ok("duration\n")
        ));
        fs::remove_dir_all(&dir).ok();
    }
}
