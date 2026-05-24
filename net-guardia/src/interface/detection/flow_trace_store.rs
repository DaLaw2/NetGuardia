use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

pub type FlowTraceWriter = Box<dyn Write + Send>;

pub const FLOW_TRACE_FILE_MARKER: &str = "flow-trace-";
pub const FLOW_TRACE_FILE_EXT: &str = ".csv";

#[derive(Debug, Clone)]
pub struct FlowTraceFile {
    pub name: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub modified_unix_secs: u64,
}

pub struct FlowTraceOpenFile {
    pub writer: FlowTraceWriter,
    pub bytes_written: u64,
}

pub trait FlowTraceStore: Send + Sync {
    fn ensure_directory(&self, directory: &Path) -> io::Result<()>;
    fn create_rotated_writer(&self, directory: &Path, header: &[String]) -> io::Result<FlowTraceOpenFile>;
    fn list_files(&self, directory: &Path) -> io::Result<Vec<FlowTraceFile>>;
    fn enforce_retention_budget(&self, directory: &Path, budget: u64) -> io::Result<()>;
}
