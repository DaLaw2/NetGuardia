use std::fs;
use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime};

pub fn clean_staging_orphans(staging_root: &Path, max_age: Duration) -> io::Result<usize> {
    if !staging_root.exists() {
        return Ok(0);
    }
    let now = SystemTime::now();
    let mut cleaned = 0usize;
    for entry in fs::read_dir(staging_root)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let metadata = entry.metadata()?;
        let mtime = metadata.modified()?;
        let age = now.duration_since(mtime).unwrap_or_default();
        if age >= max_age {
            fs::remove_dir_all(&path)?;
            cleaned += 1;
        }
    }
    Ok(cleaned)
}
