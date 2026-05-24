use std::fmt::Write as _;
use std::fs::File as StdFile;
use std::io;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::task;

use crate::interface::detection::model_promotion_store::ModelPromotionStore;

#[derive(Default)]
pub struct FsModelPromotionStore;

#[async_trait::async_trait]
impl ModelPromotionStore for FsModelPromotionStore {
    async fn exists(&self, path: &Path) -> io::Result<bool> {
        let path = path.to_path_buf();
        task::spawn_blocking(move || path.try_exists())
            .await
            .unwrap_or_else(|e| Err(io::Error::other(format!("exists join: {e}"))))
    }

    async fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        fs::create_dir_all(path).await
    }

    async fn rename(&self, src: &Path, dst: &Path) -> io::Result<()> {
        fs::rename(src, dst).await
    }

    async fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        fs::remove_dir_all(path).await
    }

    async fn remove_file(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path).await
    }

    async fn sha256_file(&self, path: &Path) -> io::Result<String> {
        let path = path.to_path_buf();
        task::spawn_blocking(move || -> io::Result<String> {
            let mut file = StdFile::open(&path)?;
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            let out = hasher.finalize();
            let mut hex = String::with_capacity(64);
            for byte in out {
                // SAFETY: write! on a String is infallible.
                let _ = write!(&mut hex, "{byte:02x}");
            }
            Ok(hex)
        })
        .await
        .unwrap_or_else(|e| Err(io::Error::other(format!("sha256 join: {e}"))))
    }
}
