use std::io;
use std::path::Path;

#[async_trait::async_trait]
pub trait ModelPromotionStore: Send + Sync {
    async fn exists(&self, path: &Path) -> io::Result<bool>;
    async fn create_dir_all(&self, path: &Path) -> io::Result<()>;
    async fn rename(&self, src: &Path, dst: &Path) -> io::Result<()>;
    async fn remove_dir_all(&self, path: &Path) -> io::Result<()>;
    async fn remove_file(&self, path: &Path) -> io::Result<()>;
    async fn sha256_file(&self, path: &Path) -> io::Result<String>;
}
