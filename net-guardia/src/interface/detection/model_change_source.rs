use tokio::sync::mpsc;

use crate::domain::detection::error::MLError;

pub trait ModelChangeSource: Send + Sync {
    fn model_dir_available(&self) -> bool;
    fn subscribe(&self, tx: mpsc::Sender<()>) -> Result<Box<dyn ModelChangeSubscription>, MLError>;
}

pub trait ModelChangeSubscription: Send {}
