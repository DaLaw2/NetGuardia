use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use macros::log;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use super::inference::Inference;
use super::model_loader::MLModels;
use crate::infrastructure::app_config::AppConfig;
use crate::model::log::ml::MLLog;
use crate::model::system::config::MLInferenceConfig;

/// Debounce window: wait for both AE + classifier to land before reloading.
const DEBOUNCE_SECS: u64 = 5;

/// Watch the models/ directory for .onnx file changes and hot-reload into the inference pipeline.
pub struct ModelWatcher {
    inference: Arc<Inference>,
    app_config: Arc<AppConfig>,
    inference_config: Arc<MLInferenceConfig>,
}

impl ModelWatcher {
    pub fn new(
        inference: Arc<Inference>,
        app_config: Arc<AppConfig>,
        inference_config: Arc<MLInferenceConfig>,
    ) -> Self {
        Self {
            inference,
            app_config,
            inference_config,
        }
    }

    /// Start watching in a background task.
    pub fn start(self) {
        tokio::spawn(async move {
            if let Err(e) = self.run().await {
                log!(MLLog::InferenceFailed(
                    "ModelWatcher".to_string(),
                    format!("watcher failed to start: {e}"),
                ));
            }
        });
    }

    async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let models_dir = PathBuf::from("models");
        if !models_dir.exists() {
            log!(MLLog::InferenceFailed(
                "ModelWatcher".to_string(),
                "models/ directory does not exist".to_string(),
            ));
            return Ok(());
        }

        let (tx, mut rx) = mpsc::channel::<()>(16);

        // notify watcher runs on a blocking thread — forward events via channel
        let _watcher = Self::spawn_watcher(models_dir, tx)?;

        log!(MLLog::ModelWatcherStarted);

        loop {
            // Wait for first event
            if rx.recv().await.is_none() {
                break;
            }

            // Debounce: drain any additional events within the window
            tokio::time::sleep(Duration::from_secs(DEBOUNCE_SECS)).await;
            while rx.try_recv().is_ok() {}

            // Attempt reload
            self.try_reload();
        }

        Ok(())
    }

    fn spawn_watcher(
        models_dir: PathBuf,
        tx: mpsc::Sender<()>,
    ) -> Result<RecommendedWatcher, notify::Error> {
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let dominated = matches!(
                    event.kind,
                    EventKind::Create(_) | EventKind::Modify(_)
                );
                let has_onnx = event.paths.iter().any(|p| {
                    p.extension().is_some_and(|ext| ext == "onnx")
                });
                if dominated && has_onnx {
                    let _ = tx.blocking_send(());
                }
            }
        })?;

        watcher.watch(&models_dir, RecursiveMode::NonRecursive)?;
        Ok(watcher)
    }

    fn try_reload(&self) {
        let batch_size = self.app_config.inference.inference_batch_size;

        log!(MLLog::ModelReloadStarting);

        match MLModels::load_models(&self.app_config, &self.inference_config, batch_size) {
            Ok(new_models) => {
                self.inference.swap_models(Arc::new(new_models));
                log!(MLLog::ModelReloadSuccess);
            }
            Err(e) => {
                log!(MLLog::ModelReloadFailed(e.to_string()));
            }
        }
    }
}
