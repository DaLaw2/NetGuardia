use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use macros::log;
use tokio::sync::mpsc;
use tokio::task;
use tokio::time::sleep;

use super::model_loader::build_adapter;
use super::runner::Inference;
use crate::core::inference::model_adapter::ModelSourceState;
use crate::domain::common::config::AppConfig;
use crate::domain::detection::error::MLError;
use crate::domain::detection::log::MLLog;
use crate::domain::detection::model_files::{MANIFEST_FILENAME, MODELS_DIR};
use crate::domain::detection::model_source::ModelInfo;
use crate::interface::detection::model_artifact_resolver::ModelArtifactResolver;
use crate::interface::detection::model_change_source::ModelChangeSource;
use crate::interface::detection::model_config_loader::ModelConfigLoader;
use crate::interface::detection::model_runtime::ModelRuntimeLoader;

#[derive(Debug)]
pub enum ModelReloadOutcome {
    Active {
        info: ModelInfo,
    },
    Dormant,
    Error {
        msg: String,
        last_attempted_path: Option<PathBuf>,
    },
}

pub struct ModelWatcher {
    inference: Arc<Inference>,
    config: Arc<ArcSwap<AppConfig>>,
    runtime_loader: Arc<dyn ModelRuntimeLoader>,
    artifact_resolver: Arc<dyn ModelArtifactResolver>,
    change_source: Arc<dyn ModelChangeSource>,
    config_loader: Arc<dyn ModelConfigLoader>,
}

impl ModelWatcher {
    pub fn new(
        inference: Arc<Inference>,
        config: Arc<ArcSwap<AppConfig>>,
        runtime_loader: Arc<dyn ModelRuntimeLoader>,
        artifact_resolver: Arc<dyn ModelArtifactResolver>,
        change_source: Arc<dyn ModelChangeSource>,
        config_loader: Arc<dyn ModelConfigLoader>,
    ) -> Self {
        Self {
            inference,
            config,
            runtime_loader,
            artifact_resolver,
            change_source,
            config_loader,
        }
    }

    pub async fn run(self) -> Result<(), MLError> {
        if !self.change_source.model_dir_available() {
            log!(MLLog::InferenceFailed(
                "ModelWatcher".to_string(),
                "models/ directory does not exist".to_string(),
            ));
            return Ok(());
        }

        let (tx, mut rx) = mpsc::channel::<()>(16);
        let _subscription = self.change_source.subscribe(tx)?;

        log!(MLLog::ModelWatcherStarted);

        loop {
            if rx.recv().await.is_none() {
                break;
            }
            sleep(Duration::from_secs(
                self.config.load().ml.inference.model_watcher_debounce_secs,
            ))
            .await;
            while rx.try_recv().is_ok() {}
            let inference = Arc::clone(&self.inference);
            let config = Arc::clone(&self.config);
            let runtime_loader = Arc::clone(&self.runtime_loader);
            let artifact_resolver = Arc::clone(&self.artifact_resolver);
            let config_loader = Arc::clone(&self.config_loader);
            if let Err(err) = task::spawn_blocking(move || {
                reload_model_from_disk(
                    &inference,
                    &config,
                    runtime_loader.as_ref(),
                    artifact_resolver.as_ref(),
                    config_loader.as_ref(),
                )
            })
            .await
            {
                log!(MLLog::ModelReloadJoinFailed(err.to_string()));
            }
        }

        Ok(())
    }
}

pub fn reload_model_from_disk(
    inference: &Inference,
    config: &ArcSwap<AppConfig>,
    runtime_loader: &dyn ModelRuntimeLoader,
    artifact_resolver: &dyn ModelArtifactResolver,
    config_loader: &dyn ModelConfigLoader,
) -> ModelReloadOutcome {
    let manifest_path = PathBuf::from(MODELS_DIR).join(MANIFEST_FILENAME);
    if !manifest_path.exists() {
        log!(MLLog::ModelReloadStarting);
        inference.swap_state(ModelSourceState::Dormant);
        log!(MLLog::ModelReloadSuccess);
        return ModelReloadOutcome::Dormant;
    }
    log!(MLLog::ModelReloadStarting);
    let app_cfg = config.load();
    let batch_size = app_cfg.ml.inference.inference_batch_size;
    let onnx_load_timeout = Duration::from_secs(app_cfg.ml.inference.onnx_load_timeout_secs);
    drop(app_cfg);
    match config_loader.load_manifest_with_sidecar(&manifest_path) {
        Ok((config, manifest)) => {
            match build_adapter(
                &manifest,
                Some(&manifest_path),
                &config,
                batch_size,
                onnx_load_timeout,
                runtime_loader,
                artifact_resolver,
            ) {
                Ok(adapter) => {
                    let info = ModelInfo::new(
                        manifest.name.clone(),
                        manifest.runtime_adapter().to_string(),
                        current_epoch_secs(),
                        manifest.runtime_feature_count(),
                    );
                    inference.swap_state(ModelSourceState::Active {
                        adapter,
                        info: info.clone(),
                    });
                    log!(MLLog::ModelReloadSuccess);
                    ModelReloadOutcome::Active { info }
                }
                Err(e) => record_error(inference, e.to_string(), Some(manifest_path.clone())),
            }
        }
        Err(e) => record_error(inference, e.to_string(), Some(manifest_path.clone())),
    }
}

fn record_error(inference: &Inference, msg: String, last_attempted_path: Option<PathBuf>) -> ModelReloadOutcome {
    log!(MLLog::ModelReloadFailed(msg.clone()));
    if !inference.is_active() {
        inference.swap_state(ModelSourceState::Error {
            msg: msg.clone(),
            since: SystemTime::now(),
            last_attempted_path: last_attempted_path.clone(),
        });
    }
    ModelReloadOutcome::Error {
        msg,
        last_attempted_path,
    }
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
