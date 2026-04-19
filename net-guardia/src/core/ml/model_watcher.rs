//! Filesystem watcher over `models/`. Reloads the ML source whenever the
//! manifest or ONNX files change, re-reading both the manifest and the
//! scaler sidecar so feature-changing uploads land without a restart.
//! Events inside the staging subdirectory are filtered so partial uploads
//! can't flicker the UI through transient `Error` states.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use macros::log;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio::time::sleep;

use super::adapter::ModelSourceState;
use super::inference::Inference;
use super::model_loader::build_adapter;
use crate::infrastructure::app_config::AppConfig;
use crate::model::config::constants::{MANIFEST_FILENAME, MODELS_DIR, STAGING_SUBDIR};
use crate::model::detection::model_source::ModelInfo;
use crate::model::error::ml::MLError;
use crate::model::log::ml::MLLog;
use crate::model::system::config::MLInferenceConfig;

/// Debounce window: wait for both manifest and ONNX to land before reloading.
const DEBOUNCE_SECS: u64 = 5;

pub struct ModelWatcher {
    inference: Arc<Inference>,
    app_config: Arc<AppConfig>,
}

impl ModelWatcher {
    pub fn new(inference: Arc<Inference>, app_config: Arc<AppConfig>) -> Self {
        Self { inference, app_config }
    }

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

    async fn run(self) -> Result<(), MLError> {
        let models_dir = PathBuf::from(MODELS_DIR);
        if !models_dir.exists() {
            log!(MLLog::InferenceFailed(
                "ModelWatcher".to_string(),
                "models/ directory does not exist".to_string(),
            ));
            return Ok(());
        }

        let (tx, mut rx) = mpsc::channel::<()>(16);
        let _watcher = Self::spawn_watcher(models_dir, tx)?;

        log!(MLLog::ModelWatcherStarted);

        loop {
            if rx.recv().await.is_none() {
                break;
            }
            sleep(Duration::from_secs(DEBOUNCE_SECS)).await;
            while rx.try_recv().is_ok() {}
            // `try_reload` loads the manifest + sidecar + ONNX off disk, any
            // of which can block for >10ms on a cold cache — move it off the
            // tokio worker so the rest of the async runtime keeps turning.
            let inference = Arc::clone(&self.inference);
            let app_config = Arc::clone(&self.app_config);
            let _ = tokio::task::spawn_blocking(move || try_reload(&inference, &app_config)).await;
        }

        Ok(())
    }

    fn spawn_watcher(models_dir: PathBuf, tx: mpsc::Sender<()>) -> Result<RecommendedWatcher, MLError> {
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                if !is_relevant_event(&event) {
                    return;
                }
                // The callback runs on notify's OS dispatch thread, which must
                // not block on a full channel — the debounce loop coalesces
                // duplicates anyway, so dropping when full is safe.
                let _ = tx.try_send(());
            }
        })
        .map_err(MLError::ModelWatcherFailed)?;

        // Recursive watch so the staging filter gets exercised — otherwise a
        // drop-in to `.staging/` wouldn't trigger notify at all on some FSes.
        watcher
            .watch(&models_dir, RecursiveMode::Recursive)
            .map_err(MLError::ModelWatcherFailed)?;
        Ok(watcher)
    }
}

/// Full reload: manifest presence check → config re-parse → adapter build →
/// atomic state swap. Any failure lands the pipeline in `Error` rather
/// than crashing. Runs under `spawn_blocking` because manifest + sidecar +
/// ONNX loads are synchronous disk I/O plus a `tract` graph solve that
/// routinely takes >10 ms.
fn try_reload(inference: &Inference, app_config: &AppConfig) {
    let manifest_path = PathBuf::from(MODELS_DIR).join(MANIFEST_FILENAME);

    // Path 1 — manifest disappeared: transition to Dormant.
    if !manifest_path.exists() {
        log!(MLLog::ModelReloadStarting);
        inference.swap_state(ModelSourceState::Dormant);
        log!(MLLog::ModelReloadSuccess);
        return;
    }

    // Path 2 — manifest present: re-read + rebuild adapter.
    log!(MLLog::ModelReloadStarting);
    let batch_size = app_config.inference.inference_batch_size;
    match MLInferenceConfig::from_manifest_with_sidecar(&manifest_path) {
        Ok((config, manifest)) => match build_adapter(&manifest, Some(&manifest_path), &config, batch_size) {
            Ok(adapter) => {
                let info = ModelInfo::new(
                    manifest.name.clone(),
                    manifest.adapter.as_str().to_string(),
                    manifest.features.len(),
                );
                inference.swap_state(ModelSourceState::Active { adapter, info });
                log!(MLLog::ModelReloadSuccess);
            }
            Err(e) => {
                record_error(inference, e.to_string(), Some(manifest_path.clone()));
            }
        },
        Err(e) => {
            record_error(inference, e.to_string(), Some(manifest_path.clone()));
        }
    }
}

fn record_error(inference: &Inference, msg: String, last_attempted_path: Option<PathBuf>) {
    log!(MLLog::ModelReloadFailed(msg.clone()));
    inference.swap_state(ModelSourceState::Error {
        msg,
        since: SystemTime::now(),
        last_attempted_path,
    });
}

/// Inbound event filter. Ignore `.staging/` paths entirely; pass through
/// `.onnx` / `.yaml` / `.yml` / `.json` changes in `models/`.
fn is_relevant_event(event: &Event) -> bool {
    // Only Create / Modify events trigger a reload; renames / removes would
    // also surface but debouncing handles both equally well.
    if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
        return false;
    }
    event.paths.iter().any(|p| {
        if path_is_inside_staging(p) {
            return false;
        }
        matches!(
            p.extension().and_then(|e| e.to_str()),
            Some("onnx") | Some("yaml") | Some("yml") | Some("json")
        )
    })
}

fn path_is_inside_staging(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == STAGING_SUBDIR)
}

#[cfg(test)]
mod tests {
    use super::*;

    use notify::event::{CreateKind, ModifyKind};

    #[test]
    fn staging_paths_are_filtered() {
        assert!(path_is_inside_staging(&PathBuf::from("models/.staging/bad.onnx")));
        assert!(path_is_inside_staging(&PathBuf::from(
            "/tmp/models/.staging/sub/x.yaml"
        )));
        assert!(!path_is_inside_staging(&PathBuf::from("models/good.onnx")));
    }

    #[test]
    fn non_relevant_extensions_rejected() {
        let event = Event {
            kind: EventKind::Create(CreateKind::Any),
            paths: vec![PathBuf::from("models/readme.md")],
            attrs: Default::default(),
        };
        assert!(!is_relevant_event(&event));
    }

    #[test]
    fn onnx_outside_staging_accepted() {
        let event = Event {
            kind: EventKind::Create(CreateKind::Any),
            paths: vec![PathBuf::from("models/foo.onnx")],
            attrs: Default::default(),
        };
        assert!(is_relevant_event(&event));
    }

    #[test]
    fn staging_paths_always_rejected() {
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: vec![PathBuf::from("models/.staging/partial.onnx")],
            attrs: Default::default(),
        };
        assert!(!is_relevant_event(&event));
    }
}
