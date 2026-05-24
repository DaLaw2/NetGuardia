use std::path::{Path, PathBuf};

use macros::log;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::domain::detection::error::MLError;
use crate::domain::detection::log::MLLog;
use crate::domain::detection::model_files::STAGING_SUBDIR;
use crate::interface::detection::model_change_source::{ModelChangeSource, ModelChangeSubscription};

pub struct NotifyModelChangeSource {
    models_dir: PathBuf,
}

impl NotifyModelChangeSource {
    pub fn new(models_dir: PathBuf) -> Self {
        Self { models_dir }
    }
}

impl ModelChangeSource for NotifyModelChangeSource {
    fn model_dir_available(&self) -> bool {
        self.models_dir.is_dir()
    }

    fn subscribe(&self, tx: mpsc::Sender<()>) -> Result<Box<dyn ModelChangeSubscription>, MLError> {
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Err(err) = res.as_ref() {
                log!(MLLog::ModelWatcherEventError(err.to_string()));
                return;
            }
            let Ok(event) = res else {
                return;
            };
            if !is_relevant_event(&event) {
                return;
            }
            match tx.try_send(()) {
                Ok(()) | Err(TrySendError::Full(())) => {}
                Err(TrySendError::Closed(())) => {
                    log!(MLLog::ModelWatcherEventError("model reload channel closed"));
                }
            }
        })
        .map_err(MLError::ModelWatcherFailed)?;
        watcher
            .watch(&self.models_dir, RecursiveMode::Recursive)
            .map_err(MLError::ModelWatcherFailed)?;
        Ok(Box::new(watcher))
    }
}

impl ModelChangeSubscription for RecommendedWatcher {}

fn is_relevant_event(event: &Event) -> bool {
    if !matches!(
        event.kind,
        EventKind::Any | EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    ) {
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
    use notify::event::{CreateKind, ModifyKind, RemoveKind};

    use super::*;

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

    #[test]
    fn manifest_remove_is_relevant() {
        let event = Event {
            kind: EventKind::Remove(RemoveKind::File),
            paths: vec![PathBuf::from("models/manifest.yaml")],
            attrs: Default::default(),
        };
        assert!(is_relevant_event(&event));
    }

    #[test]
    fn imprecise_manifest_event_is_relevant() {
        let event = Event {
            kind: EventKind::Any,
            paths: vec![PathBuf::from("models/manifest.yaml")],
            attrs: Default::default(),
        };
        assert!(is_relevant_event(&event));
    }

    #[test]
    fn model_dir_available_requires_directory() {
        let source = NotifyModelChangeSource::new(PathBuf::from("Cargo.toml"));

        assert!(!source.model_dir_available());
    }
}
