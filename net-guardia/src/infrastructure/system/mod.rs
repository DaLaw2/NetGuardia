use std::env;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::time::Duration;

use macros::log;
use sd_notify::NotifyState;
use tokio::signal::ctrl_c;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

use crate::adapter::persistence::Database;
use crate::common::error::Error;
use crate::common::error::system::SystemError;
use crate::common::log::system::SystemLog;
use crate::core::common::config_loader::{load_app_config, seed_config_defaults};
use crate::infrastructure::logger::Logger;
use crate::infrastructure::startup::{self, SystemRuntime};
use crate::infrastructure::system::lifecycle::Lifecycle;
use crate::infrastructure::system::setup::{is_setup_complete, run_setup_wizard, seed_initial_data};
use crate::interface::system::system_control::SystemCommandPort;

mod lifecycle;
mod runtime_start;
mod setup;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownMode {
    Shutdown,
    Restart,
}

pub struct ShutdownHandle {
    tx: Sender<ShutdownMode>,
}

impl ShutdownHandle {
    fn new(tx: Sender<ShutdownMode>) -> Self {
        Self { tx }
    }

    pub fn trigger(&self, mode: ShutdownMode) -> bool {
        self.tx.try_send(mode).is_ok()
    }
}

impl SystemCommandPort for ShutdownHandle {
    fn trigger_shutdown(&self) -> bool {
        self.trigger(ShutdownMode::Shutdown)
    }

    fn trigger_restart(&self) -> bool {
        self.trigger(ShutdownMode::Restart)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemPhase {
    New,
    Ready,
    Running,
    Terminated,
}

pub struct System {
    db_path: String,
    runtime: Option<SystemRuntime>,
    shutdown_handle: Option<Arc<ShutdownHandle>>,
    lifecycle: Lifecycle,
    phase: SystemPhase,
}

impl System {
    pub fn new(db_path: impl Into<String>) -> Self {
        Self {
            db_path: db_path.into(),
            runtime: None,
            shutdown_handle: None,
            lifecycle: Lifecycle::default(),
            phase: SystemPhase::New,
        }
    }

    pub async fn setup(&mut self) -> Result<(), Error> {
        if self.phase != SystemPhase::New {
            return Err(SystemError::InvalidSetupInput(format!(
                "cannot setup system while lifecycle phase is {:?}",
                self.phase
            ))
            .into());
        }

        let database = Arc::new(Database::new(&self.db_path).await?);
        let api_key_hmac = Database::derive_api_key_hmac(&self.db_path)?;
        seed_config_defaults(database.as_ref()).await?;
        let app_config = load_app_config(database.as_ref()).await?;
        let (logger, log_buffer) = Logger::initialize(&app_config)?;

        let setup_complete = is_setup_complete(&database).await?;
        if !setup_complete {
            run_setup_wizard(&database, api_key_hmac).await?;
            seed_initial_data(&database).await?;
        }

        let app_config = load_app_config(database.as_ref()).await?;

        self.runtime = Some(
            startup::create_runtime(
                database,
                app_config,
                Arc::new(logger),
                Arc::new(log_buffer),
                api_key_hmac,
            )
            .await?,
        );
        self.phase = SystemPhase::Ready;
        Ok(())
    }

    fn runtime(&self) -> Result<&SystemRuntime, Error> {
        self.runtime
            .as_ref()
            .ok_or_else(|| SystemError::InvalidConfigField("system.runtime").into())
    }

    fn runtime_mut(&mut self) -> Result<&mut SystemRuntime, Error> {
        self.runtime
            .as_mut()
            .ok_or_else(|| SystemError::InvalidConfigField("system.runtime").into())
    }

    pub async fn run(&mut self) -> Result<ShutdownMode, Error> {
        if self.phase != SystemPhase::Ready {
            return Err(SystemError::InvalidSetupInput(format!(
                "cannot run system while lifecycle phase is {:?}",
                self.phase
            ))
            .into());
        }
        self.phase = SystemPhase::Running;
        log!(SystemLog::Initializing);
        runtime_start::start_data_plane(self).await?;
        runtime_start::start_inference(self).await?;
        runtime_start::start_response(self).await?;
        let suricata_detection_tx = runtime_start::start_detection_graph(self)?;
        runtime_start::start_observability(self).await?;
        let mut shutdown_rx = runtime_start::start_http(self).await?;
        runtime_start::start_external(self, suricata_detection_tx);
        log!(SystemLog::InitializeComplete);
        tokio::select! {
            _ = ctrl_c() => Ok(ShutdownMode::Shutdown),
            mode = shutdown_rx.recv() => Ok(mode.unwrap_or(ShutdownMode::Shutdown)),
        }
    }

    pub async fn terminate(&mut self) -> Result<(), Error> {
        log!(SystemLog::Terminating);
        if let Some(runtime) = self.runtime.as_ref() {
            runtime.data_plane.ebpf_services.clone().terminate();
            runtime.detection.inference_runtime.terminate();
        }
        self.lifecycle.terminate().await;
        self.phase = SystemPhase::Terminated;
        log!(SystemLog::TerminateComplete);
        Ok(())
    }

    pub async fn handle_shutdown(self, mode: ShutdownMode) -> Result<(), Error> {
        match mode {
            ShutdownMode::Restart => {
                log!(SystemLog::Restart);
                if let Err(err) = sd_notify::notify(&[NotifyState::Reloading]) {
                    log!(SystemLog::SystemdNotifyFailed("Reloading", err.to_string()));
                }
                drop(self);
                sleep(Duration::from_millis(500)).await;
                let exe = env::current_exe().unwrap_or_else(|err| {
                    log!(SystemLog::RestartExecutableLookupFailed(err.to_string()));
                    PathBuf::from("net-guardia")
                });
                let err = process::Command::new(exe).args(env::args().skip(1)).exec();
                log!(SystemError::UnexpectedError(err));
                process::exit(1);
            }
            ShutdownMode::Shutdown => {
                log!(SystemLog::Shutdown);
                if let Err(err) = sd_notify::notify(&[NotifyState::Stopping]) {
                    log!(SystemLog::SystemdNotifyFailed("Stopping", err.to_string()));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn new_does_not_setup_runtime() {
        let system = System::new(":memory:");

        assert!(system.runtime.is_none());
        assert!(system.shutdown_handle.is_none());
        assert_eq!(system.phase, SystemPhase::New);
    }

    #[tokio::test]
    async fn run_before_setup_fails() {
        let mut system = System::new(":memory:");

        let err = system.run().await.expect_err("run before setup should fail");

        assert!(err.to_string().contains("cannot run system"));
    }

    #[tokio::test]
    async fn terminate_before_run_is_noop() {
        let mut system = System::new(":memory:");

        system.terminate().await.expect("terminate before run should succeed");
    }
}
