//! Suricata subprocess manager — M1 scope.
//!
//! Responsibilities:
//! - Spawn Suricata as a child process bound to the ingress interface via AF_PACKET,
//!   writing eve.json to the configured log path.
//! - Track liveness; update `SuricataHealth` shared state.
//! - On crash, restart with configured backoff (if enabled in config).
//! - On shutdown signal, send SIGTERM first then wait briefly, then SIGKILL
//!   if the child still hasn't exited.
//!
//! M2 will add eve.json tail + parse; M3 will add SOAR translation. This module
//! does not read eve.json itself — downstream consumers tail the log path.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use macros::log;
use tokio::process::{Child, Command};
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};

use crate::infrastructure::app_config::AppConfig;
use crate::model::error::Error;
use crate::model::error::suricata::SuricataError;
use crate::model::log::suricata::SuricataLog;
use crate::model::system::suricata::SuricataHealth;

pub struct SuricataManager {
    config: Arc<AppConfig>,
    health: Arc<ArcSwap<SuricataHealth>>,
}

impl SuricataManager {
    pub fn new(config: Arc<AppConfig>) -> Arc<Self> {
        let initial = if config.suricata.enabled {
            SuricataHealth::Stopped {
                reason: "not yet started".to_string(),
            }
        } else {
            SuricataHealth::Disabled
        };
        Arc::new(Self {
            config,
            health: Arc::new(ArcSwap::from_pointee(initial)),
        })
    }

    /// Shared handle for HTTP handlers and the health broadcast.
    pub fn health(&self) -> Arc<ArcSwap<SuricataHealth>> {
        self.health.clone()
    }

    /// Supervisor loop. Returns a `oneshot::Sender` — dropping or sending on it
    /// initiates graceful shutdown (SIGTERM → wait → SIGKILL).
    pub fn run(self: Arc<Self>) -> oneshot::Sender<()> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        if !self.config.suricata.enabled {
            log!(SuricataLog::Disabled);
            return shutdown_tx;
        }

        tokio::spawn(async move {
            self.supervisor_loop(shutdown_rx).await;
        });

        shutdown_tx
    }

    async fn supervisor_loop(self: Arc<Self>, mut shutdown_rx: oneshot::Receiver<()>) {
        loop {
            // Pre-flight: validate binary + config exist before spawning.
            if let Err(e) = Self::preflight(&self.config) {
                self.health
                    .store(Arc::new(SuricataHealth::Stopped { reason: e.to_string() }));
                return;
            }

            let mut child = match self.spawn_child() {
                Ok(c) => c,
                Err(e) => {
                    self.health
                        .store(Arc::new(SuricataHealth::Stopped { reason: e.to_string() }));
                    return;
                }
            };

            let pid = child.id().unwrap_or(0);
            self.health.store(Arc::new(SuricataHealth::Running { pid }));
            log!(SuricataLog::Started(pid));

            tokio::select! {
                exit = child.wait() => {
                    let reason = match exit {
                        Ok(status) => format!("exited with {status}"),
                        Err(e) => format!("wait error: {e}"),
                    };
                    if self.config.suricata.auto_restart_on_crash {
                        let backoff = self.config.suricata.restart_backoff_secs;
                        log!(SuricataLog::CrashedRestartPending(reason.clone(), backoff));
                        self.health.store(Arc::new(SuricataHealth::Stopped { reason }));
                        sleep(Duration::from_secs(backoff)).await;
                        continue;
                    } else {
                        log!(SuricataLog::Stopped(reason.clone()));
                        self.health.store(Arc::new(SuricataHealth::Stopped { reason }));
                        return;
                    }
                }
                _ = &mut shutdown_rx => {
                    log!(SuricataLog::ShutdownRequested);
                    Self::graceful_stop(&mut child).await;
                    self.health.store(Arc::new(SuricataHealth::Stopped {
                        reason: "shutdown".to_string(),
                    }));
                    return;
                }
            }
        }
    }

    fn preflight(config: &AppConfig) -> Result<(), Error> {
        let bin = &config.suricata.binary_path;
        if !Path::new(bin).exists() {
            Err(SuricataError::BinaryNotFound(bin.clone()))?;
        }
        let cfg = &config.suricata.config_path;
        if !Path::new(cfg).exists() {
            Err(SuricataError::ConfigNotFound(cfg.clone()))?;
        }
        Ok(())
    }

    fn spawn_child(&self) -> Result<Child, Error> {
        let sc = &self.config.suricata;
        let iface = &self.config.network.ingress_ifname;

        log!(SuricataLog::Spawning(
            sc.binary_path.clone(),
            sc.config_path.clone(),
            iface.clone(),
        ));

        let mut cmd = Command::new(&sc.binary_path);
        cmd.arg("-c")
            .arg(&sc.config_path)
            .arg("--af-packet")
            .arg(iface)
            .arg("-l")
            // Log dir is the parent of the configured eve.json path.
            .arg(
                Path::new(&sc.eve_log_path)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| ".".to_string()),
            )
            .kill_on_drop(true);

        cmd.spawn().map_err(|e| SuricataError::SpawnFailed(e).into())
    }

    /// Send SIGTERM, wait up to 5s, then SIGKILL if still alive.
    async fn graceful_stop(child: &mut Child) {
        if let Some(pid) = child.id() {
            // SAFETY: SIGTERM to a known child pid. pid was obtained from tokio::process::Child
            // and is valid as long as we haven't reaped it, which we haven't.
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
        match timeout(Duration::from_secs(5), child.wait()).await {
            Ok(_) => {}
            Err(_) => {
                let _ = child.kill().await;
            }
        }
    }
}
