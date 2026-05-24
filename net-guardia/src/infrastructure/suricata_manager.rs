use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use macros::log;
use tokio::process::{Child, Command};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::common::error::Error;
use crate::common::error::suricata::SuricataError;
use crate::common::log::suricata::SuricataLog;
use crate::domain::common::config::AppConfig;
use crate::domain::detection::suricata_health::SuricataHealth;
use crate::interface::system::health_query::SuricataHealthQuery;

pub struct SuricataManager {
    config: Arc<ArcSwap<AppConfig>>,
    health: Arc<ArcSwap<SuricataHealth>>,
}

impl SuricataManager {
    pub fn new(config: Arc<ArcSwap<AppConfig>>) -> Arc<Self> {
        let initial = if config.load().suricata.enabled {
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

    pub fn run(self: Arc<Self>) -> (oneshot::Sender<()>, JoinHandle<()>) {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        if !self.config.load().suricata.enabled {
            log!(SuricataLog::Disabled);
            let handle = tokio::spawn(async move {
                let _ = shutdown_rx.await;
            });
            return (shutdown_tx, handle);
        }

        let handle = tokio::spawn(async move {
            self.supervisor_loop(shutdown_rx).await;
        });

        (shutdown_tx, handle)
    }

    async fn supervisor_loop(self: Arc<Self>, mut shutdown_rx: oneshot::Receiver<()>) {
        loop {
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
                    let config = self.config.load();
                    if config.suricata.auto_restart_on_crash {
                        let backoff = config.suricata.restart_backoff_secs;
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

    fn preflight(config: &Arc<ArcSwap<AppConfig>>) -> Result<(), Error> {
        let config = config.load();
        let bin = &config.suricata.binary_path;
        if !Path::new(bin).exists() {
            Err(SuricataError::BinaryNotFound(bin.clone()))?;
        }
        let cfg_path = &config.suricata.config_path;
        if !Path::new(cfg_path).exists() {
            Err(SuricataError::ConfigNotFound(cfg_path.clone()))?;
        }
        Ok(())
    }

    fn spawn_child(&self) -> Result<Child, Error> {
        let config = self.config.load();
        let sc = &config.suricata;
        let iface = &config.ebpf.ingress_ifname;

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
            .arg(
                Path::new(&sc.eve_log_path)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| ".".to_string()),
            )
            .kill_on_drop(true);

        let child = cmd.spawn().map_err(SuricataError::SpawnFailed)?;
        Ok(child)
    }

    async fn graceful_stop(child: &mut Child) {
        if let Some(pid) = child.id() {
            // SAFETY: SIGTERM to a known child pid. pid was obtained from tokio::process::Child
            let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
            if ret != 0 {
                log!(SuricataLog::ShutdownSignalFailed(
                    io::Error::last_os_error().to_string(),
                ));
            }
        }
        match timeout(Duration::from_secs(5), child.wait()).await {
            Ok(_) => {}
            Err(_) => {
                if let Err(err) = child.kill().await {
                    log!(SuricataLog::ShutdownKillFailed(err.to_string()));
                }
            }
        }
    }
}

impl SuricataHealthQuery for SuricataManager {
    fn get_suricata_health(&self) -> SuricataHealth {
        (**self.health.load()).clone()
    }
}
