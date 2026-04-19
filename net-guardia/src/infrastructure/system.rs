use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use aya::Ebpf;
use aya::maps::{MapData, ProgramArray};
use macros::log;
use sd_notify::NotifyState;
use tokio::signal::ctrl_c;
use tokio::sync::broadcast::{Receiver, error::RecvError};
use tokio::sync::mpsc::{self, Sender};
use tokio::sync::oneshot;
use tokio::time::{interval, sleep};

use crate::adapter::ebpf::EbpfServices;
use crate::adapter::http::model_upload;
use crate::adapter::persistence::Database;
use crate::core::acl_service::AclService;
use crate::core::auth::jwt::JwtService;
use crate::core::config_service::ConfigService;
use crate::core::correlation::engine::CorrelationEngine;
use crate::core::detection::beaconing::BeaconingDetector;
use crate::core::detection::orchestrator::DetectionOrchestrator;
use crate::core::dns_filter_service::DnsFilterService;
use crate::core::email::scheduler::ReportScheduler;
use crate::core::ml::drift_detector::DriftDetectorHandle;
use crate::core::ml::model_watcher::ModelWatcher;
use crate::core::notification_service::NotificationService;
use crate::core::playbook_service::PlaybookService;
use crate::core::rate_limit_service::RateLimitService;
use crate::core::soar::engine::SoarEngine;
use crate::core::soar::scheduler::TtlScheduler;
use crate::core::stats_aggregator::StatsAggregator;
use crate::infrastructure::app_config::AppConfig;
use crate::infrastructure::app_services::AppServices;
use crate::infrastructure::audit_logger::AuditLogger;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::infrastructure::geoip::GeoIpService;
use crate::infrastructure::http_server::{self, HttpServerParams};
use crate::infrastructure::secret_store::SecretStore;
use crate::infrastructure::service_factory::ServiceFactory;
use crate::infrastructure::suricata_manager::SuricataManager;
use crate::infrastructure::suricata_monitor::SuricataMonitor;
use crate::interface::port::audit::AuditRepo;
use crate::interface::port::packet_sink::PacketSinkFactory;
use crate::interface::port::setting::SettingRepo;
use crate::interface::port::stats::StatsRepo;
use crate::model::config::constants::{MODELS_DIR, STAGING_SUBDIR};
use crate::model::detection::ml_detection::AlertMessage;
use crate::model::error::Error;
use crate::model::error::system::SystemError;
use crate::model::event::{DetectionEvent, DetectionSource, DriftDetectedEvent};
use crate::model::log::detection::DetectionLog;
use crate::model::log::ml::MLLog;
use crate::model::log::system::SystemLog;
use crate::model::system::config::MLInferenceConfig;
use crate::model::system::health::EbpfHealth;
use crate::model::system::readiness::ReadinessState;

/// API-triggered shutdown mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownMode {
    Shutdown,
    Restart,
}

/// Handle for triggering shutdown from HTTP endpoints. Backed by a
/// capacity-1 mpsc so the first trigger atomically wins via `try_send`,
/// and subsequent calls receive `TrySendError::Full` — no lock, no
/// `Option::take`, no `Mutex`.
pub struct ShutdownHandle {
    tx: mpsc::Sender<ShutdownMode>,
}

impl ShutdownHandle {
    fn new(tx: mpsc::Sender<ShutdownMode>) -> Self {
        Self { tx }
    }

    /// Trigger shutdown. Returns false if already triggered or the
    /// receiver has been dropped.
    pub fn trigger(&self, mode: ShutdownMode) -> bool {
        self.tx.try_send(mode).is_ok()
    }
}

/// Orchestrates system lifecycle: startup ordering and shutdown.
/// Construction is delegated to `ServiceFactory::build()`.
/// Setup mode is handled by main.rs — System only runs when setup is complete.
pub struct System {
    pub app_config: Arc<AppConfig>,
    pub inference_config: Arc<MLInferenceConfig>,
    pub ebpf_services: Arc<EbpfServices>,
    pub app_services: Arc<AppServices>,
    pub db: Arc<Database>,
    pub secret_store: Arc<SecretStore>,
    pub jwt_service: Arc<JwtService>,
    pub comm: Arc<CommunicationManager>,
    pub soar_engine: Arc<SoarEngine>,
    pub ttl_scheduler: Option<TtlScheduler>,
    pub report_scheduler: Option<ReportScheduler>,
    pub ingress_ebpf: Option<Ebpf>,
    pub egress_ebpf: Option<Ebpf>,
    pub acl_service: Arc<AclService>,
    pub config_service: Arc<ConfigService>,
    pub dns_filter_service: Arc<DnsFilterService>,
    pub notification_service: Arc<NotificationService>,
    pub playbook_service: Arc<PlaybookService>,
    pub rate_limit_service: Arc<RateLimitService>,
    pub geoip: Option<Arc<GeoIpService>>,
    pub drift_detector: DriftDetectorHandle,
    pub shutdown_handle: Option<Arc<ShutdownHandle>>,
    _ingress_program_array: Option<ProgramArray<MapData>>,
    pub ebpf_health: Arc<ArcSwap<EbpfHealth>>,
    pub suricata_manager: Arc<SuricataManager>,
    suricata_shutdown: Option<oneshot::Sender<()>>,
}

impl System {
    /// Build System from DB. Only called after setup is confirmed complete.
    pub async fn new(db: Arc<Database>) -> Result<Self, Error> {
        let state = ServiceFactory::build(db).await?;
        Ok(System {
            app_config: state.app_config,
            inference_config: state.inference_config,
            ebpf_services: state.ebpf_services,
            app_services: state.app_services,
            db: state.db,
            secret_store: state.secret_store,
            jwt_service: state.jwt_service,
            comm: state.comm,
            soar_engine: state.soar_engine,
            ttl_scheduler: Some(state.ttl_scheduler),
            report_scheduler: Some(state.report_scheduler),
            ingress_ebpf: state.ingress_ebpf,
            egress_ebpf: state.egress_ebpf,
            acl_service: state.acl_service,
            config_service: state.config_service,
            dns_filter_service: state.dns_filter_service,
            notification_service: state.notification_service,
            playbook_service: state.playbook_service,
            rate_limit_service: state.rate_limit_service,
            geoip: state.geoip,
            drift_detector: state.drift_detector,
            shutdown_handle: None,
            _ingress_program_array: state._ingress_program_array,
            ebpf_health: state.ebpf_health,
            suricata_manager: state.suricata_manager,
            suricata_shutdown: None,
        })
    }

    /// Start all services and HTTP server. Setup is already complete at this point.
    /// Returns the shutdown mode requested (Shutdown or Restart).
    pub async fn run(&mut self) -> Result<ShutdownMode, Error> {
        log!(SystemLog::Initializing);

        // Sweep model-upload staging directories left over from failed
        // uploads before the model watcher starts listening. A stale
        // `.staging/<uuid>/` would otherwise outlive restarts and eat
        // disk if the admin repeatedly aborted uploads mid-stream.
        {
            let staging_root = PathBuf::from(MODELS_DIR).join(STAGING_SUBDIR);
            match model_upload::clean_staging_orphans(&staging_root, Duration::from_secs(3600)) {
                Ok(0) => {}
                Ok(n) => log!(SystemLog::StagingOrphansCleaned(n as u64)),
                Err(e) => log!(SystemLog::StagingOrphansSweepFailed(e.to_string())),
            }
        }

        // ML source state snapshot. Day 1 with no manifest renders as Dormant
        // — the rest of the stack still runs (3-source fusion).
        {
            let status = self.app_services.ml_inference.current_status();
            match serde_json::to_string(&status) {
                Ok(s) => log!(MLLog::ModelsLoaded(s)),
                Err(e) => log!(MLLog::ModelsLoaded(format!("<unserializable status: {e}>"))),
            }
        }
        log!(MLLog::ConfigLoaded(
            self.inference_config.num_ae_features(),
            self.inference_config.num_attack_types(),
        ));

        // aya_log_init + attach_xdp only make sense if the eBPF objects
        // loaded. When eBPF is unavailable we skip both; the rest of the
        // system runs normally and the eBPF health broadcast tells the UI why.
        // aya_log_init failure is logged but non-fatal — the kernel programs
        // still run, we just lose the in-kernel log channel.
        if let (Some(ingress), Some(egress)) = (self.ingress_ebpf.as_mut(), self.egress_ebpf.as_mut()) {
            if let Err(e) = ServiceFactory::aya_log_init(ingress, egress) {
                use crate::infrastructure::ebpf_preflight;
                use crate::model::system::health::EbpfFailStage;
                let health = ebpf_preflight::classify(EbpfFailStage::LoggerInit, &e, None);
                log!(SystemLog::EbpfBringupFailed(format!("{:?}", health)));
            }
            log!(SystemLog::InitializeComplete);
            self.attach_ebpf()?;
        } else {
            log!(SystemLog::InitializeComplete);
        }

        // Subscribe to ML alerts BEFORE starting services to avoid race condition
        let ml_alert_rx = self.app_services.ml_alert.subscribe_to_alerts();

        let ebpf_services = self.ebpf_services.clone();
        let app_services = self.app_services.clone();
        // AF_XDP socket bind + drop-ring-buf consumer. If eBPF maps are
        // unavailable the call already returns Ok(()) without doing anything.
        // When maps exist but bind fails (e.g. igb on kernel < 6.17), record
        // the classified reason and continue — the ML engine will see no
        // packets, same as a network that is simply quiet.
        let sink_factory: Arc<dyn PacketSinkFactory> = app_services.ml_engine.clone();
        if let Err(e) = ebpf_services.run(sink_factory).await {
            use crate::infrastructure::ebpf_preflight;
            use crate::model::system::health::EbpfFailStage;
            let iface = self.app_config.network.ingress_ifname.as_str();
            let health = ebpf_preflight::classify(EbpfFailStage::AfXdpBind, &e, Some(iface));
            log!(SystemLog::EbpfBringupFailed(format!("{:?}", health)));
            self.ebpf_health.store(Arc::new(health));
        }
        app_services.run().await?;

        // Start SOAR engine
        self.soar_engine.recover_active_blocks().await?;
        self.soar_engine.clone().start(self.comm.clone())?;

        // Start TTL scheduler
        if let Some(ttl) = self.ttl_scheduler.take() {
            ttl.start();
        }

        // Start Report scheduler
        if let Some(report) = self.report_scheduler.take() {
            report.run();
        }

        // Start audit logger (subscribe to AuditEvent + DriftDetectedEvent, persist to DB)
        let audit_logger = Arc::new(AuditLogger::new(self.db.clone() as Arc<dyn AuditRepo>));
        audit_logger.start(&self.comm);

        // Start stats aggregator (writes weekly_* settings for Report engine)
        let stats_aggregator = StatsAggregator::new(
            self.db.clone() as Arc<dyn StatsRepo>,
            self.db.clone() as Arc<dyn SettingRepo>,
        );
        stats_aggregator.start();

        // Start drift detection background task
        {
            let drift_detector = self.drift_detector.clone();
            let comm_drift = self.comm.clone();
            tokio::spawn(async move {
                Self::run_drift_monitor(drift_detector, comm_drift).await;
            });
        }

        // Start detection orchestrator (dedup + enrichment + source attribution)
        let (detection_tx, detection_rx) = mpsc::channel::<DetectionEvent>(1024);
        let orchestrator = DetectionOrchestrator::new(
            detection_rx,
            self.comm.clone(),
            self.geoip.clone(),
            self.app_services.fusion_metrics.clone(),
        );
        orchestrator.start();

        // Clone detection_tx for correlation engine and beaconing detector
        let correlation_detection_tx = detection_tx.clone();
        let beaconing_detection_tx = detection_tx.clone();
        let suricata_detection_tx = detection_tx.clone();

        // Start cross-flow correlation engine (botnet, scan, lateral movement detection)
        let correlation_alert_rx = self.app_services.ml_alert.subscribe_to_alerts();
        let correlation_engine = CorrelationEngine::new(correlation_alert_rx, correlation_detection_tx);
        correlation_engine.start();

        // Start temporal beaconing detector (CV-based C2 periodicity detection)
        let beaconing_alert_rx = self.app_services.ml_alert.subscribe_to_alerts();
        let beaconing_detector = BeaconingDetector::new(beaconing_alert_rx, beaconing_detection_tx);
        beaconing_detector.start();

        // Bridge ML alerts → DetectionEvent (thin adapter, no enrichment)
        tokio::spawn(async move {
            Self::bridge_ml_to_detection(ml_alert_rx, detection_tx).await;
        });

        // Start model hot-reload watcher (monitors models/ for .onnx changes)
        let model_watcher = ModelWatcher::new(self.app_services.ml_inference.clone(), self.app_config.clone());
        model_watcher.start();

        // Initialize force_https flag from DB setting
        let force_https = Arc::new(AtomicBool::new(
            self.db
                .get_setting("force_https")
                .ok()
                .flatten()
                .map(|v| v == "true")
                .unwrap_or(false),
        ));

        // Build per-subsystem readiness flags for /health/ready
        let readiness_state = Arc::new(ReadinessState::new());
        // DB is connected (System::new succeeded), ML models loaded (AppServices::new succeeded)
        readiness_state.db_connected.store(true, Ordering::SeqCst);
        readiness_state.ml_model_loaded.store(true, Ordering::SeqCst);
        // eBPF was attached above (self.attach_ebpf succeeded)
        readiness_state.ebpf_attached.store(true, Ordering::SeqCst);
        // SOAR engine started above (self.soar_engine.start succeeded)
        readiness_state.soar_engine_running.store(true, Ordering::SeqCst);

        // Create shutdown channel for API-triggered shutdown/restart.
        // Capacity 1 means only the first `try_send` lands a value; later
        // ones report Full, which `ShutdownHandle::trigger` surfaces as `false`.
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<ShutdownMode>(1);
        let shutdown_handle = Arc::new(ShutdownHandle::new(shutdown_tx));
        self.shutdown_handle = Some(shutdown_handle.clone());

        // Start HTTP server in background (!Send, use actix::spawn)
        let setup_flag = Arc::new(AtomicBool::new(true));
        let ready_flag = Arc::new(AtomicBool::new(false));
        let ready_flag_for_set = ready_flag.clone();
        let params = HttpServerParams {
            app_config: self.app_config.clone(),
            inference_config: self.inference_config.clone(),
            ebpf_services: self.ebpf_services.clone(),
            app_services: self.app_services.clone(),
            db: self.db.clone(),
            secret_store: self.secret_store.clone(),
            jwt_service: self.jwt_service.clone(),
            comm: self.comm.clone(),
            setup_complete: setup_flag,
            ready: ready_flag,
            readiness_state,
            acl_service: self.acl_service.clone(),
            config_service: self.config_service.clone(),
            dns_filter_service: self.dns_filter_service.clone(),
            notification_service: self.notification_service.clone(),
            playbook_service: self.playbook_service.clone(),
            rate_limit_service: self.rate_limit_service.clone(),
            force_https,
            shutdown_handle: shutdown_handle.clone(),
            suricata_manager: self.suricata_manager.clone(),
            soar_engine: self.soar_engine.clone(),
        };
        let ready_for_http = ready_flag_for_set.clone();
        actix::spawn(async move {
            if let Err(e) = http_server::run(params).await {
                // HTTP server failed — mark system as NOT ready so health checks fail
                ready_for_http.store(false, Ordering::SeqCst);
                log!(SystemError::HttpServerError(e));
            }
        });

        // Brief delay to catch immediate bind failures before reporting ready
        sleep(Duration::from_millis(100)).await;

        // Mark system as ready — /api/health/ready will now return {"ready": true}
        ready_flag_for_set.store(true, Ordering::SeqCst);

        // Notify systemd that we are ready (Type=notify)
        let _ = sd_notify::notify(true, &[NotifyState::Ready]);
        log!(SystemLog::FullInitComplete);

        // Start systemd watchdog keepalive task
        {
            let mut usec: u64 = 0;
            if sd_notify::watchdog_enabled(false, &mut usec) && usec > 0 {
                let notify_interval = Duration::from_micros(usec / 2);
                tokio::spawn(async move {
                    let mut tick = interval(notify_interval);
                    loop {
                        tick.tick().await;
                        let _ = sd_notify::notify(false, &[NotifyState::Watchdog]);
                    }
                });
            }
        }

        // Start Suricata subprocess supervisor (no-op if disabled in config).
        self.suricata_shutdown = Some(self.suricata_manager.clone().run());

        // Start Suricata eve.json monitor — tails the log file, translates
        // alert events into DetectionEvent on the shared mpsc. No-op if the
        // bridge is disabled in config.
        SuricataMonitor::new(self.app_config.clone(), suricata_detection_tx).start();

        // Wait for shutdown signal (ctrl-c OR API-triggered)
        tokio::select! {
            _ = ctrl_c() => {
                Ok(ShutdownMode::Shutdown)
            }
            mode = shutdown_rx.recv() => {
                Ok(mode.unwrap_or(ShutdownMode::Shutdown))
            }
        }
    }

    pub async fn terminate(&mut self) -> Result<(), Error> {
        let ebpf_services = self.ebpf_services.clone();
        let app_services = self.app_services.clone();
        log!(SystemLog::Terminating);

        if let Some(tx) = self.suricata_shutdown.take() {
            let _ = tx.send(());
        }
        ebpf_services.terminate();
        app_services.terminate();
        log!(SystemLog::TerminateComplete);
        Ok(())
    }

    /// Normalize ML model attack type names to SOAR playbook event names.
    fn normalize_attack_type(raw: &str) -> String {
        match raw {
            "Brute Force" => "brute_force".to_string(),
            "C2 Communication" => "c2_communication".to_string(),
            "DoS/DDoS" => "threat_detected".to_string(),
            "Exploitation" | "Malware" | "Web Attack" => "threat_detected".to_string(),
            "Bot" | "DNS Tunneling" => "threat_detected".to_string(),
            "Reconnaissance" => "port_scan".to_string(),
            "Normal" => "normal".to_string(),
            other => {
                log!(DetectionLog::UnknownMlAttackType(other.to_string()));
                "threat_detected".to_string()
            }
        }
    }

    /// Periodically check the drift detector and publish DriftDetectedEvent when drift is found.
    async fn run_drift_monitor(drift_detector: DriftDetectorHandle, comm: Arc<CommunicationManager>) {
        let mut interval = interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let report = drift_detector.check_drift().await;
            if let Some(report) = report {
                log!(SystemLog::DriftDetected(
                    report.drifted_features.len(),
                    report.max_deviation
                ));
                let event = DriftDetectedEvent {
                    drifted_features: report.drifted_features,
                    max_deviation: report.max_deviation,
                };
                if let Err(e) = comm.publish_event(event).await {
                    log!(SystemError::DriftEventPublishFailed(e));
                }
            }
        }
    }

    /// Thin ML bridge: converts AlertMessage → DetectionEvent and sends to orchestrator.
    /// Enrichment (GeoIP, hit count, repeat offender) is handled by the DetectionOrchestrator.
    async fn bridge_ml_to_detection(mut rx: Receiver<AlertMessage>, tx: Sender<DetectionEvent>) {
        log!(DetectionLog::MlBridgeStarted);

        loop {
            match rx.recv().await {
                Ok(alert) => {
                    let raw_type = alert.attack_type.as_deref().unwrap_or("unknown");
                    let normalized = Self::normalize_attack_type(raw_type);

                    // "Normal" class means benign — no SOAR trigger needed
                    if normalized == "normal" {
                        continue;
                    }

                    let event = DetectionEvent {
                        source: DetectionSource::ML,
                        attack_type: normalized,
                        confidence: alert.confidence,
                        source_ip: alert.src_ip,
                        dest_ip: alert.dst_ip,
                        protocol: alert.protocol,
                        packet_count: alert.packet_count,
                        flow_duration_us: alert.flow_duration_us,
                        ae_score: alert.ae_score,
                        anomaly_score: alert.anomaly_score,
                        c2_score: alert.c2_score,
                    };
                    if tx.send(event).await.is_err() {
                        break; // Orchestrator dropped
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    log!(DetectionLog::MlBridgeLagged(n));
                }
                Err(RecvError::Closed) => {
                    log!(DetectionLog::MlAlertChannelClosed);
                    break;
                }
            }
        }
    }

    /// Attempt to attach the XDP programs to the configured interfaces.
    /// If either attach fails, record the reason in `ebpf_health` and
    /// continue — the rest of the system keeps running.
    fn attach_ebpf(&mut self) -> Result<(), Error> {
        let ingress_ifname = self.app_config.network.ingress_ifname.clone();
        let egress_ifname = self.app_config.network.egress_ifname.clone();
        ServiceFactory::set_memory_limit()?;

        let (ingress, egress) = match (self.ingress_ebpf.as_mut(), self.egress_ebpf.as_mut()) {
            (Some(i), Some(e)) => (i, e),
            _ => return Ok(()),
        };

        let ingress_result = ServiceFactory::attach_xdp(ingress, &ingress_ifname, true);
        let egress_result = ServiceFactory::attach_xdp(egress, &egress_ifname, false);

        match (ingress_result, egress_result) {
            (Ok(ingress_mode), Ok(egress_mode)) => {
                if let Err(e) = self.db.set_setting("xdp_ingress_mode", &ingress_mode) {
                    log!(SystemError::XdpModeStoreFailed(e));
                }
                if let Err(e) = self.db.set_setting("xdp_egress_mode", &egress_mode) {
                    log!(SystemError::XdpModeStoreFailed(e));
                }
            }
            (ingress_res, egress_res) => {
                use crate::infrastructure::ebpf_preflight;
                use crate::model::system::health::EbpfFailStage;

                let (err, iface) = match (&ingress_res, &egress_res) {
                    (Err(e), _) => (e, ingress_ifname.as_str()),
                    (_, Err(e)) => (e, egress_ifname.as_str()),
                    _ => unreachable!("at least one branch is Err here"),
                };
                let health = ebpf_preflight::classify(EbpfFailStage::XdpAttach, err, Some(iface));
                log!(SystemLog::EbpfBringupFailed(format!("{:?}", health)));
                self.ebpf_health.store(Arc::new(health));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_brute_force() {
        assert_eq!(System::normalize_attack_type("Brute Force"), "brute_force");
    }

    #[test]
    fn normalize_c2_communication() {
        assert_eq!(System::normalize_attack_type("C2 Communication"), "c2_communication");
    }

    #[test]
    fn normalize_malware() {
        assert_eq!(System::normalize_attack_type("Malware"), "threat_detected");
    }

    #[test]
    fn normalize_bot() {
        assert_eq!(System::normalize_attack_type("Bot"), "threat_detected");
    }

    #[test]
    fn normalize_dns_tunneling() {
        assert_eq!(System::normalize_attack_type("DNS Tunneling"), "threat_detected");
    }

    #[test]
    fn normalize_dos_ddos() {
        assert_eq!(System::normalize_attack_type("DoS/DDoS"), "threat_detected");
    }

    #[test]
    fn normalize_exploitation() {
        assert_eq!(System::normalize_attack_type("Exploitation"), "threat_detected");
    }

    #[test]
    fn normalize_reconnaissance() {
        assert_eq!(System::normalize_attack_type("Reconnaissance"), "port_scan");
    }

    #[test]
    fn normalize_normal() {
        assert_eq!(System::normalize_attack_type("Normal"), "normal");
    }

    #[test]
    fn normalize_unknown_falls_back_to_threat_detected() {
        assert_eq!(System::normalize_attack_type("SomethingNew"), "threat_detected");
        assert_eq!(System::normalize_attack_type("unknown"), "threat_detected");
        assert_eq!(System::normalize_attack_type(""), "threat_detected");
    }
}
