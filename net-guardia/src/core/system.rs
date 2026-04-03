use std::sync::Arc;

use aya::Ebpf;
use aya::maps::{MapData, ProgramArray};
use macros::log;

use crate::adapter::persistence::Database;
use crate::core::acl_service::AclService;
use crate::core::auth::jwt::JwtService;
use crate::core::config_service::ConfigService;
use crate::core::dns_filter_service::DnsFilterService;
use crate::core::ebpf::EbpfServices;
use crate::core::email::scheduler::ReportScheduler;
use crate::core::ml::config_loader::InferenceConfig;
use crate::core::ml::drift_detector::DriftDetector;
use crate::core::notification_service::NotificationService;
use crate::core::playbook_service::PlaybookService;
use crate::core::rate_limit_service::RateLimitService;
use crate::core::soar::engine::SoarEngine;
use crate::core::soar::scheduler::TtlScheduler;
use crate::infrastructure::app_config::AppConfig;
use crate::infrastructure::app_services::AppServices;
use crate::infrastructure::audit_logger::AuditLogger;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::infrastructure::geoip::GeoIpService;
use crate::infrastructure::http_server::HttpServerParams;
use crate::infrastructure::secret_store::SecretStore;
use crate::infrastructure::service_factory::ServiceFactory;
use crate::model::error::Error;
use crate::model::error::system::SystemError;
use crate::model::event::{DetectionEvent, DetectionSource, DriftDetectedEvent};
use crate::model::log::detection::DetectionLog;
use crate::model::log::ml::MLLog;
use crate::model::log::system::SystemLog;
use crate::model::ml_detection::AlertMessage;
use crate::model::system::readiness::ReadinessState;

/// API-triggered shutdown mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownMode {
    Shutdown,
    Restart,
}

/// Handle for triggering shutdown from HTTP endpoints.
/// Uses a parking_lot::Mutex<Option<oneshot::Sender>> so it can be shared as app_data.
pub struct ShutdownHandle {
    tx: parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<ShutdownMode>>>,
}

impl ShutdownHandle {
    fn new(tx: tokio::sync::oneshot::Sender<ShutdownMode>) -> Self {
        Self {
            tx: parking_lot::Mutex::new(Some(tx)),
        }
    }

    /// Trigger shutdown. Returns false if already triggered.
    pub fn trigger(&self, mode: ShutdownMode) -> bool {
        if let Some(tx) = self.tx.lock().take() {
            tx.send(mode).is_ok()
        } else {
            false
        }
    }
}

/// Orchestrates system lifecycle: startup ordering and shutdown.
/// Construction is delegated to `ServiceFactory::build()`.
/// Setup mode is handled by main.rs — System only runs when setup is complete.
pub struct System {
    pub app_config: Arc<AppConfig>,
    pub inference_config: Arc<InferenceConfig>,
    pub ebpf_services: Arc<EbpfServices>,
    pub app_services: Arc<AppServices>,
    pub db: Arc<Database>,
    pub secret_store: Arc<SecretStore>,
    pub jwt_service: Arc<JwtService>,
    pub comm: Arc<CommunicationManager>,
    pub soar_engine: Arc<SoarEngine>,
    pub ttl_scheduler: Option<TtlScheduler>,
    pub report_scheduler: Option<ReportScheduler>,
    pub ingress_ebpf: Ebpf,
    pub egress_ebpf: Ebpf,
    pub acl_service: Arc<AclService>,
    pub config_service: Arc<ConfigService>,
    pub dns_filter_service: Arc<DnsFilterService>,
    pub notification_service: Arc<NotificationService>,
    pub playbook_service: Arc<PlaybookService>,
    pub rate_limit_service: Arc<RateLimitService>,
    pub geoip: Option<Arc<GeoIpService>>,
    pub drift_detector: Arc<parking_lot::Mutex<DriftDetector>>,
    pub shutdown_handle: Option<Arc<ShutdownHandle>>,
    _ingress_program_array: ProgramArray<MapData>,
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
        })
    }

    /// Start all services and HTTP server. Setup is already complete at this point.
    /// Returns the shutdown mode requested (Shutdown or Restart).
    pub async fn run(&mut self) -> Result<ShutdownMode, Error> {
        log!(SystemLog::Initializing);

        log!(MLLog::ModelsLoaded(
            self.app_services.ml_models.get_model_info("deep_autoencoder")
        ));
        log!(MLLog::ModelsLoaded(
            self.app_services.ml_models.get_model_info("classifier")
        ));
        log!(MLLog::ConfigLoaded {
            features: self.inference_config.num_ae_features(),
            attacks: self.inference_config.num_attack_types()
        });

        ServiceFactory::aya_log_init(&mut self.ingress_ebpf, &mut self.egress_ebpf)?;
        log!(SystemLog::InitializeComplete);
        self.attach_ebpf()?;

        // Subscribe to ML alerts BEFORE starting services to avoid race condition
        let ml_alert_rx = self.app_services.ml_alert.subscribe_to_alerts();

        let ebpf_services = self.ebpf_services.clone();
        let app_services = self.app_services.clone();
        ebpf_services.run(app_services.ml_engine.clone()).await?;
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
        let audit_logger = Arc::new(AuditLogger::new(
            self.db.clone() as Arc<dyn crate::interface::port::audit::AuditPort>
        ));
        audit_logger.start(&self.comm);

        // Start stats aggregator (writes weekly_* settings for Report engine)
        let stats_aggregator = crate::core::stats_aggregator::StatsAggregator::new(
            self.db.clone() as Arc<dyn crate::interface::port::stats::StatsPort>,
            self.db.clone() as Arc<dyn crate::interface::port::repository::RepositoryPort>,
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
        let (detection_tx, detection_rx) = tokio::sync::mpsc::channel::<DetectionEvent>(1024);
        let orchestrator = crate::core::detection::orchestrator::DetectionOrchestrator::new(
            detection_rx,
            self.comm.clone(),
            self.geoip.clone(),
        );
        orchestrator.start();

        // Clone detection_tx for correlation engine and beaconing detector
        let correlation_detection_tx = detection_tx.clone();
        let beaconing_detection_tx = detection_tx.clone();

        // Start cross-flow correlation engine (botnet, scan, lateral movement detection)
        let correlation_alert_rx = self.app_services.ml_alert.subscribe_to_alerts();
        let correlation_engine =
            crate::core::correlation::engine::CorrelationEngine::new(correlation_alert_rx, correlation_detection_tx);
        correlation_engine.start();

        // Start temporal beaconing detector (CV-based C2 periodicity detection)
        let beaconing_alert_rx = self.app_services.ml_alert.subscribe_to_alerts();
        let beaconing_detector =
            crate::core::detection::beaconing::BeaconingDetector::new(beaconing_alert_rx, beaconing_detection_tx);
        beaconing_detector.start();

        // Bridge ML alerts → DetectionEvent (thin adapter, no enrichment)
        tokio::spawn(async move {
            Self::bridge_ml_to_detection(ml_alert_rx, detection_tx).await;
        });

        // Initialize force_https flag from DB setting
        let force_https = Arc::new(std::sync::atomic::AtomicBool::new(
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
        readiness_state
            .db_connected
            .store(true, std::sync::atomic::Ordering::SeqCst);
        readiness_state
            .ml_model_loaded
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // eBPF was attached above (self.attach_ebpf succeeded)
        readiness_state
            .ebpf_attached
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // SOAR engine started above (self.soar_engine.start succeeded)
        readiness_state
            .soar_engine_running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // Create shutdown channel for API-triggered shutdown/restart
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<ShutdownMode>();
        let shutdown_handle = Arc::new(ShutdownHandle::new(shutdown_tx));
        self.shutdown_handle = Some(shutdown_handle.clone());

        // Start HTTP server in background (!Send, use actix::spawn)
        let setup_flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let ready_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
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
        };
        let ready_for_http = ready_flag_for_set.clone();
        actix::spawn(async move {
            if let Err(e) = crate::infrastructure::http_server::run(params).await {
                // HTTP server failed — mark system as NOT ready so health checks fail
                ready_for_http.store(false, std::sync::atomic::Ordering::SeqCst);
                log!(SystemError::HttpServerError(e));
            }
        });

        // Brief delay to catch immediate bind failures before reporting ready
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Mark system as ready — /api/health/ready will now return {"ready": true}
        ready_flag_for_set.store(true, std::sync::atomic::Ordering::SeqCst);

        // Notify systemd that we are ready (Type=notify)
        let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);
        log!(SystemLog::FullInitComplete);

        // Start systemd watchdog keepalive task
        {
            let mut usec: u64 = 0;
            if sd_notify::watchdog_enabled(false, &mut usec) && usec > 0 {
                let notify_interval = std::time::Duration::from_micros(usec / 2);
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(notify_interval);
                    loop {
                        tick.tick().await;
                        let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
                    }
                });
            }
        }

        // Wait for shutdown signal (ctrl-c OR API-triggered)
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                Ok(ShutdownMode::Shutdown)
            }
            mode = shutdown_rx => {
                Ok(mode.unwrap_or(ShutdownMode::Shutdown))
            }
        }
    }

    pub async fn terminate(&self) -> Result<(), Error> {
        let ebpf_services = self.ebpf_services.clone();
        let app_services = self.app_services.clone();
        log!(SystemLog::Terminating);

        ebpf_services.terminate();
        app_services.terminate();
        log!(SystemLog::TerminateComplete);
        Ok(())
    }

    /// Normalize ML model attack type names to SOAR playbook event names.
    fn normalize_attack_type(raw: &str) -> String {
        match raw {
            "Brute Force" => "brute_force".to_string(),
            "DDoS" | "DoS" => "threat_detected".to_string(),
            "Exploitation" => "threat_detected".to_string(),
            "Reconnaissance" => "port_scan".to_string(),
            other => {
                log!(DetectionLog::UnknownMlAttackType(other.to_string()));
                "threat_detected".to_string()
            }
        }
    }

    /// Periodically check the drift detector and publish DriftDetectedEvent when drift is found.
    async fn run_drift_monitor(
        drift_detector: Arc<parking_lot::Mutex<DriftDetector>>,
        comm: Arc<CommunicationManager>,
    ) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let report = drift_detector.lock().check_drift();
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
    async fn bridge_ml_to_detection(
        mut rx: tokio::sync::broadcast::Receiver<AlertMessage>,
        tx: tokio::sync::mpsc::Sender<DetectionEvent>,
    ) {
        log!(DetectionLog::MlBridgeStarted);

        loop {
            match rx.recv().await {
                Ok(alert) => {
                    let event = DetectionEvent {
                        source: DetectionSource::ML,
                        attack_type: Self::normalize_attack_type(
                            &alert.attack_type.unwrap_or_else(|| "unknown".into()),
                        ),
                        confidence: alert.confidence,
                        source_ip: alert.src_ip,
                        dest_ip: alert.dst_ip,
                        protocol: alert.protocol,
                        packet_count: alert.packet_count,
                        flow_duration_us: alert.flow_duration_us,
                    };
                    if tx.send(event).await.is_err() {
                        break; // Orchestrator dropped
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    log!(DetectionLog::MlBridgeLagged(n));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    log!(DetectionLog::MlAlertChannelClosed);
                    break;
                }
            }
        }
    }

    fn attach_ebpf(&mut self) -> Result<(), Error> {
        let ingress_ifname = self.app_config.network.ingress_ifname.clone();
        let egress_ifname = self.app_config.network.egress_ifname.clone();
        ServiceFactory::set_memory_limit()?;

        let ingress_mode = ServiceFactory::attach_xdp(&mut self.ingress_ebpf, &ingress_ifname, true)?;
        let egress_mode = ServiceFactory::attach_xdp(&mut self.egress_ebpf, &egress_ifname, false)?;

        if let Err(e) = self.db.set_setting("xdp_ingress_mode", &ingress_mode) {
            log!(SystemError::XdpModeStoreFailed(e));
        }
        if let Err(e) = self.db.set_setting("xdp_egress_mode", &egress_mode) {
            log!(SystemError::XdpModeStoreFailed(e));
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
    fn normalize_ddos() {
        assert_eq!(System::normalize_attack_type("DDoS"), "threat_detected");
    }

    #[test]
    fn normalize_dos() {
        assert_eq!(System::normalize_attack_type("DoS"), "threat_detected");
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
    fn normalize_unknown_falls_back_to_threat_detected() {
        assert_eq!(System::normalize_attack_type("SomethingNew"), "threat_detected");
        assert_eq!(System::normalize_attack_type("unknown"), "threat_detected");
        assert_eq!(System::normalize_attack_type(""), "threat_detected");
    }
}
