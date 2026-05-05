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
use tokio::sync::broadcast;
use tokio::sync::mpsc::{self, Sender};
use tokio::sync::oneshot;
use tokio::time::interval;

use crate::adapter::ebpf::EbpfServices;
use crate::adapter::http::jwt::JwtService;
use crate::adapter::persistence::Database;
use crate::core::common::config_service::ConfigService;
use crate::core::common::enforce_mode_handler::EnforceModeHandler;
use crate::core::common::notification_service::NotificationService;
use crate::core::common::statistics::FlowStatistics;
use crate::core::correlation::engine::CorrelationEngine;
use crate::core::data_plane::acl_service::AclService;
use crate::core::data_plane::dns_filter_service::DnsFilterService;
use crate::core::data_plane::rate_limit_service::RateLimitService;
use crate::core::detection::beaconing::BeaconingDetector;
use crate::core::detection::orchestrator::DetectionOrchestrator;
use crate::core::detection::orchestrator::bridge_ml_to_detection;
use crate::core::identity::auth_service::AuthService;
use crate::core::inference::drift_detector::{DriftDetectorHandle, run_drift_monitor};
use crate::core::inference::model_watcher::ModelWatcher;
use crate::core::reporting::email_scheduler::ReportScheduler;
use crate::core::reporting::stats_aggregator::StatsAggregator;
use crate::core::response::engine::SoarEngine;
use crate::core::response::playbook_service::PlaybookService;
use crate::core::response::scheduler::TtlScheduler;
use crate::domain::common::config::AppConfig;
use crate::domain::common::config::constants::{MODELS_DIR, STAGING_SUBDIR};
use crate::domain::common::error::Error;
use crate::domain::common::error::system::SystemError;
use crate::domain::common::event::AuditEvent;
use crate::domain::common::event::{DetectionEvent, DriftDetectedEvent, ThreatDetectedEvent};
use crate::domain::common::log::system::SystemLog;
use crate::domain::common::system::health::EbpfFailStage;
use crate::domain::common::system::health::EbpfHealth;
use crate::domain::detection::log::MLLog;
use crate::domain::detection::ml_inference_config::MLInferenceConfig;
use crate::infrastructure::audit_logger::AuditLogger;
use crate::infrastructure::ebpf_preflight;
use crate::infrastructure::health::SystemHealth;
use crate::infrastructure::http_server::{self, ForceHttpsFlag, HttpServerParams, ReadyFlag, SetupCompleteFlag};
use crate::infrastructure::inference_runtime::InferenceRuntime;
use crate::infrastructure::log_buffer::LogBuffer;
use crate::infrastructure::logger::Logger;
use crate::infrastructure::readiness::ReadinessState;
use crate::infrastructure::runtime_state::RuntimeState;
use crate::infrastructure::secret_store::SecretStore;
use crate::infrastructure::service_factory::ServiceFactory;
use crate::infrastructure::suricata_manager::SuricataManager;
use crate::infrastructure::suricata_monitor::SuricataMonitor;
use crate::interface::audit::AuditRepo;
use crate::interface::geo_lookup::GeoLookup;
use crate::interface::packet_sink::PacketSinkFactory;
use crate::interface::report_snapshot::ReportSnapshotRepo;
use crate::interface::stats::StatsRepo;
use crate::utils::staging;

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

pub struct System {
    pub app_config: Arc<ArcSwap<AppConfig>>,
    pub runtime_state: Arc<ArcSwap<RuntimeState>>,
    pub inference_config: Arc<MLInferenceConfig>,

    pub database: Arc<Database>,
    pub secret_store: Arc<SecretStore>,

    pub ebpf_services: Arc<EbpfServices>,
    pub ingress_ebpf: Option<Ebpf>,
    pub egress_ebpf: Option<Ebpf>,
    _ingress_program_array: Option<ProgramArray<MapData>>,
    pub ebpf_health: Arc<ArcSwap<EbpfHealth>>,
    pub inference_runtime: Arc<InferenceRuntime>,
    pub health: Arc<SystemHealth>,
    pub flow_statistics: Arc<FlowStatistics>,
    pub drift_detector: DriftDetectorHandle,

    pub jwt_service: Arc<JwtService>,
    pub auth_service: Arc<AuthService>,
    pub enforce_handler: Arc<EnforceModeHandler>,

    pub acl_service: Arc<AclService>,
    pub config_service: Arc<ConfigService>,
    pub dns_filter_service: Arc<DnsFilterService>,
    pub notification_service: Arc<NotificationService>,
    pub playbook_service: Arc<PlaybookService>,
    pub rate_limit_service: Arc<RateLimitService>,
    pub soar_engine: Arc<SoarEngine>,
    pub ttl_scheduler: Option<TtlScheduler>,
    pub report_scheduler: Option<ReportScheduler>,
    pub geoip: Option<Arc<dyn GeoLookup>>,
    pub suricata_manager: Arc<SuricataManager>,

    pub threat_tx: broadcast::Sender<ThreatDetectedEvent>,
    pub audit_tx: broadcast::Sender<AuditEvent>,
    pub drift_tx: broadcast::Sender<DriftDetectedEvent>,

    readiness_state: Arc<ReadinessState>,
    pub shutdown_handle: Option<Arc<ShutdownHandle>>,
    health_shutdown: Option<oneshot::Sender<()>>,
    suricata_shutdown: Option<oneshot::Sender<()>>,
}

impl System {
    pub async fn new(database: Arc<Database>) -> Result<Self, Error> {
        let state = ServiceFactory::build(database).await?;
        Ok(System {
            app_config: state.app_config,
            runtime_state: state.runtime_state,
            inference_config: state.inference_config,

            database: state.database,
            secret_store: state.secret_store,

            ebpf_services: state.ebpf_services,
            ingress_ebpf: state.ingress_ebpf,
            egress_ebpf: state.egress_ebpf,
            _ingress_program_array: state._ingress_program_array,
            ebpf_health: state.ebpf_health,
            inference_runtime: state.inference_runtime,
            health: state.health,
            flow_statistics: state.flow_statistics,
            drift_detector: state.drift_detector,

            jwt_service: state.jwt_service,
            auth_service: state.auth_service,
            enforce_handler: state.enforce_handler,

            acl_service: state.acl_service,
            config_service: state.config_service,
            dns_filter_service: state.dns_filter_service,
            notification_service: state.notification_service,
            playbook_service: state.playbook_service,
            rate_limit_service: state.rate_limit_service,
            soar_engine: state.soar_engine,
            ttl_scheduler: Some(state.ttl_scheduler),
            report_scheduler: Some(state.report_scheduler),
            geoip: state.geoip,
            suricata_manager: state.suricata_manager,

            threat_tx: state.threat_tx,
            audit_tx: state.audit_tx,
            drift_tx: state.drift_tx,

            readiness_state: {
                let rs = Arc::new(ReadinessState::new());
                rs.db_connected.store(true, Ordering::SeqCst);
                rs
            },
            shutdown_handle: None,
            health_shutdown: None,
            suricata_shutdown: None,
        })
    }

    pub async fn run(&mut self, logger: Arc<Logger>, log_buffer: Arc<LogBuffer>) -> Result<ShutdownMode, Error> {
        log!(SystemLog::Initializing);
        self.boot_ebpf().await?;
        self.boot_inference().await?;
        self.boot_response().await?;
        let suricata_detection_tx = self.boot_detection();
        self.boot_observability().await;
        let mut shutdown_rx = self.boot_http_server(logger, log_buffer).await;
        self.boot_external(suricata_detection_tx);

        tokio::select! {
            _ = ctrl_c() => Ok(ShutdownMode::Shutdown),
            mode = shutdown_rx.recv() => Ok(mode.unwrap_or(ShutdownMode::Shutdown)),
        }
    }

    async fn boot_ebpf(&mut self) -> Result<(), Error> {
        if let (Some(ingress), Some(egress)) = (self.ingress_ebpf.as_mut(), self.egress_ebpf.as_mut()) {
            if let Err(err) = ServiceFactory::aya_log_init(ingress, egress) {
                let health = ebpf_preflight::classify(EbpfFailStage::LoggerInit, &err, None);
                log!(SystemLog::EbpfBringupFailed(format!("{:?}", health)));
            }
            log!(SystemLog::InitializeComplete);
            self.attach_ebpf().await?;
        } else {
            log!(SystemLog::InitializeComplete);
        }

        let sink_factory: Arc<dyn PacketSinkFactory> = self.inference_runtime.ml_engine.clone();
        if let Err(err) = self.ebpf_services.clone().run(sink_factory).await {
            let cfg = self.app_config.load();
            let iface = cfg.ebpf.ingress_ifname.as_str();
            let health = ebpf_preflight::classify(EbpfFailStage::AfXdpBind, &err, Some(iface));
            log!(SystemLog::EbpfBringupFailed(format!("{:?}", health)));
            self.ebpf_health.store(Arc::new(health));
        }

        self.readiness_state
            .ebpf_attached
            .store(self.ingress_ebpf.is_some(), Ordering::SeqCst);
        Ok(())
    }

    async fn boot_inference(&self) -> Result<(), Error> {
        self.inference_runtime.run().await?;
        self.readiness_state
            .ml_model_loaded
            .store(self.inference_runtime.ml_inference.is_active(), Ordering::SeqCst);
        Ok(())
    }

    async fn boot_response(&mut self) -> Result<(), Error> {
        self.soar_engine.recover_active_blocks().await?;
        self.soar_engine.clone().start(self.threat_tx.subscribe());
        self.readiness_state.soar_engine_running.store(true, Ordering::SeqCst);

        if let Some(ttl) = self.ttl_scheduler.take() {
            ttl.start();
        }

        Ok(())
    }

    fn boot_detection(&self) -> Sender<DetectionEvent> {
        let ml_alert_rx = self.inference_runtime.ml_alert.subscribe_to_alerts();

        let (detection_tx, detection_rx) = mpsc::channel::<DetectionEvent>(1024);
        let orchestrator = DetectionOrchestrator::new(
            &self.app_config,
            detection_rx,
            self.threat_tx.clone(),
            self.audit_tx.clone(),
            self.geoip.clone(),
            self.inference_runtime.fusion_metrics.clone(),
        );
        orchestrator.start();

        let correlation_alert_rx = self.inference_runtime.ml_alert.subscribe_to_alerts();
        let correlation_engine = CorrelationEngine::new(&self.app_config, correlation_alert_rx, detection_tx.clone());
        correlation_engine.start();

        let beaconing_alert_rx = self.inference_runtime.ml_alert.subscribe_to_alerts();
        let beaconing_detector = BeaconingDetector::new(&self.app_config, beaconing_alert_rx, detection_tx.clone());
        beaconing_detector.start();

        let suricata_detection_tx = detection_tx.clone();

        tokio::spawn(bridge_ml_to_detection(ml_alert_rx, detection_tx));

        let staging_root = PathBuf::from(MODELS_DIR).join(STAGING_SUBDIR);
        match staging::clean_staging_orphans(&staging_root, Duration::from_secs(3600)) {
            Ok(0) => {}
            Ok(n) => log!(SystemLog::StagingOrphansCleaned(n as u64)),
            Err(e) => log!(SystemLog::StagingOrphansSweepFailed(e.to_string())),
        }

        let status = self.inference_runtime.ml_inference.model_source_status();
        match serde_json::to_string(&status) {
            Ok(s) => log!(MLLog::ModelsLoaded(s)),
            Err(e) => log!(MLLog::ModelsLoaded(format!("<unserializable status: {e}>"))),
        }
        log!(MLLog::ConfigLoaded(
            self.inference_config.num_ae_features(),
            self.inference_config.num_attack_types(),
        ));

        let model_watcher = ModelWatcher::new(self.inference_runtime.ml_inference.clone(), self.app_config.clone());
        model_watcher.start();

        suricata_detection_tx
    }

    async fn boot_observability(&mut self) {
        let monitoring_interval_secs = self.app_config.load().health.monitoring_interval_secs;
        let health_shutdown = self
            .health
            .clone()
            .run(Duration::from_secs(monitoring_interval_secs))
            .await;
        self.health_shutdown = Some(health_shutdown);

        let audit_logger = Arc::new(AuditLogger::new(self.database.clone() as Arc<dyn AuditRepo>));
        audit_logger.start(self.audit_tx.subscribe(), self.drift_tx.subscribe());

        let health_query: Arc<dyn crate::interface::health_query::HealthQuery> = self.health.clone();
        let stats_aggregator = StatsAggregator::new(
            self.database.clone() as Arc<dyn StatsRepo>,
            self.database.clone() as Arc<dyn ReportSnapshotRepo>,
            health_query,
        );
        stats_aggregator.start();

        let drift_detector = self.drift_detector.clone();
        let drift_tx = self.drift_tx.clone();
        tokio::spawn(async move {
            run_drift_monitor(drift_detector, drift_tx).await;
        });

        if let Some(report) = self.report_scheduler.take() {
            report.run();
        }
    }

    async fn boot_http_server(
        &mut self,
        logger: Arc<Logger>,
        log_buffer: Arc<LogBuffer>,
    ) -> mpsc::Receiver<ShutdownMode> {
        let force_https = ForceHttpsFlag(Arc::new(AtomicBool::new(
            self.app_config.load().http_server.force_https,
        )));

        let readiness_state = self.readiness_state.clone();

        let (shutdown_tx, shutdown_rx) = mpsc::channel::<ShutdownMode>(1);
        let shutdown_handle = Arc::new(ShutdownHandle::new(shutdown_tx));
        self.shutdown_handle = Some(shutdown_handle.clone());

        let ready_flag = ReadyFlag(Arc::new(AtomicBool::new(false)));
        let ready_flag_for_set = ready_flag.0.clone();
        let params = HttpServerParams {
            app_config: self.app_config.clone(),
            runtime_state: self.runtime_state.clone(),
            inference_config: self.inference_config.clone(),

            database: self.database.clone(),
            secret_store: self.secret_store.clone(),
            logger,
            log_buffer,

            ebpf_services: self.ebpf_services.clone(),
            inference_runtime: self.inference_runtime.clone(),
            health: self.health.clone(),
            flow_statistics: self.flow_statistics.clone(),

            jwt_service: self.jwt_service.clone(),
            auth_service: self.auth_service.clone(),
            enforce_handler: self.enforce_handler.clone(),

            acl_service: self.acl_service.clone(),
            config_service: self.config_service.clone(),
            dns_filter_service: self.dns_filter_service.clone(),
            notification_service: self.notification_service.clone(),
            playbook_service: self.playbook_service.clone(),
            rate_limit_service: self.rate_limit_service.clone(),
            soar_engine: self.soar_engine.clone(),
            suricata_manager: self.suricata_manager.clone(),

            threat_tx: self.threat_tx.clone(),
            audit_tx: self.audit_tx.clone(),

            setup_complete: SetupCompleteFlag(Arc::new(AtomicBool::new(true))),
            ready: ready_flag,
            readiness_state,
            force_https,
            shutdown_handle: shutdown_handle.clone(),
        };

        let ready_for_http = ready_flag_for_set.clone();
        actix::spawn(async move {
            if let Err(e) = http_server::run(params).await {
                ready_for_http.store(false, Ordering::SeqCst);
                log!(SystemError::HttpServerError(e));
            }
        });

        ready_flag_for_set.store(true, Ordering::SeqCst);
        let _ = sd_notify::notify(true, &[NotifyState::Ready]);
        log!(SystemLog::FullInitComplete);

        shutdown_rx
    }

    fn boot_external(&mut self, suricata_detection_tx: Sender<DetectionEvent>) {
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

        self.suricata_shutdown = Some(self.suricata_manager.clone().run());
        SuricataMonitor::new(self.app_config.clone(), suricata_detection_tx).start();
    }

    pub async fn terminate(&mut self) -> Result<(), Error> {
        let ebpf_services = self.ebpf_services.clone();
        let inference_runtime = self.inference_runtime.clone();
        log!(SystemLog::Terminating);
        if let Some(tx) = self.health_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.suricata_shutdown.take() {
            let _ = tx.send(());
        }
        ebpf_services.terminate();
        inference_runtime.terminate();
        log!(SystemLog::TerminateComplete);
        Ok(())
    }

    async fn attach_ebpf(&mut self) -> Result<(), Error> {
        let cfg = self.app_config.load();
        let ingress_ifname = cfg.ebpf.ingress_ifname.clone();
        let egress_ifname = cfg.ebpf.egress_ifname.clone();
        ServiceFactory::set_memory_limit()?;

        let (ingress, egress) = match (self.ingress_ebpf.as_mut(), self.egress_ebpf.as_mut()) {
            (Some(i), Some(e)) => (i, e),
            _ => return Ok(()),
        };

        let ingress_result = ServiceFactory::attach_xdp(ingress, &ingress_ifname, true);
        let egress_result = ServiceFactory::attach_xdp(egress, &egress_ifname, false);

        match (ingress_result, egress_result) {
            (Ok(ingress_mode), Ok(egress_mode)) => {
                let mut next_state = (**self.runtime_state.load()).clone();
                next_state.xdp.ingress_mode = ingress_mode;
                next_state.xdp.egress_mode = egress_mode;
                self.runtime_state.store(Arc::new(next_state));
            }
            (ingress_res, egress_res) => {
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
