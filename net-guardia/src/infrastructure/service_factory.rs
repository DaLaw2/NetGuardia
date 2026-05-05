use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::time::Duration;

use arc_swap::ArcSwap;
use aya::Ebpf;
use aya::maps::{Array, MapData, ProgramArray};
use aya::programs::{Xdp, XdpFlags};
use aya_log::EbpfLogger;
use common::define::pipeline::*;
use macros::log;
use tokio::sync::broadcast;

use crate::adapter::access_control::AccessControlAdapter;
use crate::adapter::ebpf::EbpfServices;
use crate::adapter::http::jwt::JwtService;
use crate::adapter::notification::smtp::SmtpClientFactory;
use crate::adapter::persistence::Database;
use crate::adapter::telegram::{TelegramAdapter, TelegramAdapterFactory};
use crate::core::common::config_service::ConfigService;
use crate::core::common::enforce_mode_handler::EnforceModeHandler;
use crate::core::common::notification_service::NotificationService;
use crate::core::common::statistics::FlowStatistics;
use crate::core::data_plane::acl_service::AclService;
use crate::core::data_plane::dns_filter::DnsFilter;
use crate::core::data_plane::dns_filter_service::DnsFilterService;
use crate::core::data_plane::rate_limit_service::RateLimitService;
use crate::core::identity::auth_service::AuthService;
use crate::core::inference::drift_detector::DriftDetectorHandle;
use crate::core::reporting::email_scheduler::ReportScheduler;
use crate::core::response::engine::{SoarEngine, SoarEngineDeps};
use crate::core::response::playbook_service::PlaybookService;
use crate::core::response::scheduler::TtlScheduler;
use crate::domain::common::config::AppConfig;
use crate::domain::common::config::constants::{EVENT_CHANNEL_CAPACITY, enforce_mode_to_u8};
use crate::domain::common::error::Error;
use crate::domain::common::error::misc::MiscError;
use crate::domain::common::event::{AuditEvent, DriftDetectedEvent, ThreatDetectedEvent};
use crate::domain::common::log::system::SystemLog;
use crate::domain::common::system::health::EbpfFailStage;
use crate::domain::common::system::health::EbpfHealth;
use crate::domain::data_plane::direction::FlowDirection;
use crate::domain::data_plane::error::EbpfError;
use crate::domain::data_plane::flow_stats::FlowStatsLimits;
use crate::domain::data_plane::list_type::ListType;
use crate::domain::data_plane::log::EbpfLog;
use crate::domain::detection::drift::FeatureBaselines;
use crate::domain::detection::log::MLLog;
use crate::domain::detection::manifest::ModelManifest;
use crate::domain::detection::ml_inference_config::MLInferenceConfig;
use crate::infrastructure::ebpf_preflight;
use crate::infrastructure::geoip::GeoIpService;
use crate::infrastructure::health::SystemHealth;
use crate::infrastructure::inference_runtime::InferenceRuntime;
use crate::infrastructure::runtime_state::RuntimeState;
use crate::infrastructure::secret_store::SecretStore;
use crate::infrastructure::suricata_manager::SuricataManager;
use crate::interface::access_control::AccessControlPort;
use crate::interface::access_control_admin::AccessControlAdminPort;
use crate::interface::app_repo::AppRepo;
use crate::interface::config_repo::ConfigRepo;
use crate::interface::dns_filter_api::DnsFilterPort;
use crate::interface::dns_query_filter::DnsQueryFilter;
use crate::interface::email_sender::EmailSenderFactory;
use crate::interface::enforcement::EnforcementRepo;
use crate::interface::geo_block_api::GeoBlockPort;
use crate::interface::geo_lookup::GeoLookup;
use crate::interface::notification::{AlertNotifier, AlertNotifierFactory};
use crate::interface::rate_limit_api::RateLimitPort;
use crate::interface::report_snapshot::ReportSnapshotRepo;
use crate::interface::secret_store::SecretStorePort;
use crate::interface::soar::SoarRepo;

pub struct AppState {
    pub app_config: Arc<ArcSwap<AppConfig>>,
    pub runtime_state: Arc<ArcSwap<RuntimeState>>,
    pub inference_config: Arc<MLInferenceConfig>,

    pub database: Arc<Database>,
    pub secret_store: Arc<SecretStore>,

    pub ebpf_services: Arc<EbpfServices>,
    pub ingress_ebpf: Option<Ebpf>,
    pub egress_ebpf: Option<Ebpf>,
    pub _ingress_program_array: Option<ProgramArray<MapData>>,
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
    pub ttl_scheduler: TtlScheduler,
    pub report_scheduler: ReportScheduler,
    pub geoip: Option<Arc<dyn GeoLookup>>,
    pub suricata_manager: Arc<SuricataManager>,

    pub threat_tx: broadcast::Sender<ThreatDetectedEvent>,
    pub audit_tx: broadcast::Sender<AuditEvent>,
    pub drift_tx: broadcast::Sender<DriftDetectedEvent>,
}

/// Maps stage name (from config.toml) to (function_name, stage_id).
fn stage_registry() -> HashMap<&'static str, (&'static str, u32)> {
    HashMap::from([
        ("access_control", ("access_control", STAGE_ACCESS_CONTROL)),
        ("rate_limit", ("rate_limit", STAGE_RATE_LIMIT)),
        ("service", ("protocol_filter", STAGE_SERVICE)),
    ])
}

struct EbpfBuild {
    ingress: Ebpf,
    egress: Ebpf,
    program_array: ProgramArray<MapData>,
    services: EbpfServices,
}

/// Factory responsible for creating and wiring all application services.
pub struct ServiceFactory;

impl ServiceFactory {
    /// Build all services. DB is passed in (already created by main.rs).
    /// Only called when setup is complete — all config values are in DB.
    pub async fn build(db: Arc<Database>) -> Result<AppState, Error> {
        // Ensure DB has all default config keys (INSERT OR IGNORE — never overwrites)
        AppConfig::seed_config_defaults(db.as_ref()).await?;
        let app_config = Arc::new(ArcSwap::from_pointee(AppConfig::from_config_repo(db.as_ref()).await?));
        let runtime_state = Arc::new(ArcSwap::from_pointee(RuntimeState::default()));

        // Prefer `models/manifest.yaml` when present (v12 BYO-model path). The manifest
        // is the user-authored source of truth for features, labels, thresholds, and
        // model filenames; the legacy JSON-only path is the fallback.
        let manifest_path = PathBuf::from("models/manifest.yaml");
        let (inference_config, ml_manifest): (Arc<MLInferenceConfig>, Option<ModelManifest>) = if manifest_path.exists()
        {
            let (cfg, manifest) = MLInferenceConfig::from_manifest_with_sidecar(&manifest_path)?;
            log!(MLLog::ManifestLoaded(
                manifest.name.clone(),
                manifest.adapter.as_str().to_string(),
                manifest.features.len(),
                manifest.labels.len(),
            ));
            (Arc::new(cfg), Some(manifest))
        } else {
            (
                Arc::new(MLInferenceConfig::load_file(&app_config.load().ml.models_config_name)?),
                None,
            )
        };

        // Shared eBPF health handle. Initialized Healthy; downgraded to
        // Unavailable with a classified reason if any stage below fails.
        let ebpf_health = Arc::new(ArcSwap::from_pointee(EbpfHealth::Healthy));

        // Attempt full eBPF bring-up. On any failure we classify the error,
        // write it into `ebpf_health`, and fall back to an `EbpfServices`
        // whose eBPF-backed operations return `EbpfError::NotLoaded`. The
        // rest of the system (HTTP API, SOAR, ML engine, auth) is built
        // regardless so the operator can still reach the frontend and see
        // the reason.
        let dns_filter = Arc::new(DnsFilter::new());
        let dns_query_filter: Arc<dyn DnsQueryFilter> = dns_filter.clone();
        let dns_filter_port: Arc<dyn DnsFilterPort> = dns_filter;

        let (ingress_ebpf, egress_ebpf, ingress_program_array, ebpf_services) =
            match Self::try_build_ebpf(&app_config, dns_query_filter.clone()) {
                Ok(build) => (
                    Some(build.ingress),
                    Some(build.egress),
                    Some(build.program_array),
                    Arc::new(build.services),
                ),
                Err((stage, err)) => {
                    let health = ebpf_preflight::classify(stage, &err, None);
                    log!(SystemLog::EbpfBringupFailed(format!("{:?}", health)));
                    ebpf_health.store(Arc::new(health));
                    (
                        None,
                        None,
                        None,
                        Arc::new(EbpfServices::unavailable(app_config.clone(), dns_query_filter)),
                    )
                }
            };

        let secret_store = Arc::new(SecretStore::new(db.clone()));
        let secret_store_port: Arc<dyn SecretStorePort> = secret_store.clone();

        let jwt_service = Arc::new(JwtService::new(
            &secret_store_port,
            app_config.load().http_server.jwt_expiry_hours,
        )?);

        let auth_service = Arc::new(AuthService::new(db.clone() as Arc<dyn AppRepo>, jwt_service.clone()));

        // Initialize ML drift detector from inference config baselines
        let baselines = FeatureBaselines::from_inference_config(&inference_config);
        let drift_cfg = app_config.load();
        let drift_window_secs = drift_cfg.ml.drift_window_secs;
        let drift_max_snapshots = drift_cfg.ml.drift_max_snapshots;
        let drift_channel_capacity = drift_cfg.ml.drift_channel_capacity;
        drop(drift_cfg);
        let drift_detector = DriftDetectorHandle::spawn(
            baselines,
            Duration::from_secs(drift_window_secs),
            drift_max_snapshots,
            drift_channel_capacity,
        );

        // Create AtomicU8 enforce-level cache (Monitor=0, MlOnly=1, Enforce=2)
        let enforce_level_cache = Arc::new(AtomicU8::new({
            let mode = app_config.load().system.enforce_mode.clone();
            enforce_mode_to_u8(&mode)
        }));

        // Named broadcast channels replace the old TypeId-based CommunicationManager.
        // They must exist before InferenceRuntime spins up the TrafficLogger: the writer
        // thread can publish `flow_trace_stopped` audit events the moment it tries
        // to open its first rotated file.
        let (threat_tx, _) = broadcast::channel::<ThreatDetectedEvent>(EVENT_CHANNEL_CAPACITY);
        let (audit_tx, _) = broadcast::channel::<AuditEvent>(EVENT_CHANNEL_CAPACITY);
        let (drift_tx, _) = broadcast::channel::<DriftDetectedEvent>(EVENT_CHANNEL_CAPACITY);

        let health = Arc::new(SystemHealth::new(app_config.clone(), ebpf_health.clone())?);

        let inference_runtime = Arc::new(InferenceRuntime::new(
            app_config.clone(),
            inference_config.clone(),
            ml_manifest.clone(),
            drift_detector.clone(),
            audit_tx.clone(),
        )?);

        let flow_stats_cfg = app_config.load();
        let flow_stats_limits = FlowStatsLimits::new(
            flow_stats_cfg.detection.flow_stats.max_snapshot_entries,
            flow_stats_cfg.detection.flow_stats.max_top_n,
        );
        drop(flow_stats_cfg);
        let flow_statistics = Arc::new(FlowStatistics::new(
            inference_runtime.ml_engine.clone(),
            flow_stats_limits,
        ));

        let enforce_handler = Arc::new(EnforceModeHandler::new(
            db.clone() as Arc<dyn AppRepo>,
            app_config.clone(),
            audit_tx.clone(),
            enforce_level_cache.clone(),
        ));

        // Seed default SOAR playbooks if empty
        (db.as_ref() as &dyn SoarRepo).seed_default_playbooks().await?;

        // Restore persisted state from database
        Self::restore_dns_blacklist(&db, dns_filter_port.as_ref()).await;
        Self::restore_geo_countries(&db, &ebpf_services).await;
        Self::restore_rate_limits(&db, &ebpf_services).await;
        Self::restore_acl_rules(&db, &ebpf_services).await;

        // Create TelegramAdapter as alert notifier (may fail if not configured yet)
        let alert_notifier: Option<Arc<dyn AlertNotifier>> = match TelegramAdapter::new(
            db.clone() as Arc<dyn ConfigRepo + Send + Sync>,
            app_config.clone(),
            Some(secret_store_port.clone()),
        ) {
            Ok(adapter) => Some(Arc::new(adapter)),
            Err(e) => {
                log!(SystemLog::TelegramUnavailable(e.to_string()));
                None
            }
        };

        // Try to initialize GeoIP service
        let acl_cfg = app_config.load().acl.clone();
        let geoip: Option<Arc<dyn GeoLookup>> =
            match GeoIpService::with_cache_size(&acl_cfg.geoip_db_path, acl_cfg.geoip_cache_capacity) {
                Ok(svc) => {
                    log!(SystemLog::GeoIpInitialized);
                    Some(Arc::new(svc))
                }
                Err(e) => {
                    log!(SystemLog::GeoIpUnavailable(e.to_string()));
                    None
                }
            };

        // Create AccessControlPort adapter for SOAR/TTL (decoupled from eBPF)
        let access_control_port: Arc<dyn AccessControlPort> =
            Arc::new(AccessControlAdapter::new(ebpf_services.access_control.clone()));

        let email_sender_factory: Arc<dyn EmailSenderFactory> = Arc::new(SmtpClientFactory);

        // Create SOAR engine
        let rate_limit_port: Arc<dyn RateLimitPort> = ebpf_services.rate_limit.clone();
        let soar_engine = Arc::new(
            SoarEngine::new(SoarEngineDeps {
                db: db.clone(),
                config: app_config.clone(),
                access_control: access_control_port.clone(),
                alert_notifier: alert_notifier.clone(),
                geoip: geoip.clone(),
                rate_limit: Some(rate_limit_port.clone()),
                enforce_level_cache,
                secrets: Some(secret_store_port.clone()),
                email_sender_factory: email_sender_factory.clone(),
            })
            .await?,
        );

        // Create TTL scheduler
        let ttl_scheduler = TtlScheduler::new(db.clone(), access_control_port.clone(), soar_engine.clone());

        // Create Report scheduler
        let report_scheduler = ReportScheduler::new(
            db.clone() as Arc<dyn ReportSnapshotRepo>,
            app_config.clone(),
            Some(secret_store_port.clone()),
            email_sender_factory.clone(),
        );

        // Create domain services (Phase 2B) — upcast concrete eBPF services to
        // their port-layer traits so the core services see only abstract ports.
        let access_control_admin: Arc<dyn AccessControlAdminPort> = ebpf_services.access_control.clone();
        let geo_block_port: Arc<dyn GeoBlockPort> = ebpf_services.geo_block.clone();
        let acl_service = Arc::new(AclService::new(
            db.clone() as Arc<dyn AppRepo>,
            access_control_admin,
            geo_block_port,
        ));
        let dns_filter_service = Arc::new(DnsFilterService::new(
            db.clone() as Arc<dyn EnforcementRepo>,
            dns_filter_port,
            app_config.clone(),
        ));
        let rate_limit_service = Arc::new(RateLimitService::new(db.clone() as Arc<dyn AppRepo>, rate_limit_port));
        let playbook_service = Arc::new(PlaybookService::new(
            db.clone(),
            soar_engine.clone(),
            access_control_port,
        ));
        let config_service = Arc::new(
            ConfigService::new(db.clone() as Arc<dyn AppRepo>, app_config.clone())
                .with_secret_store(secret_store_port.clone()),
        );
        let notifier_factory: Arc<dyn AlertNotifierFactory> = Arc::new(TelegramAdapterFactory::new(
            db.clone() as Arc<dyn ConfigRepo + Send + Sync>,
            app_config.clone(),
            Some(secret_store_port.clone()),
        ));
        let notification_service = Arc::new(NotificationService::new(
            db.clone() as Arc<dyn ConfigRepo + Send + Sync>,
            app_config.clone(),
            secret_store_port,
            notifier_factory,
            email_sender_factory,
        ));

        let suricata_manager = SuricataManager::new(app_config.clone());

        Ok(AppState {
            app_config,
            runtime_state,
            inference_config,

            database: db,
            secret_store,

            ebpf_services,
            ingress_ebpf,
            egress_ebpf,
            _ingress_program_array: ingress_program_array,
            ebpf_health,
            inference_runtime,
            health,
            flow_statistics,
            drift_detector,

            jwt_service,
            auth_service,
            enforce_handler,

            acl_service,
            config_service,
            dns_filter_service,
            notification_service,
            playbook_service,
            rate_limit_service,
            soar_engine,
            ttl_scheduler,
            report_scheduler,
            geoip,
            suricata_manager,

            threat_tx,
            audit_tx,
            drift_tx,
        })
    }

    // --- eBPF loading helpers ---

    /// Attempt the full eBPF bring-up chain: load both .o files, configure the
    /// ingress pipeline, write queue counts, and hand out map handles to the
    /// services. Returns the original stage on the first failure so the
    /// classifier can render targeted diagnostics.
    fn try_build_ebpf(
        app_config: &Arc<ArcSwap<AppConfig>>,
        dns_query_filter: Arc<dyn DnsQueryFilter>,
    ) -> Result<EbpfBuild, (EbpfFailStage, Error)> {
        let mut ingress = Self::load_ebpf("ingress").map_err(|e| (EbpfFailStage::Load, e))?;
        let mut egress = Self::load_ebpf("egress").map_err(|e| (EbpfFailStage::Load, e))?;

        let config = app_config.load();
        let pipeline = Self::configure_ingress_pipeline(&mut ingress, &config.pipeline.ingress)
            .map_err(|e| (EbpfFailStage::PipelineSetup, e))?;

        let num_queues = config.ebpf.combined_queue_count;
        drop(config);
        Self::write_num_queues(&mut ingress, num_queues).map_err(|e| (EbpfFailStage::PipelineSetup, e))?;
        Self::write_num_queues(&mut egress, num_queues).map_err(|e| (EbpfFailStage::PipelineSetup, e))?;

        let services = EbpfServices::new(app_config.clone(), &mut ingress, &mut egress, dns_query_filter)
            .map_err(|e| (EbpfFailStage::MapsBind, e))?;

        Ok(EbpfBuild {
            ingress,
            egress,
            program_array: pipeline,
            services,
        })
    }

    fn load_ebpf(name: &str) -> Result<Ebpf, Error> {
        let bytes = match name {
            "ingress" => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/net-guardia-ingress")),
            "egress" => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/net-guardia-egress")),
            _ => Err(EbpfError::ProgramNotFound)?,
        };
        Ok(Ebpf::load(bytes).map_err(EbpfError::EbpfNotFound)?)
    }

    fn configure_ingress_pipeline(ebpf: &mut Ebpf, stages: &[String]) -> Result<ProgramArray<MapData>, Error> {
        let registry = stage_registry();

        let entry: &mut Xdp = ebpf
            .program_mut("net_guardia")
            .ok_or(EbpfError::ProgramNotFound)?
            .try_into()
            .map_err(EbpfError::GetProgramFailed)?;
        entry.load().map_err(EbpfError::LoadProgramFailed)?;

        let pa_map = ebpf.take_map("PROGRAM_ARRAY").ok_or(EbpfError::MapNotFound)?;
        let mut program_array = ProgramArray::try_from(pa_map).map_err(EbpfError::MapOperationError)?;

        let ns_map = ebpf.take_map("NEXT_STAGE").ok_or(EbpfError::MapNotFound)?;
        let mut next_stage = Array::<MapData, u32>::try_from(ns_map).map_err(EbpfError::MapOperationError)?;

        Self::load_program(ebpf, &mut program_array, "transmission", STAGE_TRANSMISSION)?;

        if stages.is_empty() {
            next_stage
                .set(STAGE_ENTRY, STAGE_TRANSMISSION, 0)
                .map_err(EbpfError::MapOperationError)?;
            return Ok(program_array);
        }

        let mut slots: Vec<(u32, u32)> = Vec::new();
        for (i, stage_name) in stages.iter().enumerate() {
            let (func_name, stage_id) = registry.get(stage_name.as_str()).ok_or(EbpfError::ProgramNotFound)?;
            let slot = (i + 1) as u32;
            Self::load_program(ebpf, &mut program_array, func_name, slot)?;
            slots.push((*stage_id, slot));
        }

        next_stage
            .set(STAGE_ENTRY, slots[0].1, 0)
            .map_err(EbpfError::MapOperationError)?;

        for i in 0..slots.len() {
            let (stage_id, _) = slots[i];
            let next_slot = if i + 1 < slots.len() {
                slots[i + 1].1
            } else {
                STAGE_TRANSMISSION
            };
            next_stage
                .set(stage_id, next_slot, 0)
                .map_err(EbpfError::MapOperationError)?;
        }

        Ok(program_array)
    }

    fn load_program(
        ebpf: &mut Ebpf,
        program_array: &mut ProgramArray<MapData>,
        function_name: &str,
        slot: u32,
    ) -> Result<(), Error> {
        let program: &mut Xdp = ebpf
            .program_mut(function_name)
            .ok_or(EbpfError::ProgramNotFound)?
            .try_into()
            .map_err(EbpfError::MapOperationError)?;
        program.load().map_err(EbpfError::AttachProgramFailed)?;
        let fd = program.fd().map_err(EbpfError::ProgramFdFailed)?;
        program_array.set(slot, fd, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    fn write_num_queues(ebpf: &mut Ebpf, num_queues: u32) -> Result<(), Error> {
        let map = ebpf.map_mut("NUM_QUEUES").ok_or(EbpfError::MapNotFound)?;
        let mut arr = Array::<_, u32>::try_from(map).map_err(EbpfError::MapOperationError)?;
        arr.set(0, num_queues, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    pub fn set_memory_limit() -> Result<(), Error> {
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            Err(MiscError::RamLimitUnlockError(ret))?
        }
        Ok(())
    }

    pub fn attach_xdp(ebpf: &mut Ebpf, ifname: &str, already_loaded: bool) -> Result<String, Error> {
        let xdp: &mut Xdp = ebpf
            .program_mut("net_guardia")
            .ok_or(EbpfError::ProgramNotFound)?
            .try_into()
            .map_err(EbpfError::GetProgramFailed)?;
        if !already_loaded {
            xdp.load().map_err(EbpfError::LoadProgramFailed)?;
        }

        // Try DRV_MODE first (native XDP, best performance)
        match xdp.attach(ifname, XdpFlags::DRV_MODE) {
            Ok(_) => {
                log!(EbpfLog::XdpAttachedNative(ifname.to_string()));
                return Ok("drv".to_string());
            }
            Err(drv_err) => {
                log!(EbpfLog::XdpDrvModeFailed(ifname.to_string(), drv_err.to_string()));
            }
        }

        // Fallback to SKB_MODE (generic XDP, reduced performance)
        match xdp.attach(ifname, XdpFlags::SKB_MODE) {
            Ok(_) => {
                log!(EbpfLog::XdpAttachedSkb(ifname.to_string()));
                Ok("skb".to_string())
            }
            Err(skb_err) => {
                log!(EbpfLog::XdpAttachFailed(ifname.to_string(), skb_err.to_string()));
                Err(EbpfError::AttachProgramFailed(skb_err))?
            }
        }
    }

    pub fn aya_log_init(ingress_ebpf: &mut Ebpf, egress_ebpf: &mut Ebpf) -> Result<(), Error> {
        EbpfLogger::init(ingress_ebpf).map_err(EbpfError::LoggerInitFailed)?;
        EbpfLogger::init(egress_ebpf).map_err(EbpfError::LoggerInitFailed)?;
        Ok(())
    }

    // --- State restoration helpers ---

    async fn restore_dns_blacklist(db: &Database, dns_filter_port: &dyn DnsFilterPort) {
        if let Ok(domains) = db.load_dns_domains().await {
            for domain in &domains {
                if let Err(e) = dns_filter_port.add_domain(domain) {
                    log!(SystemLog::DnsRestoreFailed(domain.clone(), e.to_string()));
                }
            }
            if !domains.is_empty() {
                log!(SystemLog::DnsBlacklistRestored(domains.len()));
            }
        }
    }

    async fn restore_geo_countries(db: &Database, ebpf_services: &EbpfServices) {
        if let Ok(countries) = db.load_geo_countries().await
            && !countries.is_empty()
        {
            if let Err(e) = ebpf_services.geo_block.block_countries(&countries) {
                log!(SystemLog::GeoRestoreFailed(e.to_string()));
            } else {
                log!(SystemLog::GeoCountriesRestored(countries.len()));
            }
        }
    }

    async fn restore_rate_limits(db: &Database, ebpf_services: &EbpfServices) {
        if let Ok(configs) = db.load_rate_limit_config().await {
            for (key, value) in &configs {
                let result = match key.as_str() {
                    "packet_rate" => ebpf_services.rate_limit.set_packet_rate(*value),
                    "syn_rate" => ebpf_services.rate_limit.set_syn_rate(*value),
                    "udp_rate" => ebpf_services.rate_limit.set_udp_rate(*value),
                    "dns_rate" => ebpf_services.rate_limit.set_dns_rate(*value),
                    "window_ns" => ebpf_services.rate_limit.set_window_ns(*value),
                    _ => Ok(()),
                };
                if let Err(e) = result {
                    log!(SystemLog::RateLimitRestoreFailed(key.clone(), e.to_string()));
                }
            }
            if !configs.is_empty() {
                log!(SystemLog::RateLimitsRestored(configs.len()));
            }
        }
    }

    async fn restore_acl_rules(db: &Database, ebpf_services: &EbpfServices) {
        if let Ok(rules) = db.list_acl_rules().await {
            let mut restored = 0u32;
            for rule in &rules {
                let dir = match rule.direction.as_str() {
                    "source" => FlowDirection::Source,
                    "destination" => FlowDirection::Destination,
                    other => {
                        log!(SystemLog::AclUnknownDirection(other.to_string()));
                        continue;
                    }
                };
                let lt = match rule.list_type.as_str() {
                    "whitelist" => ListType::White,
                    "blacklist" => ListType::Black,
                    other => {
                        log!(SystemLog::AclUnknownListType(other.to_string()));
                        continue;
                    }
                };
                let result = match rule.ip_version {
                    4 => match rule.ip_address.parse::<Ipv4Addr>() {
                        Ok(addr) => {
                            ebpf_services
                                .access_control
                                .add_ipv4_list(dir, lt, SocketAddrV4::new(addr, rule.port))
                        }
                        Err(e) => {
                            log!(SystemLog::AclIpv4ParseFailed(rule.ip_address.clone(), e.to_string()));
                            continue;
                        }
                    },
                    6 => match rule.ip_address.parse::<Ipv6Addr>() {
                        Ok(addr) => ebpf_services.access_control.add_ipv6_list(
                            dir,
                            lt,
                            SocketAddrV6::new(addr, rule.port, 0, 0),
                        ),
                        Err(e) => {
                            log!(SystemLog::AclIpv6ParseFailed(rule.ip_address.clone(), e.to_string()));
                            continue;
                        }
                    },
                    other => {
                        log!(SystemLog::AclUnknownIpVersion(other));
                        continue;
                    }
                };
                if let Err(e) = result {
                    log!(SystemLog::AclRuleRestoreFailed(
                        rule.direction.clone(),
                        rule.list_type.clone(),
                        rule.ip_address.clone(),
                        rule.port,
                        e.to_string()
                    ));
                } else {
                    restored += 1;
                }
            }
            if restored > 0 {
                log!(SystemLog::AclRulesRestored(restored as usize));
            }
        }
    }
}
