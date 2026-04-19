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

use crate::core::auth::jwt::JwtService;

use crate::adapter::access_control_adapter::EbpfAccessControlAdapter;
use crate::adapter::ebpf::EbpfServices;
use crate::adapter::persistence::Database;
use crate::adapter::telegram::{TelegramAdapter, TelegramAdapterFactory};
use crate::core::acl_service::AclService;
use crate::core::config_service::ConfigService;
use crate::core::dns_filter_service::DnsFilterService;
use crate::core::email::scheduler::ReportScheduler;
use crate::core::ml::drift_detector::DriftDetectorHandle;
use crate::core::ml::manifest::ModelManifest;
use crate::core::notification_service::NotificationService;
use crate::core::playbook_service::PlaybookService;
use crate::core::rate_limit_service::RateLimitService;
use crate::core::soar::engine::SoarEngine;
use crate::core::soar::scheduler::TtlScheduler;
use crate::infrastructure::app_config::AppConfig;
use crate::infrastructure::app_services::AppServices;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::infrastructure::ebpf_preflight;
use crate::infrastructure::enforce_mode_handler::EnforceModeHandler;
use crate::infrastructure::geoip::GeoIpService;
use crate::infrastructure::secret_store::SecretStore;
use crate::infrastructure::suricata_manager::SuricataManager;
use crate::interface::communication::command_types::ChangeEnforceModeCommand;
use crate::interface::communication::query_types::GetEnforceModeQuery;
use crate::interface::port::access_control::AccessControlPort;
use crate::interface::port::access_control_admin::AccessControlAdminPort;
use crate::interface::port::app_repo::AppRepo;
use crate::interface::port::dns_filter_api::DnsFilterPort;
use crate::interface::port::geo_block_api::GeoBlockPort;
use crate::interface::port::notification::{AlertNotifier, AlertNotifierFactory};
use crate::interface::port::rate_limit_api::RateLimitPort;
use crate::interface::port::secret_store::SecretStorePort;
use crate::interface::port::setting::SettingRepo;
use crate::interface::port::soar::SoarRepo;
use crate::model::access_control::list_type::ListType;
use crate::model::detection::drift::FeatureBaselines;
use crate::model::error::Error;
use crate::model::error::ebpf::EbpfError;
use crate::model::error::misc::MiscError;
use crate::model::event::{AuditEvent, DriftDetectedEvent, ThreatDetectedEvent};
use crate::model::log::ebpf::EbpfLog;
use crate::model::log::ml::MLLog;
use crate::model::log::system::SystemLog;
use crate::model::monitoring::direction::FlowDirection;
use crate::model::system::config::MLInferenceConfig;
use crate::model::system::health::EbpfFailStage;
use crate::model::system::health::EbpfHealth;
use macros::log;

/// Holds all Arc-wrapped services that make up the running application.
pub struct AppState {
    pub app_config: Arc<AppConfig>,
    pub inference_config: Arc<MLInferenceConfig>,
    pub ebpf_services: Arc<EbpfServices>,
    pub app_services: Arc<AppServices>,
    pub db: Arc<Database>,
    pub secret_store: Arc<SecretStore>,
    pub jwt_service: Arc<JwtService>,
    pub comm: Arc<CommunicationManager>,
    pub soar_engine: Arc<SoarEngine>,
    pub ttl_scheduler: TtlScheduler,
    pub report_scheduler: ReportScheduler,
    pub acl_service: Arc<AclService>,
    pub config_service: Arc<ConfigService>,
    pub dns_filter_service: Arc<DnsFilterService>,
    pub notification_service: Arc<NotificationService>,
    pub playbook_service: Arc<PlaybookService>,
    pub rate_limit_service: Arc<RateLimitService>,
    pub geoip: Option<Arc<GeoIpService>>,
    pub drift_detector: DriftDetectorHandle,
    pub ingress_ebpf: Option<Ebpf>,
    pub egress_ebpf: Option<Ebpf>,
    /// Held to keep the eBPF program array map FD alive. `None` when eBPF
    /// failed to load.
    pub _ingress_program_array: Option<ProgramArray<MapData>>,
    /// Shared eBPF health state. Populated to `Healthy` on successful bring-up,
    /// or to `Unavailable { stage, category, reason }` when any stage fails.
    /// Read by `SystemHealth` for the metrics broadcast and by HTTP handlers
    /// that render runtime status to the frontend.
    pub ebpf_health: Arc<ArcSwap<EbpfHealth>>,
    pub suricata_manager: Arc<SuricataManager>,
}

/// Maps stage name (from config.toml) to (function_name, stage_id).
fn stage_registry() -> HashMap<&'static str, (&'static str, u32)> {
    HashMap::from([
        ("access_control", ("access_control", STAGE_ACCESS_CONTROL)),
        ("rate_limit", ("rate_limit", STAGE_RATE_LIMIT)),
        ("service", ("protocol_filter", STAGE_SERVICE)),
    ])
}

/// Factory responsible for creating and wiring all application services.
pub struct ServiceFactory;

impl ServiceFactory {
    /// Build all services. DB is passed in (already created by main.rs).
    /// Only called when setup is complete — all config values are in DB.
    pub async fn build(db: Arc<Database>) -> Result<AppState, Error> {
        // Ensure DB has all default config keys (INSERT OR IGNORE — never overwrites)
        AppConfig::seed_defaults(&db)?;
        let app_config = Arc::new(AppConfig::new(&db)?);

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
                Arc::new(MLInferenceConfig::load_file(&app_config.inference.models_config_name)?),
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
        let (ingress_ebpf, egress_ebpf, ingress_program_array, ebpf_services) = match Self::try_build_ebpf(&app_config)
        {
            Ok((ingress, egress, pa, services)) => (Some(ingress), Some(egress), Some(pa), Arc::new(services)),
            Err((stage, err)) => {
                let health = ebpf_preflight::classify(stage, &err, None);
                log!(SystemLog::EbpfBringupFailed(format!("{:?}", health)));
                ebpf_health.store(Arc::new(health));
                (
                    None,
                    None,
                    None,
                    Arc::new(EbpfServices::unavailable(app_config.clone())),
                )
            }
        };

        // Ensure enforce_mode setting exists (default: monitor)
        if db.get_setting("enforce_mode")?.is_none() {
            db.set_setting("enforce_mode", "monitor")?;
        }

        let secret_store = Arc::new(SecretStore::new(db.clone()));
        let secret_store_port: Arc<dyn SecretStorePort> = secret_store.clone();

        let jwt_service = Arc::new(JwtService::new(&secret_store_port, app_config.http.jwt_expiry_hours)?);

        // Initialize ML drift detector from inference config baselines
        let baselines = FeatureBaselines::from_inference_config(&inference_config);
        let drift_window_secs: u64 = db
            .get_setting("ml_drift_window_secs")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);
        let drift_detector = DriftDetectorHandle::spawn(baselines, Duration::from_secs(drift_window_secs));

        // Create AtomicU8 enforce-level cache (Monitor=0, MlOnly=1, Enforce=2)
        let enforce_level_cache = Arc::new(AtomicU8::new({
            use crate::infrastructure::enforce_mode_handler::enforce_mode_to_u8;
            let mode_str = db.get_setting("enforce_mode")?.unwrap_or_default();
            enforce_mode_to_u8(&mode_str)
        }));

        // CommunicationManager and its event channels must exist before
        // AppServices spins up the TrafficLogger: the writer thread can
        // publish `flow_trace_stopped` audit events the moment it tries
        // to open its first rotated file, and an unregistered channel
        // would silently drop that evidence.
        let comm = Arc::new(CommunicationManager::new());
        comm.register_event_type::<ThreatDetectedEvent>();
        comm.register_event_type::<DriftDetectedEvent>();
        comm.register_event_type::<AuditEvent>();

        let app_services = Arc::new(AppServices::new(
            app_config.clone(),
            inference_config.clone(),
            ml_manifest.clone(),
            drift_detector.clone(),
            ebpf_health.clone(),
            comm.clone(),
        )?);

        let enforce_handler = Arc::new(EnforceModeHandler::new(
            db.clone() as Arc<dyn AppRepo>,
            comm.clone(),
            enforce_level_cache.clone(),
        ));
        let _ = comm
            .clone()
            .with_service(enforce_handler)
            .command::<ChangeEnforceModeCommand>()
            .query::<GetEnforceModeQuery>()
            .build();

        // Seed default SOAR playbooks if empty
        (db.as_ref() as &dyn SoarRepo).seed_default_playbooks()?;

        // Restore persisted state from database
        Self::restore_dns_blacklist(&db, &ebpf_services);
        Self::restore_geo_countries(&db, &ebpf_services);
        Self::restore_rate_limits(&db, &ebpf_services);
        Self::restore_acl_rules(&db, &ebpf_services).await;

        // Create TelegramAdapter as alert notifier (may fail if not configured yet)
        let alert_notifier: Option<Arc<dyn AlertNotifier>> = match TelegramAdapter::new(
            db.clone() as Arc<dyn SettingRepo>,
            db.clone() as Arc<dyn AppRepo>,
            Some(secret_store_port.clone()),
        ) {
            Ok(adapter) => Some(Arc::new(adapter)),
            Err(e) => {
                log!(SystemLog::TelegramUnavailable(e.to_string()));
                None
            }
        };

        // Try to initialize GeoIP service
        let geoip: Option<Arc<GeoIpService>> = match GeoIpService::new(&app_config.misc.geoip_db_name) {
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
            Arc::new(EbpfAccessControlAdapter::new(ebpf_services.access_control.clone()));

        // Create SOAR engine
        let rate_limit_port: Arc<dyn RateLimitPort> = ebpf_services.rate_limit.clone();
        let soar_engine = Arc::new(SoarEngine::new(
            db.clone(),
            access_control_port.clone(),
            alert_notifier.clone(),
            geoip.clone(),
            Some(rate_limit_port.clone()),
            enforce_level_cache,
            Some(secret_store_port.clone()),
        )?);

        // Create TTL scheduler
        let ttl_scheduler = TtlScheduler::new(db.clone(), access_control_port.clone(), soar_engine.clone());

        // Create Report scheduler
        let report_scheduler =
            ReportScheduler::new(db.clone() as Arc<dyn SettingRepo>, Some(secret_store_port.clone()));

        // Create domain services (Phase 2B) — upcast concrete eBPF services to
        // their port-layer traits so the core services see only abstract ports.
        let access_control_admin: Arc<dyn AccessControlAdminPort> = ebpf_services.access_control.clone();
        let geo_block_port: Arc<dyn GeoBlockPort> = ebpf_services.geo_block.clone();
        let dns_filter_port: Arc<dyn DnsFilterPort> = ebpf_services.dns_filter.clone();
        let acl_service = Arc::new(AclService::new(
            db.clone() as Arc<dyn AppRepo>,
            access_control_admin,
            geo_block_port,
        ));
        let dns_filter_service = Arc::new(DnsFilterService::new(db.clone() as Arc<dyn AppRepo>, dns_filter_port));
        let rate_limit_service = Arc::new(RateLimitService::new(db.clone() as Arc<dyn AppRepo>, rate_limit_port));
        let playbook_service = Arc::new(PlaybookService::new(
            db.clone(),
            soar_engine.clone(),
            access_control_port,
        ));
        let config_service =
            Arc::new(ConfigService::new(db.clone() as Arc<dyn AppRepo>).with_secret_store(secret_store_port.clone()));
        let notifier_factory: Arc<dyn AlertNotifierFactory> = Arc::new(TelegramAdapterFactory::new(
            db.clone() as Arc<dyn SettingRepo>,
            db.clone() as Arc<dyn AppRepo>,
            Some(secret_store_port.clone()),
        ));
        let notification_service = Arc::new(NotificationService::new(
            db.clone() as Arc<dyn SettingRepo>,
            db.clone() as Arc<dyn AppRepo>,
            secret_store_port,
            notifier_factory,
        ));

        let suricata_manager = SuricataManager::new(app_config.clone());

        Ok(AppState {
            app_config,
            inference_config,
            ebpf_services,
            app_services,
            db,
            secret_store,
            jwt_service,
            comm,
            soar_engine,
            ttl_scheduler,
            report_scheduler,
            acl_service,
            config_service,
            dns_filter_service,
            notification_service,
            playbook_service,
            rate_limit_service,
            geoip,
            drift_detector,
            ingress_ebpf,
            egress_ebpf,
            _ingress_program_array: ingress_program_array,
            ebpf_health,
            suricata_manager,
        })
    }

    // --- eBPF loading helpers ---

    /// Attempt the full eBPF bring-up chain: load both .o files, configure the
    /// ingress pipeline, write queue counts, and hand out map handles to the
    /// services. Returns the original stage on the first failure so the
    /// classifier can render targeted diagnostics.
    #[allow(clippy::type_complexity)]
    fn try_build_ebpf(
        app_config: &Arc<AppConfig>,
    ) -> Result<(Ebpf, Ebpf, ProgramArray<MapData>, EbpfServices), (EbpfFailStage, Error)> {
        use crate::model::system::health::EbpfFailStage;

        let mut ingress = Self::load_ebpf("ingress").map_err(|e| (EbpfFailStage::Load, e))?;
        let mut egress = Self::load_ebpf("egress").map_err(|e| (EbpfFailStage::Load, e))?;

        let pipeline = Self::configure_ingress_pipeline(&mut ingress, &app_config.pipeline.ingress)
            .map_err(|e| (EbpfFailStage::PipelineSetup, e))?;

        let num_queues = app_config.network.combined_queue_count;
        Self::write_num_queues(&mut ingress, num_queues).map_err(|e| (EbpfFailStage::PipelineSetup, e))?;
        Self::write_num_queues(&mut egress, num_queues).map_err(|e| (EbpfFailStage::PipelineSetup, e))?;

        let services = EbpfServices::new(app_config.clone(), &mut ingress, &mut egress)
            .map_err(|e| (EbpfFailStage::MapsBind, e))?;

        Ok((ingress, egress, pipeline, services))
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

    fn restore_dns_blacklist(db: &Database, ebpf_services: &EbpfServices) {
        if let Ok(domains) = db.load_dns_domains() {
            for domain in &domains {
                if let Err(e) = ebpf_services.dns_filter.add_domain(domain) {
                    log!(SystemLog::DnsRestoreFailed(domain.clone(), e.to_string()));
                }
            }
            if !domains.is_empty() {
                log!(SystemLog::DnsBlacklistRestored(domains.len()));
            }
        }
    }

    fn restore_geo_countries(db: &Database, ebpf_services: &EbpfServices) {
        if let Ok(countries) = db.load_geo_countries()
            && !countries.is_empty()
        {
            if let Err(e) = ebpf_services.geo_block.block_countries(&countries) {
                log!(SystemLog::GeoRestoreFailed(e.to_string()));
            } else {
                log!(SystemLog::GeoCountriesRestored(countries.len()));
            }
        }
    }

    fn restore_rate_limits(db: &Database, ebpf_services: &EbpfServices) {
        if let Ok(configs) = db.load_rate_limit_config() {
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
        if let Ok(rules) = db.load_acl_rules() {
            let mut restored = 0u32;
            for (ip_version, direction, list_type, ip_address, port) in &rules {
                let dir = match direction.as_str() {
                    "source" => FlowDirection::Source,
                    "destination" => FlowDirection::Destination,
                    other => {
                        log!(SystemLog::AclUnknownDirection(other.to_string()));
                        continue;
                    }
                };
                let lt = match list_type.as_str() {
                    "whitelist" => ListType::White,
                    "blacklist" => ListType::Black,
                    other => {
                        log!(SystemLog::AclUnknownListType(other.to_string()));
                        continue;
                    }
                };
                let result = match ip_version {
                    4 => match ip_address.parse::<Ipv4Addr>() {
                        Ok(addr) => ebpf_services
                            .access_control
                            .add_ipv4_list(dir, lt, SocketAddrV4::new(addr, *port)),
                        Err(e) => {
                            log!(SystemLog::AclIpv4ParseFailed(ip_address.clone(), e.to_string()));
                            continue;
                        }
                    },
                    6 => match ip_address.parse::<Ipv6Addr>() {
                        Ok(addr) => {
                            ebpf_services
                                .access_control
                                .add_ipv6_list(dir, lt, SocketAddrV6::new(addr, *port, 0, 0))
                        }
                        Err(e) => {
                            log!(SystemLog::AclIpv6ParseFailed(ip_address.clone(), e.to_string()));
                            continue;
                        }
                    },
                    other => {
                        log!(SystemLog::AclUnknownIpVersion(*other));
                        continue;
                    }
                };
                if let Err(e) = result {
                    log!(SystemLog::AclRuleRestoreFailed(
                        direction.clone(),
                        list_type.clone(),
                        ip_address.clone(),
                        *port,
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
