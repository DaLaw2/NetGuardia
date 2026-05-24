use std::sync::Arc;
use std::sync::atomic::AtomicU8;

use arc_swap::ArcSwap;
use aya::Ebpf;
use aya::maps::{MapData, ProgramArray};
use tokio::sync::broadcast;

use crate::adapter::ebpf::EbpfServices;
use crate::adapter::http::session::SessionCookieService;
use crate::adapter::persistence::Database;
use crate::adapter::secret_store::SecretStore;
use crate::common::error::Error;
use crate::core::common::config_service::ConfigService;
use crate::core::common::enforce_mode_handler::EnforceModeHandler;
use crate::core::common::notification_service::NotificationService;
use crate::core::common::setup_service::SetupService;
use crate::core::common::statistics::FlowStatistics;
use crate::core::data_plane::acl_service::AclService;
use crate::core::data_plane::dns_filter_service::DnsFilterService;
use crate::core::data_plane::rate_limit_service::RateLimitService;
use crate::core::identity::auth_service::AuthService;
use crate::core::identity::group_service::GroupService;
use crate::core::identity::session_service::SessionService;
use crate::core::identity::user_service::UserService;
use crate::core::inference::drift_detector::{DriftDetectorHandle, DriftDetectorRunner};
use crate::core::inference::inference_runtime::InferenceRuntime;
use crate::core::inference::model_promotion::PromoteGate;
use crate::core::reporting::email_scheduler::ReportScheduler;
use crate::core::reporting::report_delivery::ReportDeliveryService;
use crate::core::reporting::report_generation::ReportGenerationService;
use crate::core::response::engine::SoarEngine;
use crate::core::response::playbook_service::PlaybookService;
use crate::core::response::rate_limit_owner::RateLimitOwnerRunner;
use crate::core::response::scheduler::TtlScheduler;
use crate::domain::common::config::AppConfig;
use crate::domain::common::event::{AuditEvent, DriftDetectedEvent, ThreatDetectedEvent};
use crate::domain::common::system::health::EbpfHealth;
use crate::domain::detection::ml_inference_config::MLInferenceConfig;
use crate::infrastructure::health::SystemHealth;
use crate::infrastructure::log_buffer::LogBuffer;
use crate::infrastructure::logger::Logger;
use crate::infrastructure::model_promotion_deps::ModelPromotionDeps;
use crate::infrastructure::readiness::ReadinessState;
use crate::infrastructure::runtime_state::RuntimeState;
use crate::infrastructure::suricata_manager::SuricataManager;
use crate::interface::detection::geo_lookup::GeoLookup;
use crate::interface::identity::api_key_hasher::ApiKeyHasher;
use crate::interface::system::secret_store::SecretStorePort;
use crate::interface::system::system_control::BootTimeQuery;

pub mod data_plane;
mod detection;
mod foundation;
mod identity;
mod observability;
mod reporting;
mod response;

use data_plane::build_data_plane;
use detection::build_detection;
use foundation::build_foundation;
use identity::build_identity;
use observability::build_observability;
use reporting::build_reporting;
use response::build_response;

const EVENT_CHANNEL_CAPACITY: usize = 256;

pub struct SystemRuntime {
    pub foundation: FoundationRuntime,
    pub data_plane: DataPlaneRuntime,
    pub identity: IdentityRuntime,
    pub detection: DetectionRuntime,
    pub response: ResponseRuntime,
    pub reporting: ReportingRuntime,
    pub observability: ObservabilityRuntime,
}

pub struct FoundationRuntime {
    pub app_config: Arc<ArcSwap<AppConfig>>,
    pub runtime_state: Arc<ArcSwap<RuntimeState>>,
    pub database: Arc<Database>,
    pub logger: Arc<Logger>,
    pub log_buffer: Arc<LogBuffer>,
    pub secret_store: Arc<SecretStore>,
    pub secret_store_port: Arc<dyn SecretStorePort>,
    pub ebpf_health: Arc<ArcSwap<EbpfHealth>>,
    pub channels: EventChannels,
    pub readiness: Arc<ReadinessState>,
    pub setup_service: Arc<SetupService>,
    pub boot_time_query: Arc<dyn BootTimeQuery>,
}

pub struct EventChannels {
    pub threat_tx: broadcast::Sender<ThreatDetectedEvent>,
    pub audit_tx: broadcast::Sender<AuditEvent>,
    pub drift_tx: broadcast::Sender<DriftDetectedEvent>,
}

pub struct DataPlaneRuntime {
    pub ebpf_services: Arc<EbpfServices>,
    pub ingress_ebpf: Option<Ebpf>,
    pub egress_ebpf: Option<Ebpf>,
    pub _ingress_program_array: Option<ProgramArray<MapData>>,
}

pub struct IdentityRuntime {
    pub session_service: Arc<SessionService>,
    pub session_cookie_service: Arc<SessionCookieService>,
    pub auth_service: Arc<AuthService>,
    pub user_service: Arc<UserService>,
    pub group_service: Arc<GroupService>,
    pub enforce_handler: Arc<EnforceModeHandler>,
    pub enforce_level_cache: Arc<AtomicU8>,
    pub api_key_hasher: Arc<dyn ApiKeyHasher>,
}

pub struct DetectionRuntime {
    pub inference_config: Arc<MLInferenceConfig>,
    pub inference_runtime: Arc<InferenceRuntime>,
    pub flow_statistics: Arc<FlowStatistics>,
    pub drift_detector: DriftDetectorHandle,
    pub drift_detector_runner: Option<DriftDetectorRunner>,
    pub promote_gate: Arc<PromoteGate>,
    pub model_promotion_deps: Arc<ModelPromotionDeps>,
}

pub struct ResponseRuntime {
    pub acl_service: Arc<AclService>,
    pub config_service: Arc<ConfigService>,
    pub dns_filter_service: Arc<DnsFilterService>,
    pub notification_service: Arc<NotificationService>,
    pub playbook_service: Arc<PlaybookService>,
    pub rate_limit_service: Arc<RateLimitService>,
    pub soar_engine: Arc<SoarEngine>,
    pub rate_limit_owner_runner: Option<RateLimitOwnerRunner>,
    pub ttl_scheduler: Option<TtlScheduler>,
    pub geoip: Option<Arc<dyn GeoLookup>>,
}

pub struct ReportingRuntime {
    pub report_generation_service: Arc<ReportGenerationService>,
    pub report_delivery_service: Arc<ReportDeliveryService>,
    pub report_scheduler: Option<ReportScheduler>,
}

pub struct ObservabilityRuntime {
    pub health: Arc<SystemHealth>,
    pub suricata_manager: Arc<SuricataManager>,
}

pub async fn create_runtime(
    db: Arc<Database>,
    app_config: AppConfig,
    logger: Arc<Logger>,
    log_buffer: Arc<LogBuffer>,
    api_key_hmac: [u8; 32],
) -> Result<SystemRuntime, Error> {
    let foundation = build_foundation(db, app_config, logger, log_buffer).await?;
    let (data_plane, dns_filter_port) = build_data_plane(&foundation);
    let identity = build_identity(&foundation, api_key_hmac)?;
    let detection = build_detection(&foundation)?;
    let response = build_response(&foundation, &data_plane, dns_filter_port, &identity).await?;
    let reporting = build_reporting(&foundation).await;
    let observability = build_observability(&foundation)?;

    Ok(SystemRuntime {
        foundation,
        data_plane,
        identity,
        detection,
        response,
        reporting,
        observability,
    })
}
