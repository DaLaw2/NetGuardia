use std::sync::Arc;
use std::sync::atomic::Ordering;

use arc_swap::ArcSwap;
use tokio::sync::broadcast;

use crate::adapter::identity::password_hasher::Argon2PasswordHasher;
use crate::adapter::persistence::Database;
use crate::adapter::secret_store::SecretStore;
use crate::common::error::Error;
use crate::core::common::setup_service::SetupService;
use crate::domain::common::config::AppConfig;
use crate::domain::common::event::{AuditEvent, DriftDetectedEvent, ThreatDetectedEvent};
use crate::domain::common::system::health::EbpfHealth;
use crate::infrastructure::boot_time::SysinfoBootTimeQuery;
use crate::infrastructure::log_buffer::LogBuffer;
use crate::infrastructure::logger::Logger;
use crate::infrastructure::readiness::ReadinessState;
use crate::infrastructure::runtime_state::RuntimeState;
use crate::infrastructure::startup::{EVENT_CHANNEL_CAPACITY, EventChannels, FoundationRuntime};
use crate::interface::system::secret_store::SecretStorePort;
use crate::interface::system::setup::SetupRepo;
use crate::interface::system::system_control::BootTimeQuery;

pub async fn build_foundation(
    db: Arc<Database>,
    app_config: AppConfig,
    logger: Arc<Logger>,
    log_buffer: Arc<LogBuffer>,
) -> Result<FoundationRuntime, Error> {
    let app_config = Arc::new(ArcSwap::from_pointee(app_config));
    let runtime_state = Arc::new(ArcSwap::from_pointee(RuntimeState::default()));
    let secret_store = Arc::new(SecretStore::new(db.clone()));
    let secret_store_port: Arc<dyn SecretStorePort> = secret_store.clone();
    let ebpf_health = Arc::new(ArcSwap::from_pointee(EbpfHealth::Healthy));
    let channels = create_event_channels();
    let readiness = Arc::new(ReadinessState::new());
    readiness.db_connected.store(true, Ordering::SeqCst);

    let setup_service = Arc::new(SetupService::new(
        db.clone() as Arc<dyn SetupRepo>,
        secret_store.clone() as Arc<dyn SecretStorePort>,
        Arc::new(Argon2PasswordHasher),
    ));
    let boot_time_query = Arc::new(SysinfoBootTimeQuery) as Arc<dyn BootTimeQuery>;

    Ok(FoundationRuntime {
        app_config,
        runtime_state,
        database: db,
        logger,
        log_buffer,
        secret_store,
        secret_store_port,
        ebpf_health,
        channels,
        readiness,
        setup_service,
        boot_time_query,
    })
}

fn create_event_channels() -> EventChannels {
    let (threat_tx, _) = broadcast::channel::<ThreatDetectedEvent>(EVENT_CHANNEL_CAPACITY);
    let (audit_tx, _) = broadcast::channel::<AuditEvent>(EVENT_CHANNEL_CAPACITY);
    let (drift_tx, _) = broadcast::channel::<DriftDetectedEvent>(EVENT_CHANNEL_CAPACITY);
    EventChannels {
        threat_tx,
        audit_tx,
        drift_tx,
    }
}
