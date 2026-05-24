use std::sync::Arc;
use std::sync::atomic::AtomicU8;

use arc_swap::ArcSwap;

use crate::common::error::Error;
use crate::core::response::matcher::PlaybookMatcher;
use crate::core::response::rate_limit_owner::RateLimitOwnerHandle;
use crate::domain::common::config::AppConfig;
use crate::interface::data_plane::access_control::AccessControlPort;
use crate::interface::detection::geo_lookup::GeoLookup;
use crate::interface::reporting::email_sender::EmailSenderFactory;
use crate::interface::response::notification::AlertNotifier;
use crate::interface::response::soar::SoarControlRepo;
use crate::interface::response::webhook_sender::WebhookSender;
use crate::interface::system::secret_store::SecretStorePort;

mod dry_run;
mod execution;
mod playbook;

pub struct SoarEngine {
    pub db: Arc<dyn SoarControlRepo>,
    pub access_control: Arc<dyn AccessControlPort>,
    pub matcher: PlaybookMatcher,
    pub alert_notifier: Option<Arc<dyn AlertNotifier>>,
    pub geoip: Option<Arc<dyn GeoLookup>>,
    pub rate_limit: Option<RateLimitOwnerHandle>,
    pub enforce_level_cache: Arc<AtomicU8>,
    pub secrets: Option<Arc<dyn SecretStorePort>>,
    pub email_sender_factory: Arc<dyn EmailSenderFactory>,
    pub webhook_sender: Arc<dyn WebhookSender>,
}

pub struct SoarEngineDeps {
    pub db: Arc<dyn SoarControlRepo>,
    pub config: Arc<ArcSwap<AppConfig>>,
    pub access_control: Arc<dyn AccessControlPort>,
    pub alert_notifier: Option<Arc<dyn AlertNotifier>>,
    pub geoip: Option<Arc<dyn GeoLookup>>,
    pub rate_limit: Option<RateLimitOwnerHandle>,
    pub enforce_level_cache: Arc<AtomicU8>,
    pub secrets: Option<Arc<dyn SecretStorePort>>,
    pub email_sender_factory: Arc<dyn EmailSenderFactory>,
    pub webhook_sender: Arc<dyn WebhookSender>,
}

impl SoarEngine {
    pub async fn new(deps: SoarEngineDeps) -> Result<Self, Error> {
        let SoarEngineDeps {
            db,
            config,
            access_control,
            alert_notifier,
            geoip,
            rate_limit,
            enforce_level_cache,
            secrets,
            email_sender_factory,
            webhook_sender,
        } = deps;
        let soar_cfg = config.load();
        let freq_max_keys = soar_cfg.soar.frequency_max_tracked_keys;
        let freq_max_events_per_key = soar_cfg.soar.frequency_max_events_per_key;
        let freq_retention_secs = soar_cfg.soar.frequency_retention_secs;
        drop(soar_cfg);
        let matcher = PlaybookMatcher::new(config, freq_max_keys, freq_max_events_per_key, freq_retention_secs);
        let engine = Self {
            db,
            access_control,
            matcher,
            alert_notifier,
            geoip,
            rate_limit,
            enforce_level_cache,
            secrets,
            email_sender_factory,
            webhook_sender,
        };
        engine.reload_cache().await?;
        Ok(engine)
    }
}

#[cfg(test)]
mod tests;
