use std::sync::Arc;

use arc_swap::ArcSwap;
use macros::log;

use crate::adapter::access_control::AccessControlAdapter;
use crate::adapter::geoip::GeoIpService;
use crate::adapter::notification::smtp::SmtpClientFactory;
use crate::adapter::telegram::{TelegramAdapter, TelegramAdapterFactory};
use crate::adapter::webhook_sender::ReqwestWebhookSender;
use crate::common::error::Error;
use crate::common::log::data_plane::DataPlaneLog;
use crate::common::log::notification::NotificationLog;
use crate::core::common::config_service::ConfigService;
use crate::core::common::notification_service::NotificationService;
use crate::core::data_plane::acl_service::AclService;
use crate::core::data_plane::dns_filter_service::DnsFilterService;
use crate::core::data_plane::rate_limit_service::RateLimitService;
use crate::core::response::engine::{SoarEngine, SoarEngineDeps};
use crate::core::response::playbook_service::PlaybookService;
use crate::core::response::rate_limit_owner::RateLimitOwnerHandle;
use crate::core::response::scheduler::TtlScheduler;
use crate::domain::common::config::AppConfig;
use crate::infrastructure::startup::{DataPlaneRuntime, FoundationRuntime, IdentityRuntime, ResponseRuntime};
use crate::interface::data_plane::access_control::AccessControlPort;
use crate::interface::data_plane::access_control_admin::AccessControlAdminPort;
use crate::interface::data_plane::acl::AclRepo;
use crate::interface::data_plane::dns_filter_api::DnsFilterPort;
use crate::interface::data_plane::enforcement::DnsEnforcementPort;
use crate::interface::data_plane::enforcement::GeoEnforcementPort;
use crate::interface::data_plane::enforcement::RateLimitWritePort;
use crate::interface::data_plane::geo_block_api::GeoBlockPort;
use crate::interface::data_plane::rate_limit_api::RateLimitPort;
use crate::interface::detection::geo_lookup::GeoLookup;
use crate::interface::reporting::email_sender::EmailSenderFactory;
use crate::interface::response::notification::{AlertNotifier, AlertNotifierFactory};
use crate::interface::response::soar::SoarControlRepo;
use crate::interface::system::config_repo::ConfigRepo;

pub async fn build_response(
    foundation: &FoundationRuntime,
    data_plane: &DataPlaneRuntime,
    dns_filter_port: Arc<dyn DnsFilterPort>,
    identity: &IdentityRuntime,
) -> Result<ResponseRuntime, Error> {
    let alert_notifier = build_alert_notifier(foundation);
    let geoip = build_geoip(&foundation.app_config);
    let access_control_port: Arc<dyn AccessControlPort> = Arc::new(AccessControlAdapter::new(
        data_plane.ebpf_services.access_control.clone(),
    ));
    let email_sender_factory: Arc<dyn EmailSenderFactory> = Arc::new(SmtpClientFactory);
    let webhook_sender = Arc::new(ReqwestWebhookSender);
    let rate_limit_port: Arc<dyn RateLimitPort> = data_plane.ebpf_services.rate_limit.clone();
    let rate_limit_channel = foundation.app_config.load().soar.rate_limit_cmd_channel_capacity;
    let (rate_limit_owner, rate_limit_owner_runner) =
        RateLimitOwnerHandle::new(rate_limit_port.clone(), rate_limit_channel);
    let soar_engine = Arc::new(
        SoarEngine::new(SoarEngineDeps {
            db: foundation.database.clone() as Arc<dyn SoarControlRepo>,
            config: foundation.app_config.clone(),
            access_control: access_control_port.clone(),
            alert_notifier: alert_notifier.clone(),
            geoip: geoip.clone(),
            rate_limit: Some(rate_limit_owner),
            enforce_level_cache: identity.enforce_level_cache.clone(),
            secrets: Some(foundation.secret_store_port.clone()),
            email_sender_factory: email_sender_factory.clone(),
            webhook_sender,
        })
        .await?,
    );
    let ttl_scheduler = TtlScheduler::new(
        foundation.database.clone() as Arc<dyn SoarControlRepo>,
        access_control_port.clone(),
        soar_engine.clone(),
    );
    let access_control_admin: Arc<dyn AccessControlAdminPort> = data_plane.ebpf_services.access_control.clone();
    let geo_block_port: Arc<dyn GeoBlockPort> = data_plane.ebpf_services.geo_block.clone();
    let acl_service = Arc::new(AclService::new(
        foundation.database.clone() as Arc<dyn AclRepo>,
        foundation.database.clone() as Arc<dyn GeoEnforcementPort>,
        access_control_admin,
        geo_block_port,
    ));
    let dns_filter_service = Arc::new(DnsFilterService::new(
        foundation.database.clone() as Arc<dyn DnsEnforcementPort>,
        dns_filter_port,
        foundation.app_config.clone(),
    ));
    let rate_limit_service = Arc::new(RateLimitService::new(
        foundation.database.clone() as Arc<dyn RateLimitWritePort>,
        rate_limit_port,
    ));
    let playbook_service = Arc::new(PlaybookService::new(
        foundation.database.clone() as Arc<dyn SoarControlRepo>,
        soar_engine.clone(),
        access_control_port,
    ));
    let config_service = Arc::new(
        ConfigService::new(
            foundation.database.clone() as Arc<dyn ConfigRepo>,
            foundation.app_config.clone(),
        )
        .with_secret_store(foundation.secret_store_port.clone()),
    );
    let notifier_factory: Arc<dyn AlertNotifierFactory> = Arc::new(TelegramAdapterFactory::new(
        foundation.database.clone() as Arc<dyn ConfigRepo + Send + Sync>,
        foundation.app_config.clone(),
        Some(foundation.secret_store_port.clone()),
    ));
    let notification_service = Arc::new(NotificationService::new(
        foundation.database.clone() as Arc<dyn ConfigRepo + Send + Sync>,
        foundation.app_config.clone(),
        foundation.secret_store_port.clone(),
        notifier_factory,
        email_sender_factory,
    ));

    dns_filter_service.restore().await;
    acl_service.restore().await;
    rate_limit_service.restore().await;

    Ok(ResponseRuntime {
        acl_service,
        config_service,
        dns_filter_service,
        notification_service,
        playbook_service,
        rate_limit_service,
        soar_engine,
        rate_limit_owner_runner: Some(rate_limit_owner_runner),
        ttl_scheduler: Some(ttl_scheduler),
        geoip,
    })
}

fn build_alert_notifier(foundation: &FoundationRuntime) -> Option<Arc<dyn AlertNotifier>> {
    match TelegramAdapter::new(
        foundation.database.clone() as Arc<dyn ConfigRepo + Send + Sync>,
        foundation.app_config.clone(),
        Some(foundation.secret_store_port.clone()),
    ) {
        Ok(adapter) => Some(Arc::new(adapter)),
        Err(e) => {
            log!(NotificationLog::TelegramUnavailable(e.to_string()));
            None
        }
    }
}

fn build_geoip(app_config: &Arc<ArcSwap<AppConfig>>) -> Option<Arc<dyn GeoLookup>> {
    let acl_cfg = app_config.load().acl.clone();
    match GeoIpService::with_cache_size(&acl_cfg.geoip_db_path, acl_cfg.geoip_cache_capacity) {
        Ok(svc) => {
            log!(DataPlaneLog::GeoIpInitialized);
            Some(Arc::new(svc))
        }
        Err(e) => {
            log!(DataPlaneLog::GeoIpUnavailable(e.to_string()));
            None
        }
    }
}
