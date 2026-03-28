use std::sync::Arc;

use aya::maps::{MapData, ProgramArray};
use aya::Ebpf;
use macros::log;

use crate::core::acl_service::AclService;
use crate::core::auth::jwt::JwtService;
use crate::core::config_service::ConfigService;
use crate::core::dns_filter_service::DnsFilterService;
use crate::core::notification_service::NotificationService;
use crate::core::playbook_service::PlaybookService;
use crate::core::rate_limit_service::RateLimitService;
use crate::adapter::persistence::Database;
use crate::core::ebpf::EbpfServices;
use crate::infrastructure::app_config::AppConfig;
use crate::infrastructure::app_services::AppServices;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::core::ml::config_loader::InferenceConfig;
use crate::infrastructure::http_server::HttpServerParams;
use crate::infrastructure::service_factory::ServiceFactory;
use crate::core::email::scheduler::ReportScheduler;
use crate::core::soar::engine::SoarEngine;
use crate::core::soar::scheduler::TtlScheduler;
use crate::interface::communication::event_types::ThreatDetectedEvent;
use crate::model::error::Error;
use crate::model::error::system::SystemError;
use crate::model::log::ml::MLLog;
use crate::model::log::system::SystemLog;
use crate::model::ml_detection::AlertMessage;

/// Orchestrates system lifecycle: startup ordering and shutdown.
/// Construction is delegated to `ServiceFactory::build()`.
/// Setup mode is handled by main.rs — System only runs when setup is complete.
pub struct System {
    pub app_config: Arc<AppConfig>,
    pub inference_config: Arc<InferenceConfig>,
    pub ebpf_services: Arc<EbpfServices>,
    pub app_services: Arc<AppServices>,
    pub db: Arc<Database>,
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
            _ingress_program_array: state._ingress_program_array,
        })
    }

    /// Start all services and HTTP server. Setup is already complete at this point.
    pub async fn run(&mut self) -> Result<(), Error> {
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

        // Start stats aggregator (writes weekly_* settings for Report engine)
        let stats_aggregator = crate::core::stats_aggregator::StatsAggregator::new(self.db.clone());
        stats_aggregator.start();

        // Bridge ML alerts → SOAR
        let comm_for_bridge = self.comm.clone();
        tokio::spawn(async move {
            Self::bridge_ml_to_soar(ml_alert_rx, comm_for_bridge).await;
        });

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
            jwt_service: self.jwt_service.clone(),
            comm: self.comm.clone(),
            setup_complete: setup_flag,
            ready: ready_flag,
            acl_service: self.acl_service.clone(),
            config_service: self.config_service.clone(),
            dns_filter_service: self.dns_filter_service.clone(),
            notification_service: self.notification_service.clone(),
            playbook_service: self.playbook_service.clone(),
            rate_limit_service: self.rate_limit_service.clone(),
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

        // Wait for shutdown signal
        tokio::signal::ctrl_c().await.ok();
        Ok(())
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
                log!(SystemLog::UnknownMlAttackType(other.to_string()));
                "threat_detected".to_string()
            }
        }
    }

    async fn bridge_ml_to_soar(
        mut rx: tokio::sync::broadcast::Receiver<AlertMessage>,
        comm: Arc<CommunicationManager>,
    ) {
        log!(SystemLog::MlSoarBridgeStarted);
        loop {
            match rx.recv().await {
                Ok(alert) => {
                    let event = ThreatDetectedEvent {
                        attack_type: Self::normalize_attack_type(
                            &alert.attack_type.unwrap_or_else(|| "unknown".into()),
                        ),
                        confidence: alert.confidence,
                        source_ip: alert.src_ip,
                        dest_ip: alert.dst_ip,
                    };
                    if let Err(e) = comm.publish_event(event).await {
                        log!(SystemError::MlSoarBridgeFailed(e));
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    log!(SystemLog::MlSoarBridgeLagged(n));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    log!(SystemLog::MlAlertChannelClosed);
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
