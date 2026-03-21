use std::sync::Arc;

use aya::maps::{MapData, ProgramArray};
use aya::Ebpf;
use macros::log;

use crate::core::auth::jwt::JwtService;
use crate::adapter::persistence::Database;
use crate::core::ebpf::EbpfServices;
use crate::infrastructure::app_config::AppConfig;
use crate::infrastructure::app_services::AppServices;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::core::ml::config_loader::InferenceConfig;
#[cfg(feature = "license")]
use crate::core::license::LicenseInfo;
use crate::infrastructure::http_server::HttpServerParams;
use crate::infrastructure::service_factory::ServiceFactory;
use crate::model::error::Error;
use crate::model::log::ml::MLLog;
use crate::model::log::system::SystemLog;
use crate::utils::logging::Logging;

/// Thin wrapper around infrastructure services.
/// Delegates construction to `ServiceFactory::build()` and HTTP to
/// `infrastructure::http_server::run()`.
/// Will be removed in a later refactoring phase.
pub struct System {
    pub app_config: Arc<AppConfig>,
    pub inference_config: Arc<InferenceConfig>,
    pub ebpf_services: Arc<EbpfServices>,
    pub app_services: Arc<AppServices>,
    pub db: Arc<Database>,
    pub jwt_service: Arc<JwtService>,
    pub comm: Arc<CommunicationManager>,
    #[cfg(feature = "license")]
    pub license_info: Arc<LicenseInfo>,
    pub ingress_ebpf: Ebpf,
    pub egress_ebpf: Ebpf,
    #[allow(dead_code)]
    ingress_program_array: ProgramArray<MapData>,
}

impl System {
    pub async fn new() -> Result<Self, Error> {
        let state = ServiceFactory::build().await?;
        Ok(System {
            app_config: state.app_config,
            inference_config: state.inference_config,
            ebpf_services: state.ebpf_services,
            app_services: state.app_services,
            db: state.db,
            jwt_service: state.jwt_service,
            comm: state.comm,
            #[cfg(feature = "license")]
            license_info: state.license_info,
            ingress_ebpf: state.ingress_ebpf,
            egress_ebpf: state.egress_ebpf,
            ingress_program_array: state.ingress_program_array,
        })
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        let ebpf_services = self.ebpf_services.clone();
        let app_services = self.app_services.clone();
        Logging::initialize()?;
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

        ebpf_services.run(app_services.ml_engine.clone()).await?;
        app_services.run().await?;
        self.run_http_server().await?;
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

    fn attach_ebpf(&mut self) -> Result<(), Error> {
        let ingress_ifname = self.app_config.network.ingress_ifname.clone();
        let egress_ifname = self.app_config.network.egress_ifname.clone();
        ServiceFactory::set_memory_limit()?;

        let ingress_mode = ServiceFactory::attach_xdp(&mut self.ingress_ebpf, &ingress_ifname, true)?;
        let egress_mode = ServiceFactory::attach_xdp(&mut self.egress_ebpf, &egress_ifname, false)?;

        // Store XDP mode in settings for health API reporting
        if let Err(e) = self.db.set_setting("xdp_ingress_mode", &ingress_mode) {
            tracing::warn!("Failed to store XDP ingress mode: {}", e);
        }
        if let Err(e) = self.db.set_setting("xdp_egress_mode", &egress_mode) {
            tracing::warn!("Failed to store XDP egress mode: {}", e);
        }

        Ok(())
    }

    async fn run_http_server(&self) -> Result<(), Error> {
        let params = HttpServerParams {
            app_config: self.app_config.clone(),
            inference_config: self.inference_config.clone(),
            ebpf_services: self.ebpf_services.clone(),
            app_services: self.app_services.clone(),
            db: self.db.clone(),
            jwt_service: self.jwt_service.clone(),
            comm: self.comm.clone(),
            #[cfg(feature = "license")]
            license_info: self.license_info.clone(),
        };
        crate::infrastructure::http_server::run(params).await
    }
}
