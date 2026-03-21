use std::collections::HashMap;
use std::sync::Arc;

use actix_web::web::route;
use actix_web::{web, App, HttpServer};
use aya::maps::{Array, MapData, ProgramArray};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use aya_log::EbpfLogger;
use common::define::pipeline::*;
use macros::log;

use crate::core::ebpf::EbpfServices;
use crate::core::infrastructure::app_config::AppConfig;
use crate::core::infrastructure::MLService;
use crate::core::ml::config_loader::InferenceConfig;
use crate::model::error::ebpf::EbpfError;
use crate::model::error::http::HttpError;
use crate::model::error::misc::MiscError;
use crate::model::error::Error;
use crate::model::log::ml::MLLog;
use crate::model::log::system::SystemLog;
use crate::utils::logging::Logging;
use crate::web::api::{acl, filter, rate_limit as rate_limit_api, stats, health as health_api, ml, system as system_api, default, ws};

/// Maps stage name (from config.toml) to (function_name, stage_id)
fn stage_registry() -> HashMap<&'static str, (&'static str, u32)> {
    HashMap::from([
        ("access_control", ("access_control", STAGE_ACCESS_CONTROL)),
        ("rate_limit", ("rate_limit", STAGE_RATE_LIMIT)),
        ("service", ("protocol_filter", STAGE_SERVICE)),
    ])
}

pub struct System {
    pub app_config: Arc<AppConfig>,
    pub inference_config: Arc<InferenceConfig>,
    pub ebpf_services: Arc<EbpfServices>,
    pub app_services: Arc<MLService>,
    pub ingress_ebpf: Ebpf,
    pub egress_ebpf: Ebpf,
    #[allow(dead_code)]
    ingress_program_array: ProgramArray<MapData>,
}

impl System {
    pub async fn new() -> Result<Self, Error> {
        let mut ingress_ebpf = Self::load_ebpf("ingress")?;
        let mut egress_ebpf = Self::load_ebpf("egress")?;
        let app_config = Arc::new(AppConfig::new()?);

        let ingress_program_array = Self::configure_ingress_pipeline(
            &mut ingress_ebpf,
            &app_config.pipeline.ingress,
        )?;

        let inference_config = Arc::new(InferenceConfig::load_file(&app_config.inference.models_config_name)?);

        // Write queue count to eBPF maps for symmetric hash redirect
        let num_queues = app_config.network.combined_queue_count;
        Self::write_num_queues(&mut ingress_ebpf, num_queues)?;
        Self::write_num_queues(&mut egress_ebpf, num_queues)?;

        let ebpf_services = Arc::new(EbpfServices::new(
            app_config.clone(),
            &mut ingress_ebpf,
            &mut egress_ebpf,
        )?);

        let app_services = Arc::new(MLService::new(app_config.clone(), inference_config.clone())?);

        Ok(System {
            app_config,
            inference_config,
            ebpf_services,
            app_services,
            ingress_ebpf,
            egress_ebpf,
            ingress_program_array,
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

        self.aya_log_init()?;
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

    fn aya_log_init(&mut self) -> Result<(), Error> {
        EbpfLogger::init(&mut self.ingress_ebpf).map_err(EbpfError::LoggerInitFailed)?;
        EbpfLogger::init(&mut self.egress_ebpf).map_err(EbpfError::LoggerInitFailed)?;
        Ok(())
    }

    fn attach_ebpf(&mut self) -> Result<(), Error> {
        let ingress_ifname = self.app_config.network.ingress_ifname.clone();
        let egress_ifname = self.app_config.network.egress_ifname.clone();
        Self::set_memory_limit()?;

        Self::attach_xdp(&mut self.ingress_ebpf, &ingress_ifname, true)?;
        Self::attach_xdp(&mut self.egress_ebpf, &egress_ifname, false)?;
        Ok(())
    }

    fn attach_xdp(ebpf: &mut Ebpf, ifname: &str, already_loaded: bool) -> Result<(), Error> {
        let xdp: &mut Xdp = ebpf
            .program_mut("net_guardia")
            .ok_or(EbpfError::ProgramNotFound)?
            .try_into()
            .map_err(EbpfError::GetProgramFailed)?;
        if !already_loaded {
            xdp.load().map_err(EbpfError::LoadProgramFailed)?;
        }
        xdp.attach(ifname, XdpFlags::DRV_MODE)
            .map_err(EbpfError::AttachProgramFailed)?;
        Ok(())
    }

    async fn run_http_server(&self) -> Result<(), Error> {
        let app_config = self.app_config.clone();
        let inference_config = self.inference_config.clone();
        let access_control = self.ebpf_services.access_control.clone();
        let protocol_filter = self.ebpf_services.protocol_filter.clone();
        let dns_filter = self.ebpf_services.dns_filter.clone();
        let geo_block = self.ebpf_services.geo_block.clone();
        let rate_limit = self.ebpf_services.rate_limit.clone();
        let health = self.app_services.health.clone();
        let ml_alert = self.app_services.ml_alert.clone();
        let ml_engine = self.app_services.ml_engine.clone();
        let flow_statistics = self.app_services.flow_statistics.clone();
        let drop_monitor = self.ebpf_services.drop_monitor.clone();
        let port = self.app_config.http.http_server_bind_port;
        HttpServer::new(move || {
            let cors = actix_cors::Cors::default()
                .allowed_origin("http://localhost:8080")
                .allowed_origin("http://127.0.0.1:8080")
                .allow_any_method()
                .allow_any_header()
                .max_age(3600);
            App::new()
                .wrap(cors)
                .app_data(web::Data::from(app_config.clone()))
                .app_data(web::Data::from(inference_config.clone()))
                .app_data(web::Data::from(access_control.clone()))
                .app_data(web::Data::from(protocol_filter.clone()))
                .app_data(web::Data::from(dns_filter.clone()))
                .app_data(web::Data::from(geo_block.clone()))
                .app_data(web::Data::from(rate_limit.clone()))
                .app_data(web::Data::from(health.clone()))
                .app_data(web::Data::from(ml_alert.clone()))
                .app_data(web::Data::from(ml_engine.clone()))
                .app_data(web::Data::from(flow_statistics.clone()))
                .app_data(web::Data::from(drop_monitor.clone()))
                .service(
                    web::scope("/api")
                        .service(acl::initialize())
                        .service(filter::initialize())
                        .service(rate_limit_api::initialize())
                        .service(stats::initialize())
                        .service(health_api::initialize())
                        .service(ml::initialize())
                        .service(system_api::initialize())
                )
                .service(ws::initialize())
                .default_service(route().to(default::default_route))
        })
        .bind(format!("0.0.0.0:{}", port))
        .map_err(HttpError::BindPortError)?
        .run()
        .await
        .map_err(HttpError::ServerPanic)?;
        Ok(())
    }

    fn load_ebpf(name: &str) -> Result<Ebpf, Error> {
        let bytes = match name {
            "ingress" => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/net-guardia-ingress")),
            "egress" => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/net-guardia-egress")),
            _ => return Err(EbpfError::ProgramNotFound.into()),
        };
        Ok(Ebpf::load(bytes).map_err(EbpfError::EbpfNotFound)?)
    }

    /// Configure the ingress pipeline based on config.toml [Pipeline] section.
    /// Loads each stage program into ProgramArray and wires NEXT_STAGE map.
    fn configure_ingress_pipeline(
        ebpf: &mut Ebpf,
        stages: &[String],
    ) -> Result<ProgramArray<MapData>, Error> {
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
                .set(STAGE_ENTRY as u32, STAGE_TRANSMISSION, 0)
                .map_err(EbpfError::MapOperationError)?;
            return Ok(program_array);
        }

        let mut slots: Vec<(u32, u32)> = Vec::new();
        for (i, stage_name) in stages.iter().enumerate() {
            let (func_name, stage_id) = registry
                .get(stage_name.as_str())
                .ok_or(EbpfError::ProgramNotFound)?;
            let slot = (i + 1) as u32;
            Self::load_program(ebpf, &mut program_array, func_name, slot)?;
            slots.push((*stage_id, slot));
        }

        next_stage
            .set(STAGE_ENTRY as u32, slots[0].1, 0)
            .map_err(EbpfError::MapOperationError)?;

        for i in 0..slots.len() {
            let (stage_id, _) = slots[i];
            let next_slot = if i + 1 < slots.len() {
                slots[i + 1].1
            } else {
                STAGE_TRANSMISSION
            };
            next_stage
                .set(stage_id as u32, next_slot, 0)
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
        let fd = program.fd().map_err(|_| EbpfError::UnknownError)?;
        program_array
            .set(slot, fd, 0)
            .map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    fn set_memory_limit() -> Result<(), Error> {
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

    fn write_num_queues(ebpf: &mut Ebpf, num_queues: u32) -> Result<(), Error> {
        let map = ebpf.map_mut("NUM_QUEUES").ok_or(EbpfError::MapNotFound)?;
        let mut arr = Array::<_, u32>::try_from(map).map_err(EbpfError::MapOperationError)?;
        arr.set(0, num_queues, 0).map_err(EbpfError::MapOperationError)?;
        Ok(())
    }
}
