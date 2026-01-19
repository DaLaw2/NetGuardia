use std::sync::Arc;

use actix_web::web::route;
use actix_web::{web, App, HttpServer};
use aya::maps::{MapData, ProgramArray};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use aya_log::EbpfLogger;
use common::define::program_array::*;
use macros::log;

use crate::core::ebpf::EbpfServices;
use crate::core::infrastructure::app_config::AppConfig;
use crate::model::error::ebpf::EbpfError;
use crate::model::error::http::HttpError;
use crate::model::error::misc::MiscError;
use crate::model::error::Error;
use crate::model::error::ml::MLError;
use crate::model::log::ml::MLLog;
use crate::model::log::system::SystemLog;
use crate::utils::logging::Logging;
use crate::web::api::{control, default, misc};

pub struct System {
    pub app_config: Arc<AppConfig>,
    pub ebpf_services: Arc<EbpfServices>,
    pub ingress_ebpf: Ebpf,
    pub egress_ebpf: Ebpf,
    #[allow(dead_code)]
    ingress_program_array: ProgramArray<MapData>,
    #[allow(dead_code)]
    egress_program_array: ProgramArray<MapData>,
}

impl System {
    pub async fn new() -> Result<Self, Error> {
        let (mut ingress_ebpf, ingress_program_array) = System::get_ingress_ebpf()?;
        let (mut egress_ebpf, egress_program_array) = System::get_egress_ebpf()?;
        let app_config = Arc::new(AppConfig::new()?);

        let ebpf_services = Arc::new(EbpfServices::new(
            app_config.clone(),
            &mut ingress_ebpf,
            &mut egress_ebpf,
        )?);

        let system = System {
            app_config,
            ebpf_services,
            ingress_ebpf,
            egress_ebpf,
            ingress_program_array,
            egress_program_array,
        };
        Ok(system)
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        let ebpf_services = self.ebpf_services.clone();
        Logging::initialize()?;
        log!(SystemLog::Initializing);
        self.aya_log_init()?;
        log!(SystemLog::InitializeComplete);
        self.attach_ebpf()?;

        ebpf_services.run().await?;
        self.run_http_server().await?;
        Ok(())
    }

    pub async fn terminate(&self) -> Result<(), Error> {
        let ebpf_services = self.ebpf_services.clone();
        log!(SystemLog::Terminating);

        ebpf_services.terminate();
        log!(SystemLog::TerminateComplete);
        Ok(())
    }

    fn aya_log_init(&mut self) -> Result<(), Error> {
        EbpfLogger::init(&mut self.ingress_ebpf).map_err(EbpfError::LoggerInitFailed)?;
        EbpfLogger::init(&mut self.egress_ebpf).map_err(EbpfError::LoggerInitFailed)?;
        Ok(())
    }

    fn attach_ebpf(&mut self) -> Result<(), Error> {
        let config = self.app_config.config.clone();
        let ingress_ifname = config.ingress_ifname;
        let egress_ifname = config.egress_ifname;
        Self::set_memory_limit()?;
        let ingress_xdp: &mut Xdp = self
            .ingress_ebpf
            .program_mut("net_guardia")
            .ok_or(EbpfError::ProgramNotFound)?
            .try_into()
            .map_err(EbpfError::GetProgramFailed)?;
        let egress_xdp: &mut Xdp = self
            .egress_ebpf
            .program_mut("net_guardia")
            .ok_or(EbpfError::ProgramNotFound)?
            .try_into()
            .map_err(EbpfError::GetProgramFailed)?;
        ingress_xdp.load().map_err(EbpfError::LoadProgramFailed)?;
        ingress_xdp
            .attach(&ingress_ifname, XdpFlags::DRV_MODE)
            .map_err(EbpfError::AttachProgramFailed)?;
        egress_xdp.load().map_err(EbpfError::LoadProgramFailed)?;
        egress_xdp
            .attach(&egress_ifname, XdpFlags::DRV_MODE)
            .map_err(EbpfError::AttachProgramFailed)?;
        Ok(())
    }

    async fn run_http_server(&self) -> Result<(), Error> {
        let app_config = self.app_config.clone();
        let access_control = self.ebpf_services.access_control.clone();
        let service = self.ebpf_services.service.clone();
        let statistics = self.ebpf_services.statistics.clone();
        let health = self.ebpf_services.health.clone();
        let port = self.app_config.http_server_bind_port;
        HttpServer::new(move || {
            let cors = actix_cors::Cors::default()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600);
            App::new()
                .wrap(cors)
                .app_data(web::Data::from(app_config.clone()))
                .app_data(web::Data::from(access_control.clone()))
                .app_data(web::Data::from(service.clone()))
                .app_data(web::Data::from(statistics.clone()))
                .app_data(web::Data::from(health.clone()))
                .service(control::initialize())
                .service(misc::initialize())
                .default_service(route().to(default::default_route))
        })
            .bind(format!("0.0.0.0:{}", port))
            .map_err(HttpError::BindPortError)?
            .run()
            .await
            .map_err(HttpError::ServerPanic)?;
        Ok(())
    }

    fn get_ingress_ebpf() -> Result<(Ebpf, ProgramArray<MapData>), Error> {
        let mut ingress_ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/net-guardia-ingress"
        )))
            .map_err(EbpfError::EbpfNotFound)?;
        let program_array = ingress_ebpf.take_map("PROGRAM_ARRAY").ok_or(EbpfError::MapNotFound)?;
        let mut program_array = ProgramArray::try_from(program_array).map_err(EbpfError::MapOperationError)?;
        Self::load_program(&mut ingress_ebpf, &mut program_array, "access_control", ingress::ACCESS_CONTROL)?;
        Self::load_program(&mut ingress_ebpf, &mut program_array, "service", ingress::SERVICE)?;
        Self::load_program(&mut ingress_ebpf, &mut program_array, "statistics", ingress::STATISTICS)?;
        Self::load_program(&mut ingress_ebpf, &mut program_array, "transmission", ingress::TRANSMISSION)?;
        Ok((ingress_ebpf, program_array))
    }

    fn get_egress_ebpf() -> Result<(Ebpf, ProgramArray<MapData>), Error> {
        let mut egress_ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/net-guardia-egress"
        )))
            .map_err(EbpfError::EbpfNotFound)?;
        let program_array = egress_ebpf.take_map("PROGRAM_ARRAY").ok_or(EbpfError::MapNotFound)?;
        let mut program_array = ProgramArray::try_from(program_array).map_err(EbpfError::MapOperationError)?;
        Self::load_program(&mut egress_ebpf, &mut program_array, "statistics", egress::STATISTICS)?;
        Ok((egress_ebpf, program_array))
    }

    fn load_program(
        ebpf: &mut Ebpf,
        program_array: &mut ProgramArray<MapData>,
        function_name: &str,
        index: u32,
    ) -> Result<(), Error> {
        let program: &mut Xdp = ebpf
            .program_mut(function_name)
            .ok_or(EbpfError::ProgramNotFound)?
            .try_into()
            .map_err(EbpfError::MapOperationError)?;
        program.load().map_err(EbpfError::AttachProgramFailed)?;
        let fd = program.fd().map_err(|_| EbpfError::UnknownError)?;
        program_array.set(index, fd, 0).map_err(EbpfError::MapOperationError)?;
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
}
