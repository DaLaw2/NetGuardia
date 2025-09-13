use std::sync::OnceLock;
use std::time::Duration;

use actix_web::web::route;
use actix_web::{App, HttpServer};
use aya::maps::{MapData, ProgramArray};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use aya_log::EbpfLogger;
use macros::log;
use sysinfo::System as SystemInfo;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::core::app_config::AppConfig;
use crate::core::control::Control;
use crate::core::health::SystemHealth;
use crate::core::statistics::Statistics;
use crate::model::error::ebpf::EbpfError;
use crate::model::error::http::HttpError;
use crate::model::error::misc::MiscError;
use crate::model::error::Error;
use crate::model::log::ebpf::EbpfLog;
use crate::model::log::system::SystemLog;
use crate::utils::logging::Logging;
use crate::web::api::{control, default, health, misc, statistics};

static SYSTEM: OnceLock<RwLock<System>> = OnceLock::new();

pub struct System {
    pub ingress_ebpf: Ebpf,
    pub egress_ebpf: Ebpf,
    pub boot_time: u64,
    #[allow(dead_code)]
    ingress_program_array: ProgramArray<MapData>,
    #[allow(dead_code)]
    egress_program_array: ProgramArray<MapData>,
}

impl System {
    pub async fn initialize() -> Result<(), Error> {
        Logging::initialize().await?;
        log!(SystemLog::Initializing);

        AppConfig::initialization().await?;

        SystemHealth::initialize(Duration::from_secs(5)).await;

        System::ebpf_initialize().await?;
        Statistics::initialize().await?;
        Control::initialize().await?;

        log!(SystemLog::InitializeComplete);
        Ok(())
    }

    async fn ebpf_initialize() -> Result<(), Error> {
        let config = AppConfig::now().await;
        let ingress_interface = config.ingress_ifindex;
        let egress_interface = config.egress_ifindex;
        let boot_time = SystemInfo::boot_time() * 1_000_000_000;
        Self::set_memory_limit()?;
        let (mut ingress_ebpf, ingress_program_array) = System::get_ingress_ebpf()?;
        let ingress_program: &mut Xdp = ingress_ebpf
            .program_mut("net_guardia")
            .ok_or(EbpfError::ProgramNotFound)?
            .try_into()
            .map_err(EbpfError::GetProgramFailed)?;
        let (mut egress_ebpf, egress_program_array) = System::get_egress_ebpf()?;
        let egress_program: &mut Xdp = egress_ebpf
            .program_mut("net_guardia")
            .ok_or(EbpfError::ProgramNotFound)?
            .try_into()
            .map_err(EbpfError::GetProgramFailed)?;
        ingress_program.load().map_err(EbpfError::LoadProgramFailed)?;
        ingress_program
            .attach(&ingress_interface, XdpFlags::default())
            .map_err(EbpfError::AttachProgramFailed)?;
        egress_program.load().map_err(EbpfError::LoadProgramFailed)?;
        egress_program
            .attach(&egress_interface, XdpFlags::default())
            .map_err(EbpfError::AttachProgramFailed)?;
        let system = System {
            ingress_ebpf,
            egress_ebpf,
            boot_time,
            ingress_program_array,
            egress_program_array,
        };
        SYSTEM.get_or_init(|| RwLock::new(system));
        log!(EbpfLog::AttachProgramSuccess);
        Ok(())
    }

    fn get_ingress_ebpf() -> Result<(Ebpf, ProgramArray<MapData>), Error> {
        let mut ingress_ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/net-guardia-ingress"
        )))
        .map_err(EbpfError::EbpfNotFound)?;
        EbpfLogger::init(&mut ingress_ebpf).map_err(EbpfError::LoggerInitFailed)?;
        let program_array = ingress_ebpf.take_map("PROGRAM_ARRAY").ok_or(EbpfError::MapNotFound)?;
        let mut program_array = ProgramArray::try_from(program_array).map_err(EbpfError::MapOperationError)?;
        Self::load_program(&mut ingress_ebpf, &mut program_array, "access_control", 0)?;
        Self::load_program(&mut ingress_ebpf, &mut program_array, "service", 1)?;
        Self::load_program(&mut ingress_ebpf, &mut program_array, "statistics", 2)?;
        Ok((ingress_ebpf, program_array))
    }

    fn get_egress_ebpf() -> Result<(Ebpf, ProgramArray<MapData>), Error> {
        let mut egress_ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/net-guardia-egress"
        )))
        .map_err(EbpfError::EbpfNotFound)?;
        EbpfLogger::init(&mut egress_ebpf).map_err(EbpfError::LoggerInitFailed)?;
        let program_array = egress_ebpf.take_map("PROGRAM_ARRAY").ok_or(EbpfError::MapNotFound)?;
        let mut program_array = ProgramArray::try_from(program_array).map_err(EbpfError::MapOperationError)?;
        Self::load_program(&mut egress_ebpf, &mut program_array, "statistics", 0)?;
        Ok((egress_ebpf, program_array))
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

    pub async fn run() -> Result<(), Error> {
        log!(SystemLog::Online);

        Statistics::run().await;

        let config = AppConfig::now().await;
        HttpServer::new(|| {
            let cors = actix_cors::Cors::default()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600);
            App::new()
                .wrap(cors)
                .service(statistics::initialize())
                .service(control::initialize())
                .service(misc::initialize())
                .service(health::initialize())
                .default_service(route().to(default::default_route))
        })
        .bind(format!("0.0.0.0:{}", config.http_server_bind_port))
        .map_err(HttpError::BindPortError)?
        .run()
        .await
        .map_err(HttpError::ServerPanic)?;
        Ok(())
    }

    pub async fn terminate() -> Result<(), Error> {
        log!(SystemLog::Terminating);

        Statistics::terminate().await;
        SystemHealth::shutdown().await;

        log!(SystemLog::TerminateComplete);
        Ok(())
    }

    pub async fn instance() -> RwLockReadGuard<'static, System> {
        // Initialization has been ensured
        let once_lock = SYSTEM.get().unwrap();
        // There is no lock acquired multiple times, so this is safe
        once_lock.read().await
    }

    pub async fn instance_mut() -> RwLockWriteGuard<'static, System> {
        // Initialization has been ensured
        let once_lock = SYSTEM.get().unwrap();
        // There is no lock acquired multiple times, so this is safe
        once_lock.write().await
    }

    pub async fn boot_time() -> u64 {
        let system = System::instance().await;
        system.boot_time
    }
}
