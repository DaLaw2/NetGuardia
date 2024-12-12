use crate::core::config_manager::ConfigManager;
use crate::core::control::Control;
use crate::core::monitor::Monitor;
use crate::utils::log_entry::ebpf::EbpfEntry;
use crate::utils::log_entry::system::SystemEntry;
use crate::utils::logging::Logging;
use crate::web::api::{control, default, misc, monitor};
use actix_web::web::route;
use actix_web::{App, HttpServer};
use anyhow::Context;
use aya::maps::{MapData, ProgramArray};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use std::sync::OnceLock;
use sysinfo::System as SystemInfo;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{error, info, warn};

static SYSTEM: OnceLock<RwLock<System>> = OnceLock::new();

pub struct System {
    pub ebpf: Ebpf,
    pub boot_time: u64,
    #[allow(dead_code)]
    program_array: ProgramArray<MapData>,
}

impl System {
    pub async fn initialize() -> anyhow::Result<()> {
        Logging::initialize().await?;
        info!("{}", SystemEntry::Initializing);
        ConfigManager::initialization().await?;
        System::ebpf_initialize().await?;
        Monitor::initialize().await?;
        Control::initialize().await?;
        info!("{}", SystemEntry::InitializeComplete);
        Ok(())
    }

    async fn ebpf_initialize() -> anyhow::Result<()> {
        let config = ConfigManager::now().await;
        let interface = config.ingress_ifindex;
        let boot_time = SystemInfo::boot_time() * 1_000_000_000;
        Self::set_memory_limit()?;
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/net-guardia"
        )))?;
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            error!("{}", e);
            warn!("{}", EbpfEntry::LoggerInitializeFailed);
        }
        let mut program_array = ProgramArray::try_from(ebpf.take_map("PROGRAM_ARRAY").unwrap())?;
        Self::load_program(&mut ebpf, &mut program_array, "access_control", 0)?;
        Self::load_program(&mut ebpf, &mut program_array, "service", 1)?;
        // Self::load_program(&mut ebpf, &mut program_array, "defence", 2)?;
        Self::load_program(&mut ebpf, &mut program_array, "sampling", 3)?;
        Self::load_program(&mut ebpf, &mut program_array, "monitor", 4)?;
        let program: &mut Xdp = ebpf.program_mut("net_guardia").unwrap().try_into()?;
        program.load()?;
        program
            .attach(&interface, XdpFlags::default())
            .context(EbpfEntry::AttachProgramFailed)?;
        let system = System {
            ebpf,
            boot_time,
            program_array,
        };
        SYSTEM.get_or_init(|| RwLock::new(system));
        info!("{}", EbpfEntry::AttachProgramSuccess);
        Ok(())
    }

    fn set_memory_limit() -> anyhow::Result<()> {
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            info!("Failed to remove limit on locked memory, ret is: {}", ret);
        }
        Ok(())
    }

    fn load_program(
        ebpf: &mut Ebpf,
        program_array: &mut ProgramArray<MapData>,
        function_name: &str,
        index: u32,
    ) -> anyhow::Result<()> {
        let program: &mut Xdp = ebpf.program_mut(function_name).unwrap().try_into()?;
        program.load()?;
        let fd = program.fd()?;
        program_array.set(index, fd, 0)?;
        Ok(())
    }

    pub async fn run() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Online);
        Monitor::run().await;
        let config = ConfigManager::now().await;
        HttpServer::new(|| {
            let cors = actix_cors::Cors::default()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600);
            App::new()
                .wrap(cors)
                .service(monitor::initialize())
                .service(control::initialize())
                .service(misc::initialize())
                .default_service(route().to(default::default_route))
        })
        .bind(format!("0.0.0.0:{}", config.http_server_bind_port))?
        .run()
        .await?;
        Ok(())
    }

    pub async fn terminate() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Terminating);
        Monitor::terminate().await;
        info!("{}", SystemEntry::TerminateComplete);
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
