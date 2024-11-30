use crate::core::config_manager::ConfigManager;
use crate::core::monitor::Monitor;
use crate::utils::log_entry::ebpf::EbpfEntry;
use crate::utils::log_entry::system::SystemEntry;
use crate::utils::logging::Logging;
use crate::web::api::{default, monitor};
use actix_web::web::route;
use actix_web::{App, HttpServer};
use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use std::sync::OnceLock;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{error, info, warn};

static SYSTEM: OnceLock<RwLock<System>> = OnceLock::new();

pub struct System {
    pub ebpf: Ebpf,
}

impl System {
    pub async fn initialize() -> anyhow::Result<()> {
        Logging::initialize().await?;
        info!("{}", SystemEntry::Initializing);
        ConfigManager::initialization().await?;
        System::ebpf_initialize().await?;
        Monitor::initialize().await?;
        info!("{}", SystemEntry::InitializeComplete);
        Ok(())
    }

    async fn ebpf_initialize() -> anyhow::Result<()> {
        let config = ConfigManager::now().await;
        let interface = config.ingress_ifindex;
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/net-guardia"
        )))?;
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            error!("{}", e);
            warn!("{}", EbpfEntry::LoggerInitializeFailed);
        }
        let program: &mut Xdp = ebpf.program_mut("net_guardia").unwrap().try_into()?;
        program.load()?;
        program
            .attach(&interface, XdpFlags::default())
            .context(EbpfEntry::AttachProgramFailed)?;
        SYSTEM.get_or_init(|| RwLock::new(System { ebpf }));
        info!("{}", EbpfEntry::AttachProgramSuccess);
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
}
