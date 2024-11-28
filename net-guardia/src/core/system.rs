use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use log::info;
use tracing::warn;
use crate::core::config_manager::ConfigManager;
use crate::core::monitor::Monitor;
use crate::utils::log_entry::ebpf::EbpfEntry;
use crate::utils::log_entry::system::SystemEntry;
use crate::utils::logging::Logging;

pub struct System;

impl System {
    pub async fn initialize() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Initializing);
        ConfigManager::initialization().await?;
        Logging::initialize().await?;
        System::ebpf_initialize().await?;
        Monitor::initialize().await?;
        info!("{}", SystemEntry::InitializeComplete);
        Ok(())
    }

    async fn ebpf_initialize() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Initializing);
        let config = ConfigManager::now().await;
        let interface = config.ingress_ifindex;
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/net-guardia"
        )))?;
        if let Err(_) = aya_log::EbpfLogger::init(&mut ebpf) {
            warn!("{}", EbpfEntry::LoggerInitializeFailed);
        }
        let program: &mut Xdp = ebpf.program_mut("net_guardia").unwrap().try_into()?;
        program.load()?;
        program.attach(&interface, XdpFlags::default())
            .context(EbpfEntry::AttachProgramFailed)?;
        info!("{}", EbpfEntry::AttachProgramSuccess);
        info!("{}", SystemEntry::InitializeComplete);
        Ok(())
    }

    pub async fn run() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Online);
        unimplemented!();
        Ok(())
    }

    pub async fn terminate() -> anyhow::Result<()> {
        info!("{}", SystemEntry::Terminating);
        unimplemented!();
        info!("{}", SystemEntry::TerminateComplete);
        Ok(())
    }
}
