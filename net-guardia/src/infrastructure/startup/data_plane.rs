use std::sync::Arc;

use arc_swap::ArcSwap;
use aya::Ebpf;
use aya::maps::{Array, MapData, ProgramArray};
use aya::programs::{Xdp, XdpFlags};
use aya_log::EbpfLogger;
use macros::log;
use net_guardia_abi::define::pipeline::*;

use crate::adapter::ebpf::EbpfServices;
use crate::common::error::Error;
use crate::common::log::system::SystemLog;
use crate::core::data_plane::dns_filter::DnsFilter;
use crate::domain::common::config::AppConfig;
use crate::domain::common::system::health::EbpfHealth;
use crate::domain::data_plane::error::EbpfError;
use crate::domain::data_plane::log::EbpfLog;
use crate::infrastructure::startup::{DataPlaneRuntime, FoundationRuntime};
use crate::interface::data_plane::dns_filter_api::DnsFilterPort;
use crate::interface::data_plane::dns_query_filter::DnsQueryFilter;

struct EbpfBuild {
    ingress: Ebpf,
    egress: Ebpf,
    program_array: ProgramArray<MapData>,
    services: EbpfServices,
}

pub fn build_data_plane(foundation: &FoundationRuntime) -> (DataPlaneRuntime, Arc<dyn DnsFilterPort>) {
    let dns_filter = Arc::new(DnsFilter::new());
    let dns_query_filter: Arc<dyn DnsQueryFilter> = dns_filter.clone();
    let dns_filter_port: Arc<dyn DnsFilterPort> = dns_filter;
    let data_plane = build_ebpf_runtime(foundation, dns_query_filter);
    (data_plane, dns_filter_port)
}

fn build_ebpf_runtime(foundation: &FoundationRuntime, dns_query_filter: Arc<dyn DnsQueryFilter>) -> DataPlaneRuntime {
    match try_build_ebpf(&foundation.app_config, dns_query_filter.clone()) {
        Ok(build) => DataPlaneRuntime {
            ingress_ebpf: Some(build.ingress),
            egress_ebpf: Some(build.egress),
            _ingress_program_array: Some(build.program_array),
            ebpf_services: Arc::new(build.services),
        },
        Err(_) => {
            log!(SystemLog::EbpfBringupFailed);
            foundation.ebpf_health.store(Arc::new(EbpfHealth::Unavailable));
            DataPlaneRuntime {
                ingress_ebpf: None,
                egress_ebpf: None,
                _ingress_program_array: None,
                ebpf_services: Arc::new(EbpfServices::unavailable(
                    foundation.app_config.clone(),
                    dns_query_filter,
                )),
            }
        }
    }
}

fn try_build_ebpf(
    app_config: &Arc<ArcSwap<AppConfig>>,
    dns_query_filter: Arc<dyn DnsQueryFilter>,
) -> Result<EbpfBuild, Error> {
    let mut ingress = load_ebpf("ingress")?;
    let mut egress = load_ebpf("egress")?;

    let config = app_config.load();
    let pipeline = configure_ingress_pipeline(&mut ingress, &config.pipeline.ingress)?;
    let num_queues = config.ebpf.combined_queue_count;
    drop(config);
    write_num_queues(&mut ingress, num_queues)?;
    write_num_queues(&mut egress, num_queues)?;

    let services = EbpfServices::new(app_config.clone(), &mut ingress, &mut egress, dns_query_filter)?;

    Ok(EbpfBuild {
        ingress,
        egress,
        program_array: pipeline,
        services,
    })
}

fn load_ebpf(name: &str) -> Result<Ebpf, Error> {
    let bytes = match name {
        "ingress" => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/net-guardia-ingress")),
        "egress" => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/net-guardia-egress")),
        _ => Err(EbpfError::ProgramNotFound)?,
    };
    Ok(Ebpf::load(bytes).map_err(EbpfError::EbpfNotFound)?)
}

fn configure_ingress_pipeline(ebpf: &mut Ebpf, stages: &[String]) -> Result<ProgramArray<MapData>, Error> {
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

    load_program(ebpf, &mut program_array, "transmission", STAGE_TRANSMISSION)?;

    if stages.is_empty() {
        next_stage
            .set(STAGE_ENTRY, STAGE_TRANSMISSION, 0)
            .map_err(EbpfError::MapOperationError)?;
        return Ok(program_array);
    }

    let mut slots: Vec<(u32, u32)> = Vec::new();
    for (i, stage_name) in stages.iter().enumerate() {
        let (func_name, stage_id) = match stage_name.as_str() {
            "access_control" => ("access_control", STAGE_ACCESS_CONTROL),
            "rate_limit" => ("rate_limit", STAGE_RATE_LIMIT),
            "service" => ("protocol_filter", STAGE_SERVICE),
            _ => Err(EbpfError::ProgramNotFound)?,
        };
        let slot = (i + 1) as u32;
        load_program(ebpf, &mut program_array, func_name, slot)?;
        slots.push((stage_id, slot));
    }

    next_stage
        .set(STAGE_ENTRY, slots[0].1, 0)
        .map_err(EbpfError::MapOperationError)?;

    for i in 0..slots.len() {
        let (stage_id, _) = slots[i];
        let next_slot = if i + 1 < slots.len() {
            slots[i + 1].1
        } else {
            STAGE_TRANSMISSION
        };
        next_stage
            .set(stage_id, next_slot, 0)
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
    let fd = program.fd().map_err(EbpfError::ProgramFdFailed)?;
    program_array.set(slot, fd, 0).map_err(EbpfError::MapOperationError)?;
    Ok(())
}

fn write_num_queues(ebpf: &mut Ebpf, num_queues: u32) -> Result<(), Error> {
    let map = ebpf.map_mut("NUM_QUEUES").ok_or(EbpfError::MapNotFound)?;
    let mut arr = Array::<_, u32>::try_from(map).map_err(EbpfError::MapOperationError)?;
    arr.set(0, num_queues, 0).map_err(EbpfError::MapOperationError)?;
    Ok(())
}

pub fn set_memory_limit() -> Result<(), Error> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        Err(EbpfError::MemoryLimitUnlockFailed(ret))?
    }
    Ok(())
}

pub fn attach_xdp(ebpf: &mut Ebpf, ifname: &str, already_loaded: bool) -> Result<String, Error> {
    let xdp: &mut Xdp = ebpf
        .program_mut("net_guardia")
        .ok_or(EbpfError::ProgramNotFound)?
        .try_into()
        .map_err(EbpfError::GetProgramFailed)?;
    if !already_loaded {
        xdp.load().map_err(EbpfError::LoadProgramFailed)?;
    }
    match xdp.attach(ifname, XdpFlags::DRV_MODE) {
        Ok(_) => {
            log!(EbpfLog::XdpAttachedNative(ifname.to_string()));
            return Ok("drv".to_string());
        }
        Err(drv_err) => {
            log!(EbpfLog::XdpDrvModeFailed(ifname.to_string(), drv_err.to_string()));
        }
    }
    match xdp.attach(ifname, XdpFlags::SKB_MODE) {
        Ok(_) => {
            log!(EbpfLog::XdpAttachedSkb(ifname.to_string()));
            Ok("skb".to_string())
        }
        Err(skb_err) => {
            log!(EbpfLog::XdpAttachFailed(ifname.to_string(), skb_err.to_string()));
            Err(EbpfError::AttachProgramFailed(skb_err))?
        }
    }
}

pub fn aya_log_init(ingress_ebpf: &mut Ebpf, egress_ebpf: &mut Ebpf) -> Result<(), Error> {
    EbpfLogger::init(ingress_ebpf).map_err(EbpfError::LoggerInitFailed)?;
    EbpfLogger::init(egress_ebpf).map_err(EbpfError::LoggerInitFailed)?;
    Ok(())
}
