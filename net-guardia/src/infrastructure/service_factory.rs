use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use aya::maps::{Array, MapData, ProgramArray};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use aya_log::EbpfLogger;
use common::define::pipeline::*;

use crate::core::auth::jwt::JwtService;
use crate::core::auth::password;
use crate::adapter::persistence::Database;
use crate::core::ebpf::EbpfServices;
use crate::infrastructure::app_config::AppConfig;
use crate::infrastructure::app_services::AppServices;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::infrastructure::enforce_mode_handler::EnforceModeHandler;
use crate::interface::communication::command_types::ChangeEnforceModeCommand;
use crate::interface::communication::query_types::GetEnforceModeQuery;
use crate::interface::port::repository::RepositoryPort;
#[cfg(feature = "license")]
use crate::core::license::LicenseInfo;
#[cfg(feature = "license")]
use crate::core::license::validator::validate_license;
use crate::core::ml::config_loader::InferenceConfig;
use crate::model::direction::FlowDirection;
use crate::model::error::ebpf::EbpfError;
use crate::model::error::misc::MiscError;
use crate::model::error::Error;
use crate::model::list_type::ListType;

/// Holds all Arc-wrapped services that make up the running application.
pub struct AppState {
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
    pub ingress_program_array: ProgramArray<MapData>,
}

/// Maps stage name (from config.toml) to (function_name, stage_id).
fn stage_registry() -> HashMap<&'static str, (&'static str, u32)> {
    HashMap::from([
        ("access_control", ("access_control", STAGE_ACCESS_CONTROL)),
        ("rate_limit", ("rate_limit", STAGE_RATE_LIMIT)),
        ("service", ("protocol_filter", STAGE_SERVICE)),
    ])
}

/// Factory responsible for creating and wiring all application services.
pub struct ServiceFactory;

impl ServiceFactory {
    /// Build all services and return the complete application state.
    pub async fn build() -> Result<AppState, Error> {
        let mut ingress_ebpf = Self::load_ebpf("ingress")?;
        let mut egress_ebpf = Self::load_ebpf("egress")?;
        let app_config = Arc::new(AppConfig::new()?);

        #[cfg(feature = "license")]
        let license_info = Arc::new(validate_license(
            &app_config.misc.license_file,
            &app_config.network.ingress_ifname,
            &app_config.network.egress_ifname,
        )?);

        let ingress_program_array = Self::configure_ingress_pipeline(
            &mut ingress_ebpf,
            &app_config.pipeline.ingress,
        )?;

        let inference_config = Arc::new(InferenceConfig::load_file(&app_config.inference.models_config_name)?);

        // Write queue count to eBPF maps for symmetric hash redirect
        let num_queues = app_config.network.combined_queue_count;
        Self::write_num_queues(&mut ingress_ebpf, num_queues)?;
        Self::write_num_queues(&mut egress_ebpf, num_queues)?;

        let db = Arc::new(Database::new(&app_config.misc.database_path)?);

        // Create default admin user if no users exist
        if db.user_count().unwrap_or(0) == 0 {
            let hash = password::hash_password("admin")?;
            let admin_user_id = db.insert_user("admin", &hash, "admin", true)?;
            // Assign to Administrator group
            if let Ok(groups) = db.list_user_groups()
                && let Some((group_id, _, _, _, _)) = groups.into_iter().find(|(_, name, _, _, _)| name == "Administrator")
            {
                let _ = db.set_user_groups(admin_user_id, &[group_id]);
            }
            tracing::warn!("Default admin user created with password 'admin' — you must change it on first login");
        }

        // Ensure enforce_mode setting exists (default: monitor)
        if db.get_setting("enforce_mode")?.is_none() {
            db.set_setting("enforce_mode", "monitor")?;
        }

        let jwt_service = Arc::new(JwtService::new(db.as_ref(), app_config.http.jwt_expiry_hours)?);

        let ebpf_services = Arc::new(EbpfServices::new(
            app_config.clone(),
            &mut ingress_ebpf,
            &mut egress_ebpf,
        )?);

        let app_services = Arc::new(AppServices::new(app_config.clone(), inference_config.clone())?);

        // Create CommunicationManager and register enforce-mode handler
        let comm = Arc::new(CommunicationManager::new());
        let enforce_handler = Arc::new(EnforceModeHandler::new(db.clone() as Arc<dyn RepositoryPort>));
        let _ = comm.clone()
            .with_service(enforce_handler)
            .command::<ChangeEnforceModeCommand>()
            .query::<GetEnforceModeQuery>()
            .build();

        // Restore persisted state from database
        Self::restore_dns_blacklist(&db, &ebpf_services);
        Self::restore_geo_countries(&db, &ebpf_services);
        Self::restore_rate_limits(&db, &ebpf_services);
        Self::restore_acl_rules(&db, &ebpf_services).await;

        Ok(AppState {
            app_config,
            inference_config,
            ebpf_services,
            app_services,
            db,
            jwt_service,
            comm,
            #[cfg(feature = "license")]
            license_info,
            ingress_ebpf,
            egress_ebpf,
            ingress_program_array,
        })
    }

    // --- eBPF loading helpers ---

    fn load_ebpf(name: &str) -> Result<Ebpf, Error> {
        let bytes = match name {
            "ingress" => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/net-guardia-ingress")),
            "egress" => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/net-guardia-egress")),
            _ => return Err(EbpfError::ProgramNotFound.into()),
        };
        Ok(Ebpf::load(bytes).map_err(EbpfError::EbpfNotFound)?)
    }

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
                .set(STAGE_ENTRY, STAGE_TRANSMISSION, 0)
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
        let fd = program.fd().map_err(|_| EbpfError::UnknownError)?;
        program_array
            .set(slot, fd, 0)
            .map_err(EbpfError::MapOperationError)?;
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
            Err(MiscError::RamLimitUnlockError(ret))?
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

        // Try DRV_MODE first (native XDP, best performance)
        match xdp.attach(ifname, XdpFlags::DRV_MODE) {
            Ok(_) => {
                tracing::info!("XDP attached to {} in native DRV_MODE", ifname);
                return Ok("drv".to_string());
            }
            Err(drv_err) => {
                tracing::warn!(
                    "XDP DRV_MODE failed on {}: {}. Falling back to SKB_MODE.",
                    ifname, drv_err
                );
            }
        }

        // Fallback to SKB_MODE (generic XDP, reduced performance)
        match xdp.attach(ifname, XdpFlags::SKB_MODE) {
            Ok(_) => {
                tracing::warn!(
                    "XDP attached to {} in generic SKB_MODE (reduced performance). \
                     For best performance, use a NIC with native XDP support (e.g., virtio-net, Intel i40e/ice).",
                    ifname
                );
                Ok("skb".to_string())
            }
            Err(skb_err) => {
                tracing::error!(
                    "XDP attach failed on {} with both DRV_MODE and SKB_MODE. \
                     Ensure the interface exists and supports XDP. \
                     Supported NICs: virtio-net, Intel i40e/ice/i350, Mellanox mlx5. \
                     SKB error: {}",
                    ifname, skb_err
                );
                Err(EbpfError::AttachProgramFailed(skb_err).into())
            }
        }
    }

    pub fn aya_log_init(ingress_ebpf: &mut Ebpf, egress_ebpf: &mut Ebpf) -> Result<(), Error> {
        EbpfLogger::init(ingress_ebpf).map_err(EbpfError::LoggerInitFailed)?;
        EbpfLogger::init(egress_ebpf).map_err(EbpfError::LoggerInitFailed)?;
        Ok(())
    }

    // --- State restoration helpers ---

    fn restore_dns_blacklist(db: &Database, ebpf_services: &EbpfServices) {
        if let Ok(domains) = db.load_dns_domains() {
            for domain in &domains {
                if let Err(e) = ebpf_services.dns_filter.add_domain(domain) {
                    tracing::warn!("Failed to restore DNS domain '{}': {}", domain, e);
                }
            }
            if !domains.is_empty() {
                tracing::info!("Restored {} DNS blacklist domains from database", domains.len());
            }
        }
    }

    fn restore_geo_countries(db: &Database, ebpf_services: &EbpfServices) {
        if let Ok(countries) = db.load_geo_countries()
            && !countries.is_empty() {
                if let Err(e) = ebpf_services.geo_block.block_countries(&countries) {
                    tracing::warn!("Failed to restore geo-blocked countries: {}", e);
                } else {
                    tracing::info!("Restored {} geo-blocked countries from database", countries.len());
                }
        }
    }

    fn restore_rate_limits(db: &Database, ebpf_services: &EbpfServices) {
        if let Ok(configs) = db.load_rate_limit_config() {
            for (key, value) in &configs {
                let result = match key.as_str() {
                    "packet_rate" => ebpf_services.rate_limit.set_packet_rate(*value),
                    "syn_rate" => ebpf_services.rate_limit.set_syn_rate(*value),
                    "udp_rate" => ebpf_services.rate_limit.set_udp_rate(*value),
                    "dns_rate" => ebpf_services.rate_limit.set_dns_rate(*value),
                    "window_ns" => ebpf_services.rate_limit.set_window_ns(*value),
                    _ => Ok(()),
                };
                if let Err(e) = result {
                    tracing::warn!("Failed to restore rate limit '{}': {}", key, e);
                }
            }
            if !configs.is_empty() {
                tracing::info!("Restored {} rate limit settings from database", configs.len());
            }
        }
    }

    async fn restore_acl_rules(db: &Database, ebpf_services: &EbpfServices) {
        if let Ok(rules) = db.load_acl_rules() {
            let mut restored = 0u32;
            for (ip_version, direction, list_type, ip_address, port) in &rules {
                let dir = match direction.as_str() {
                    "source" => FlowDirection::Source,
                    "destination" => FlowDirection::Destination,
                    other => {
                        tracing::warn!("Unknown ACL direction '{}', skipping", other);
                        continue;
                    }
                };
                let lt = match list_type.as_str() {
                    "whitelist" => ListType::White,
                    "blacklist" => ListType::Black,
                    other => {
                        tracing::warn!("Unknown ACL list type '{}', skipping", other);
                        continue;
                    }
                };
                let result = match ip_version {
                    4 => {
                        match ip_address.parse::<Ipv4Addr>() {
                            Ok(addr) => ebpf_services.access_control.add_ipv4_list(dir, lt, SocketAddrV4::new(addr, *port)).await,
                            Err(e) => {
                                tracing::warn!("Failed to parse IPv4 address '{}': {}", ip_address, e);
                                continue;
                            }
                        }
                    }
                    6 => {
                        match ip_address.parse::<Ipv6Addr>() {
                            Ok(addr) => ebpf_services.access_control.add_ipv6_list(dir, lt, SocketAddrV6::new(addr, *port, 0, 0)).await,
                            Err(e) => {
                                tracing::warn!("Failed to parse IPv6 address '{}': {}", ip_address, e);
                                continue;
                            }
                        }
                    }
                    other => {
                        tracing::warn!("Unknown IP version {}, skipping", other);
                        continue;
                    }
                };
                if let Err(e) = result {
                    tracing::warn!("Failed to restore ACL rule ({} {} {}:{}): {}", direction, list_type, ip_address, port, e);
                } else {
                    restored += 1;
                }
            }
            if restored > 0 {
                tracing::info!("Restored {} ACL rules from database", restored);
            }
        }
    }
}
