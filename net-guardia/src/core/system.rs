use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use actix_web::web::route;
use actix_web::{web, App, HttpServer};
use aya::maps::{Array, MapData, ProgramArray};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use aya_log::EbpfLogger;
use common::define::pipeline::*;
use macros::log;

use crate::core::auth::jwt::JwtService;
use crate::core::auth::password;
use crate::core::database::Database;
use crate::core::ebpf::EbpfServices;
use crate::core::infrastructure::app_config::AppConfig;
use crate::core::infrastructure::MLService;
#[cfg(feature = "license")]
use crate::core::license::LicenseInfo;
#[cfg(feature = "license")]
use crate::core::license::validator::validate_license;
use crate::core::ml::config_loader::InferenceConfig;
use crate::model::error::ebpf::EbpfError;
use crate::model::error::http::HttpError;
use crate::model::error::misc::MiscError;
use crate::model::direction::FlowDirection;
use crate::model::error::Error;
use crate::model::list_type::ListType;
use crate::model::log::ml::MLLog;
use crate::model::log::system::SystemLog;
use crate::utils::logging::Logging;
use crate::web::api::{acl, auth, filter, rate_limit as rate_limit_api, stats, health as health_api, ml, system as system_api, default, ws};

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
    pub db: Arc<Database>,
    pub jwt_service: Arc<JwtService>,
    #[cfg(feature = "license")]
    pub license_info: Arc<LicenseInfo>,
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
            db.insert_user("admin", &hash, "admin", true)?;
            tracing::warn!("Default admin user created with password 'admin' — you must change it on first login");
        }

        // Ensure enforce_mode setting exists (default: monitor)
        if db.get_setting("enforce_mode")?.is_none() {
            db.set_setting("enforce_mode", "monitor")?;
        }

        let jwt_service = Arc::new(JwtService::new(&db, app_config.http.jwt_expiry_hours)?);

        let ebpf_services = Arc::new(EbpfServices::new(
            app_config.clone(),
            &mut ingress_ebpf,
            &mut egress_ebpf,
        )?);

        let app_services = Arc::new(MLService::new(app_config.clone(), inference_config.clone())?);

        // Load persisted DNS blacklist
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

        // Load persisted geo-blocked countries
        if let Ok(countries) = db.load_geo_countries() {
            if !countries.is_empty() {
                if let Err(e) = ebpf_services.geo_block.block_countries(&countries) {
                    tracing::warn!("Failed to restore geo-blocked countries: {}", e);
                } else {
                    tracing::info!("Restored {} geo-blocked countries from database", countries.len());
                }
            }
        }

        // Load persisted rate limit config
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

        // Load persisted ACL rules
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

        Ok(System {
            app_config,
            inference_config,
            ebpf_services,
            app_services,
            db,
            jwt_service,
            #[cfg(feature = "license")]
            license_info,
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

        let ingress_mode = Self::attach_xdp(&mut self.ingress_ebpf, &ingress_ifname, true)?;
        let egress_mode = Self::attach_xdp(&mut self.egress_ebpf, &egress_ifname, false)?;

        // Store XDP mode in settings for health API reporting
        if let Err(e) = self.db.set_setting("xdp_ingress_mode", &ingress_mode) {
            tracing::warn!("Failed to store XDP ingress mode: {}", e);
        }
        if let Err(e) = self.db.set_setting("xdp_egress_mode", &egress_mode) {
            tracing::warn!("Failed to store XDP egress mode: {}", e);
        }

        Ok(())
    }

    fn attach_xdp(ebpf: &mut Ebpf, ifname: &str, already_loaded: bool) -> Result<String, Error> {
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
        let db = self.db.clone();
        let jwt_service = self.jwt_service.clone();
        #[cfg(feature = "license")]
        let license_info = self.license_info.clone();
        let port = self.app_config.http.http_server_bind_port;
        HttpServer::new(move || {
            let cors = actix_cors::Cors::default()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600);
            let app = App::new()
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
                .app_data(web::Data::from(db.clone()))
                .app_data(web::Data::from(jwt_service.clone()));
            #[cfg(feature = "license")]
            let app = app.app_data(web::Data::from(license_info.clone()));
            app.service(
                    web::scope("/api")
                        .wrap(crate::core::auth::middleware::AuthMiddleware)
                        .service(auth::initialize())
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
