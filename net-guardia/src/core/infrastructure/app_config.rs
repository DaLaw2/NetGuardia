use std::fs;

use crate::model::config::{
    AppConfigTable, HttpConfig, InferenceConfig as InfConfig, MiscConfig, NetworkConfig, PipelineConfig,
};
use crate::model::error::system::SystemError;
use crate::model::error::Error;

pub struct AppConfig {
    pub http: HttpConfig,
    pub network: NetworkConfig,
    pub inference: InfConfig,
    #[allow(dead_code)]
    pub misc: MiscConfig,
    pub pipeline: PipelineConfig,
}

impl AppConfig {
    pub fn new() -> Result<Self, Error> {
        let toml_string = fs::read_to_string("./config.toml").map_err(SystemError::ConfigNotFound)?;
        let table = toml::from_str::<AppConfigTable>(&toml_string).map_err(|_| SystemError::InvalidConfig)?;
        if !Self::validate(&table) {
            Err(SystemError::InvalidConfig)?
        }
        Ok(Self {
            http: table.http,
            network: table.network,
            inference: table.inference,
            misc: table.misc,
            pipeline: table.pipeline,
        })
    }

    fn validate(table: &AppConfigTable) -> bool {
        let net = &table.network;
        let inf = &table.inference;
        net.refresh_interval <= 3600
            && net.combined_queue_count > 0
            && net.fill_queue_size > 0
            && net.comp_queue_size > 0
            && net.tx_queue_size > 0
            && net.rx_queue_size > 0
            && net.frame_size > 0
            && net.frame_count > 0
            && table.http.http_server_bind_port > 0
            && inf.max_concurrent_flows > 0
            && inf.min_packets_for_inference > 0
            && inf.inference_interval_secs > 0
            && inf.inference_batch_size > 0
    }
}
