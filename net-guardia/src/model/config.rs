use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ConfigTable {
    #[serde(rename = "Config")]
    pub config: Config,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub ingress_ifindex: String,
    pub egress_ifindex: String,
    pub management_ifindex: String,
    pub refresh_interval: u64,
    pub http_server_bind_port: u16
}
