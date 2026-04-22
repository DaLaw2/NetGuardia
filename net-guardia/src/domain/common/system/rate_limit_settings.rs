use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct RateLimitSettings {
    pub packet_rate: Option<u64>,
    pub syn_rate: Option<u64>,
    pub udp_rate: Option<u64>,
    pub dns_rate: Option<u64>,
    pub window_ns: Option<u64>,
}
