use serde::Serialize;

use crate::domain::data_plane::ip_version::IpVersion;

#[derive(Debug, Clone, Serialize)]
pub struct DropEventMessage {
    pub timestamp_ns: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub reason: String,
    pub ip_version: IpVersion,
}

#[derive(Default, Clone, Serialize)]
pub struct DropCounters {
    pub acl_blacklist: u64,
    pub rate_limit_pkt: u64,
    pub rate_limit_syn: u64,
    pub rate_limit_udp: u64,
    pub rate_limit_dns: u64,
    pub protocol_filter: u64,
    pub dns_blacklist: u64,
    pub geo_block: u64,
    pub total: u64,
}
