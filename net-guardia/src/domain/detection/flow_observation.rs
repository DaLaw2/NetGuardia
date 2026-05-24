#[derive(Debug, Clone)]
pub struct FlowObservation {
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: u8,
    pub packet_count: u64,
    pub flow_duration_us: u64,
}
