use serde::Serialize;
use net_guardia_common::model::flow_stats::EbpfFlowStats;

#[derive(Serialize, Debug, Clone)]
pub struct FlowStats {
    pub bytes: u64,
    pub packets: u64,
    pub last_seen: u64,
}

impl From<EbpfFlowStats> for FlowStats {
    fn from(ebpf_flow_status: EbpfFlowStats) -> Self {
        FlowStats {
            bytes: ebpf_flow_status[0],
            packets: ebpf_flow_status[1],
            last_seen: ebpf_flow_status[2],
        }
    }
}

impl From<FlowStats> for EbpfFlowStats {
    fn from(flow_status: FlowStats) -> Self {
        [flow_status.bytes, flow_status.packets, flow_status.last_seen]
    }
}
