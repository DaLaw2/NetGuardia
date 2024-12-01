use crate::model::flow_stats::FlowStats;
use net_guardia_common::model::flow_stats::EbpfFlowStats as EbpfFlowStats;
use net_guardia_common::model::ip_address::{
    EbpfAddrPortV4 as EbpfAddrPortV4, EbpfAddrPortV6 as EbpfAddrPortV6,
};
use std::collections::HashMap;
use crate::utils::definition::IntoString;

pub fn transform_ipv4_flow_data(
    original: HashMap<EbpfAddrPortV4, EbpfFlowStats>,
) -> HashMap<String, FlowStats> {
    original
        .into_iter()
        .map(|(key, value)| (key.into_string(), FlowStats::from(value)))
        .collect()
}

pub fn transform_ipv6_flow_data(
    original: HashMap<EbpfAddrPortV6, EbpfFlowStats>,
) -> HashMap<String, FlowStats> {
    original
        .into_iter()
        .map(|(key, value)| (key.into_string(), FlowStats::from(value)))
        .collect()
}
