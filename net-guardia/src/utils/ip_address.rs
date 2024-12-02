use net_guardia_common::MAX_RULES_PORT;
use net_guardia_common::model::ip_address::Port;

pub fn convert_ports_to_vec(ports: [u16; MAX_RULES_PORT]) -> Vec<Port> {
    let mut filtered_ports: Vec<Port> = ports
        .into_iter()
        .filter(|&port| port != 0)
        .collect();
    if filtered_ports.is_empty() {
        filtered_ports.push(0);
    }
    filtered_ports
}
