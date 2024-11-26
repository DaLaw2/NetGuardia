use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use net_guardia_common::model::general::MAX_RULES;
use net_guardia_common::model::ip_port_key::IpPortKey;

#[map]
static FORWARD_RULES: HashMap<IpPortKey, IpPortKey> = HashMap::with_max_entries(MAX_RULES, 0);

pub fn get_forward_rule(source_ip: u32, source_port: u16) -> Option<IpPortKey> {
    unsafe {
        let key = [source_ip, source_port as u32];
        FORWARD_RULES.get(&key).cloned()
    }
}
