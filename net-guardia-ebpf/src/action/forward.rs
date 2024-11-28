use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use net_guardia_common::model::ip_address::{AddrPortV4, AddrPortV6};
use net_guardia_common::MAX_RULES;

#[map]
static FORWARD_RULES_IPV4: HashMap<AddrPortV4, AddrPortV4> = HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static FORWARD_RULES_IPV6: HashMap<AddrPortV6, AddrPortV6> = HashMap::with_max_entries(MAX_RULES, 0);

#[inline(always)]
pub fn get_forward_rule_ipv4(source: &AddrPortV4) -> Option<AddrPortV4> {
    unsafe { FORWARD_RULES_IPV4.get(source).cloned() }
}

#[inline(always)]
pub fn get_forward_rule_ipv6(source: &AddrPortV6) -> Option<AddrPortV6> {
    unsafe { FORWARD_RULES_IPV6.get(&source).cloned() }
}
