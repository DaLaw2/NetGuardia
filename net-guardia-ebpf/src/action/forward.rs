use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use net_guardia_common::model::ip_address::{EbpfAddrPortV4, EbpfAddrPortV6};
use net_guardia_common::MAX_RULES;

#[map]
static FORWARD_RULES_IPV4: HashMap<EbpfAddrPortV4, EbpfAddrPortV4> = HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static FORWARD_RULES_IPV6: HashMap<EbpfAddrPortV6, EbpfAddrPortV6> = HashMap::with_max_entries(MAX_RULES, 0);

#[inline(always)]
pub fn get_forward_rule_ipv4(source: &EbpfAddrPortV4) -> Option<EbpfAddrPortV4> {
    unsafe { FORWARD_RULES_IPV4.get(source).cloned() }
}

#[inline(always)]
pub fn get_forward_rule_ipv6(source: &EbpfAddrPortV6) -> Option<EbpfAddrPortV6> {
    unsafe { FORWARD_RULES_IPV6.get(&source).cloned() }
}
