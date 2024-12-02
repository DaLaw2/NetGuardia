use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use net_guardia_common::model::ip_address::{EbpfAddrPortV4, EbpfAddrPortV6};
use net_guardia_common::MAX_RULES;

#[map]
static IPV4_FORWARD_RULES: HashMap<EbpfAddrPortV4, EbpfAddrPortV4> = HashMap::with_max_entries(MAX_RULES, 0);
#[map]
static IPV6_FORWARD_RULES: HashMap<EbpfAddrPortV6, EbpfAddrPortV6> = HashMap::with_max_entries(MAX_RULES, 0);

#[inline(always)]
pub fn get_ipv4_forward_rule(source: &EbpfAddrPortV4) -> Option<EbpfAddrPortV4> {
    unsafe { IPV4_FORWARD_RULES.get(source).cloned() }
}

#[inline(always)]
pub fn get_ipv6_forward_rule(source: &EbpfAddrPortV6) -> Option<EbpfAddrPortV6> {
    unsafe { IPV6_FORWARD_RULES.get(&source).cloned() }
}
