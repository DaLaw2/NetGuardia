use aya::maps::{HashMap as AyaHashMap, MapData};
use net_guardia_common::MAX_RULES_PORT;
use net_guardia_common::model::ip_address::{IPv4, IPv6, Port};

pub struct Control {
    ipv4_black_list: AyaHashMap<MapData, IPv4, [Port; MAX_RULES_PORT]>,
    ipv6_black_list: AyaHashMap<MapData, IPv6, [Port; MAX_RULES_PORT]>,
}

