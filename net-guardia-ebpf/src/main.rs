#![no_std]
#![no_main]

mod action;
mod utils;

use crate::utils::parsing;
use action::{blocking, monitor};
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
#[allow(unused_imports)]
use aya_log_ebpf::info;
use network_types::eth::EtherType;
use crate::action::{defence, service};

#[xdp]
pub fn net_guardia(ctx: XdpContext) -> u32 {
    match try_net_guardia(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_net_guardia(ctx: XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    match parsing::parse_ether_type(start, end)? {
        EtherType::Ipv4 => {
            let event = parsing::parse_ipv4_packet(start, end)?;
            if blocking::ipv4_should_block(&event) {
                return Ok(xdp_action::XDP_DROP);
            }
            if service::ipv4_service_rule_violation(start, end, &event) {
                return Ok(xdp_action::XDP_DROP);
            }
            // if defence::is_attack_ipv4(&event) {
            //     return Ok(xdp_action::XDP_DROP);
            // }
            monitor::ipv4_update_stats(&event);
        }
        EtherType::Ipv6 => {
            let event = parsing::parse_ipv6_packet(start, end)?;
            if blocking::ipv6_should_block(&event) {
                return Ok(xdp_action::XDP_DROP);
            }
            if service::ipv6_service_rule_violation(start, end, &event) {
                return Ok(xdp_action::XDP_DROP);
            }
            // if defence::is_attack_ipv6(&event) {
            //     return Ok(xdp_action::XDP_DROP);
            // }
            monitor::ipv6_update_stats(&event);
        }
        _ => Err(())?,
    }
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
