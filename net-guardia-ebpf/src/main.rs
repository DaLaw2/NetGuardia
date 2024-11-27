#![no_std]
#![no_main]

mod action;
mod utils;

use crate::utils::{change_destination, parsing};
use action::{filter, forward, monitor};
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use network_types::eth::EtherType;

#[xdp]
pub fn net_guardia(ctx: XdpContext) -> u32 {
    match try_net_guardia(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_net_guardia(ctx: XdpContext) -> Result<u32, ()> {
    match parsing::parse_ether_type(&ctx)? {
        EtherType::Ipv4 => {
            let event = parsing::parse_ipv4_packet(&ctx)?;
            if filter::should_block_ipv4(&event) {
                return Ok(xdp_action::XDP_DROP);
            }
            if let Some(forward_rule) = forward::get_forward_rule_ipv4(&event.get_source()) {
                change_destination::modify_ipv4_packet_destination(&ctx, forward_rule)?;
            }
            monitor::update_stats_ipv4(&event);
        }
        EtherType::Ipv6 => {
            let event = parsing::parse_ipv6_packet(&ctx)?;
            if filter::should_block_ipv6(&event) {
                return Ok(xdp_action::XDP_DROP);
            }
            if let Some(forward_rule) = forward::get_forward_rule_ipv6(&event.get_source()) {
                change_destination::modify_ipv6_packet_destination(&ctx, forward_rule)?;
            }
            monitor::update_stats_ipv6(&event);
        }
        _ => Err(())?,
    }
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
