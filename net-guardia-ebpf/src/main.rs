#![no_std]
#![no_main]

mod action;
mod utils;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use action::{filter, forward, monitor};
use crate::utils::{parsing, misc};

#[xdp]
pub fn net_guardia(ctx: XdpContext) -> u32 {
    match try_net_guardia(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_net_guardia(ctx: XdpContext) -> Result<u32, ()> {
    let event = match parsing::parse_packet(&ctx) {
        Ok(event) => event,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };

    if filter::should_block(&event) {
        return Ok(xdp_action::XDP_DROP);
    }

    // if let Some(forward_rule) = forward::get_forward_rule_ipv4(packet.source_ip, packet.source_port) {
    //     let _ = misc::modify_packet_destination(&ctx, forward_rule[0], forward_rule[1] as u16);
    // }

    monitor::update_stats(&event);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
