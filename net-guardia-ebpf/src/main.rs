#![no_std]
#![no_main]

mod action;
mod utils;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use network_types::eth::EtherType;
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
    // let ether_type = match parsing::parse_ether_type(&ctx) {
    //     Ok(ether_type) => ether_type,
    //     Err(_) => return Ok(xdp_action::XDP_PASS)
    // };
    //
    // match ether_type {
    //     EtherType::Ipv4 => {
    //
    //     }
    //     EtherType::Ipv6 => {
    //
    //     }
    //     _ => {}
    // }

    let event = match parsing::parse_packet(&ctx) {
        Ok(event) => event,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };

    if filter::should_block(&event) {
        return Ok(xdp_action::XDP_DROP);
    }

    if let Some(forward_rule) = forward::get_forward_rule(event.get_source()) {
        // let _ = misc::modify_packet_destination(&ctx, forward_rule[0], forward_rule[1] as u16);
    }

    monitor::update_stats(&event);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
