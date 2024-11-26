#![no_std]
#![no_main]

mod filter;
mod forward;
mod monitor;
mod parsing;
mod utils;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

#[xdp]
pub fn net_guardia(ctx: XdpContext) -> u32 {
    match try_net_guardia(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_DROP,
    }
}

fn try_net_guardia(ctx: XdpContext) -> Result<u32, ()> {
    let packet = match parsing::parse_packet(&ctx) {
        Ok(packet) => packet,
        Err(_) => return Ok(xdp_action::XDP_DROP),
    };

    if filter::should_block(&packet) {
        return Ok(xdp_action::XDP_DROP);
    }

    if let Some(forward_rule) = forward::get_forward_rule(packet.source_ip, packet.source_port) {
        let _ = parsing::modify_packet_destination(&ctx, forward_rule[0], forward_rule[1] as u16);
    }

    monitor::update_stats(&packet);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
