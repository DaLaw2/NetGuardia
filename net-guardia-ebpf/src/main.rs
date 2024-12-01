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
    let mut offset = 0_usize;
    match parsing::parse_ether_type(start, end, &mut offset)? {
        EtherType::Ipv4 => {
            let event = parsing::parse_ipv4_packet(start, end, &mut offset)?;
            if blocking::should_block_ipv4(&event) {
                return Ok(xdp_action::XDP_DROP);
            }

            monitor::update_stats_ipv4(&event);
        }
        EtherType::Ipv6 => {
            let event = parsing::parse_ipv6_packet(start, end, &mut offset)?;
            if blocking::should_block_ipv6(&event) {
                return Ok(xdp_action::XDP_DROP);
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
