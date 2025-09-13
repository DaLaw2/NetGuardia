#![no_std]
#![no_main]
mod action;

use action::statistics;
use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{PerCpuArray, ProgramArray};
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::error;
use common::{ebpf::parsing, model::event::Event};
use network_types::eth::EtherType;

#[map]
static PROGRAM_ARRAY: ProgramArray = ProgramArray::with_max_entries(8, 0);
#[map]
static PARSED_PACKET: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);

#[xdp]
pub fn net_guardia(ctx: XdpContext) -> u32 {
    unsafe { packet_intake(ctx).unwrap_or(xdp_action::XDP_PASS) }
}

unsafe fn packet_intake(ctx: XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let ptr = PARSED_PACKET.get_ptr_mut(0).ok_or(())?;
    parsing::parse_packet(start, end, ptr)?;
    if unsafe { PROGRAM_ARRAY.tail_call(&ctx, 0).is_err() } {
        error!(&ctx, "Tail call failed");
    }
    Ok(xdp_action::XDP_PASS)
}

#[xdp]
pub fn statistics(ctx: XdpContext) -> u32 {
    unsafe { try_statistics(ctx).unwrap_or(xdp_action::XDP_PASS) }
}

unsafe fn try_statistics(_: XdpContext) -> Result<u32, ()> {
    unsafe {
        let ptr = PARSED_PACKET.get_ptr(0).ok_or(())?;
        let parsed_packet = &*ptr;
        match parsed_packet {
            Event::IPv4(event) => {
                statistics::ipv4_update_stats(event);
            }
            Event::IPv6(event) => {
                statistics::ipv6_update_stats(event);
            }
        }
        Ok(xdp_action::XDP_PASS)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
