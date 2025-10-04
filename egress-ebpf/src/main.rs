#![no_std]
#![no_main]
mod action;

use action::statistics;
use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{PerCpuArray, ProgramArray};
use aya_ebpf::programs::XdpContext;
#[allow(unused_imports)]
use aya_log_ebpf::info;
use common::define::program_array::egress::*;
use common::{ebpf::parsing, model::event::Event};

#[map]
static PROGRAM_ARRAY: ProgramArray = ProgramArray::with_max_entries(8, 0);
#[map]
static PARSED_PACKET: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);

#[xdp]
pub fn net_guardia(ctx: XdpContext) -> u32 {
    unsafe {
        let _ = packet_intake(ctx);
        xdp_action::XDP_PASS
    }
}

unsafe fn packet_intake(ctx: XdpContext) -> Result<u32, ()> {
    unsafe {
        let start = ctx.data();
        let end = ctx.data_end();
        let ptr = PARSED_PACKET.get_ptr_mut(0).ok_or(())?;
        parsing::parse_packet(start, end, ptr)?;
        let _ = PROGRAM_ARRAY.tail_call(&ctx, STATISTICS);
        Err(())
    }
}

#[xdp]
pub fn statistics(ctx: XdpContext) -> u32 {
    unsafe {
        let _ = try_statistics(ctx);
        xdp_action::XDP_PASS
    }
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
