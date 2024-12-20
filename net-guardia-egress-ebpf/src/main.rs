#![no_std]
#![no_main]
mod action;
mod utils;

use action::statistics;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{PerCpuArray, ProgramArray};
use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::error;
use net_guardia_common::model::event::Event;
use network_types::eth::EtherType;
use utils::parsing;

#[map]
static PROGRAM_ARRAY: ProgramArray = ProgramArray::with_max_entries(8, 0);
#[map]
static PARSED_PACKET: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);

#[xdp]
pub fn net_guardia(ctx: XdpContext) -> u32 {
    match unsafe { parsing(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

unsafe fn parsing(ctx: XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let event = parsing::parse_packet(start, end)?;
    let ptr = PARSED_PACKET.get_ptr_mut(0).ok_or(())?;
    let parsed_packet = ptr.as_mut().ok_or(())?;
    *parsed_packet = event;
    if PROGRAM_ARRAY.tail_call(&ctx, 0).is_err() {
        error!(&ctx, "Tail call failed");
    }
    Err(())
}

#[xdp]
pub fn statistics(ctx: XdpContext) -> u32 {
    match unsafe { try_statistics(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

unsafe fn try_statistics(_: XdpContext) -> Result<u32, ()> {
    let ptr = PARSED_PACKET.get_ptr(0).ok_or(())?;
    let parsed_packet = ptr.read();
    match parsed_packet.eth_type {
        EtherType::Ipv4 => {
            let event = parsed_packet.into_ipv4_event();
            statistics::ipv4_update_stats(&event);
        }
        EtherType::Ipv6 => {
            let event = parsed_packet.into_ipv6_event();
            statistics::ipv6_update_stats(&event);
        }
        _ => Err(())?,
    }
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
