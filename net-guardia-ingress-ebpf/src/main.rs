#![no_std]
#![no_main]
mod action;

use crate::action::{access_control, service, statistics, transmission};
use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{PerCpuArray, ProgramArray},
    programs::XdpContext,
};
use aya_log_ebpf::error;
use net_guardia_common::ebpf::parsing;
use net_guardia_common::model::event::Event;

#[map]
static PROGRAM_ARRAY: ProgramArray = ProgramArray::with_max_entries(8, 0);
#[map]
static PARSED_PACKET: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);

#[xdp]
pub fn net_guardia(ctx: XdpContext) -> u32 {
    unsafe {
        packet_intake(ctx).unwrap_or(xdp_action::XDP_PASS)
    }
}

unsafe fn packet_intake(ctx: XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let ptr = PARSED_PACKET.get_ptr_mut(0).ok_or(())?;
    parsing::parse_packet(start, end, ptr)?;
    transmission::transmission(start, end, ptr)?;
    if unsafe { PROGRAM_ARRAY.tail_call(&ctx, 0).is_err() } {
        error!(&ctx, "Tail call failed");
    }
    Ok(xdp_action::XDP_PASS)
}

#[xdp]
pub fn access_control(ctx: XdpContext) -> u32 {
    unsafe {
        try_access_control(ctx).unwrap_or(xdp_action::XDP_PASS)
    }
}

unsafe fn try_access_control(ctx: XdpContext) -> Result<u32, ()> {
    unsafe {
        let ptr = PARSED_PACKET.get_ptr(0).ok_or(())?;
        let parsed_packet = &*ptr;
        match parsed_packet {
            Event::IPv4(event) => {
                if access_control::ipv4_is_whitelisted(event) {
                    return Ok(xdp_action::XDP_PASS);
                }
                if access_control::ipv4_is_blacklisted(event) {
                    return Ok(xdp_action::XDP_DROP);
                }
            }
            Event::IPv6(event) => {
                if access_control::ipv6_is_whitelisted(event) {
                    return Ok(xdp_action::XDP_PASS);
                }
                if access_control::ipv6_is_blacklisted(event) {
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        }
        if PROGRAM_ARRAY.tail_call(&ctx, 1).is_err() {
            error!(&ctx, "Tail call failed");
        }
        Err(())
    }
}

#[xdp]
pub fn service(ctx: XdpContext) -> u32 {
    unsafe {
        try_service(ctx).unwrap_or(xdp_action::XDP_PASS)
    }
}

unsafe fn try_service(ctx: XdpContext) -> Result<u32, ()> {
    unsafe {
        let start = ctx.data();
        let end = ctx.data_end();
        let ptr = PARSED_PACKET.get_ptr(0).ok_or(())?;
        let parsed_packet = &*ptr;
        match parsed_packet {
            Event::IPv4(event) => {
                if service::ipv4_service_rule_violation(start, end, event) {
                    return Ok(xdp_action::XDP_DROP);
                }
            }
            Event::IPv6(event) => {
                if service::ipv6_service_rule_violation(start, end, event) {
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        }
        if PROGRAM_ARRAY.tail_call(&ctx, 2).is_err() {
            error!(&ctx, "Tail call failed");
        }
        Err(())
    }
}

#[xdp]
pub fn statistics(ctx: XdpContext) -> u32 {
    unsafe {
        try_statistics(ctx).unwrap_or(xdp_action::XDP_PASS)
    }
}

unsafe fn try_statistics(_: XdpContext) -> Result<u32, ()> {
    unsafe {
        let ptr = PARSED_PACKET.get_ptr(0).ok_or(())?;
        let parsed_packet = &*ptr;
        match parsed_packet {
            Event::IPv4(event) => {
                statistics::ipv4_update_stats(&event);
            }
            Event::IPv6(event) => {
                statistics::ipv6_update_stats(&event);
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
