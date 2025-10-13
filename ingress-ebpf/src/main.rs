#![no_std]
#![no_main]
mod action;

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{PerCpuArray, ProgramArray, XskMap};
use aya_ebpf::programs::XdpContext;
#[allow(unused_imports)]
use aya_log_ebpf::info;
use common::define::program_array::ingress::*;
use common::ebpf::parsing;
use common::model::event::Event;

use crate::action::{access_control, service, statistics};

#[map]
static PROGRAM_ARRAY: ProgramArray = ProgramArray::with_max_entries(8, 0);
#[map]
static PARSED_PACKET: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);
#[map]
static XSKS_MAP: XskMap = XskMap::with_max_entries(64, 0);

#[xdp]
pub fn net_guardia(ctx: XdpContext) -> u32 {
    unsafe {
        let _ = packet_intake(&ctx);
        let _ = PROGRAM_ARRAY.tail_call(&ctx, TRANSMISSION);
        xdp_action::XDP_PASS
    }
}

#[inline(always)]
unsafe fn packet_intake(ctx: &XdpContext) -> Result<u32, ()> {
    unsafe {
        let start = ctx.data();
        let end = ctx.data_end();
        let ptr = PARSED_PACKET.get_ptr_mut(0).ok_or(())?;
        parsing::parse_packet(start, end, ptr)?;
        let _ = PROGRAM_ARRAY.tail_call(ctx, ACCESS_CONTROL);
        Err(())
    }
}

#[xdp]
pub fn access_control(ctx: XdpContext) -> u32 {
    unsafe {
        match try_access_control(&ctx) {
            Ok(action) => action,
            Err(_) => {
                let _ = PROGRAM_ARRAY.tail_call(&ctx, TRANSMISSION);
                xdp_action::XDP_PASS
            }
        }
    }
}

#[inline(always)]
unsafe fn try_access_control(ctx: &XdpContext) -> Result<u32, ()> {
    unsafe {
        let ptr = PARSED_PACKET.get_ptr(0).ok_or(())?;
        let parsed_packet = &*ptr;
        match parsed_packet {
            Event::IPv4(event) => {
                if access_control::ipv4_is_whitelisted(event) {
                    let _ = PROGRAM_ARRAY.tail_call(ctx, STATISTICS);
                    return Err(());
                }
                if access_control::ipv4_is_blacklisted(event) {
                    return Ok(xdp_action::XDP_DROP);
                }
            }
            Event::IPv6(event) => {
                if access_control::ipv6_is_whitelisted(event) {
                    let _ = PROGRAM_ARRAY.tail_call(ctx, STATISTICS);
                    return Err(());
                }
                if access_control::ipv6_is_blacklisted(event) {
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        }
        let _ = PROGRAM_ARRAY.tail_call(ctx, SERVICE);
        Err(())
    }
}

#[xdp]
pub fn service(ctx: XdpContext) -> u32 {
    unsafe {
        match try_service(&ctx) {
            Ok(action) => action,
            Err(_) => {
                let _ = PROGRAM_ARRAY.tail_call(&ctx, TRANSMISSION);
                xdp_action::XDP_PASS
            }
        }
    }
}

#[inline(always)]
unsafe fn try_service(ctx: &XdpContext) -> Result<u32, ()> {
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
        let _ = PROGRAM_ARRAY.tail_call(ctx, STATISTICS);
        Err(())
    }
}

#[xdp]
pub fn statistics(ctx: XdpContext) -> u32 {
    unsafe {
        let _ = try_statistics(&ctx);
        xdp_action::XDP_PASS
    }
}

#[inline(always)]
unsafe fn try_statistics(ctx: &XdpContext) -> Result<u32, ()> {
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
        let _ = PROGRAM_ARRAY.tail_call(ctx, TRANSMISSION);
        Err(())
    }
}

#[xdp]
pub fn transmission(ctx: XdpContext) -> u32 {
    let queue_id = unsafe { (*ctx.ctx).rx_queue_index };
    match XSKS_MAP.redirect(queue_id, 0) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
