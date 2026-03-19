#![no_std]
#![no_main]
mod action;

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{Array, PerCpuArray, ProgramArray, XskMap};
use aya_ebpf::programs::XdpContext;
#[allow(unused_imports)]
use aya_log_ebpf::info;
use common::ebpf::parsing;
use common::define::pipeline::*;
use common::model::parsed_packet::ParsedPacket;

use crate::action::{access_control, rate_limit, protocol_filter};

#[map]
static PROGRAM_ARRAY: ProgramArray = ProgramArray::with_max_entries(MAX_STAGES, 0);
#[map]
static NEXT_STAGE: Array<u32> = Array::with_max_entries(MAX_STAGES, 0);
#[map]
static PARSED_PACKET: PerCpuArray<ParsedPacket> = PerCpuArray::with_max_entries(1, 0);
#[map]
static INGRESS_XSKS_MAP: XskMap = XskMap::pinned(64, 0);

#[inline(always)]
unsafe fn chain_next(ctx: &XdpContext, current_id: u32) {
    unsafe {
        if let Some(&next_slot) = NEXT_STAGE.get(current_id) {
            if next_slot != STAGE_NONE {
                let _ = PROGRAM_ARRAY.tail_call(ctx, next_slot);
            }
        }
        let _ = PROGRAM_ARRAY.tail_call(ctx, STAGE_TRANSMISSION);
    }
}

#[xdp]
pub fn net_guardia(ctx: XdpContext) -> u32 {
    unsafe {
        packet_intake(&ctx);
        let _ = PROGRAM_ARRAY.tail_call(&ctx, STAGE_TRANSMISSION);
        xdp_action::XDP_PASS
    }
}

#[inline(always)]
unsafe fn packet_intake(ctx: &XdpContext) {
    let Some(ptr) = PARSED_PACKET.get_ptr_mut(0) else { return };
    if parsing::parse_packet(ctx.data(), ctx.data_end(), ptr).is_ok() {
        chain_next(ctx, STAGE_ENTRY);
    }
}

#[xdp]
pub fn access_control(ctx: XdpContext) -> u32 {
    unsafe {
        match try_access_control(&ctx) {
            Ok(action) => action,
            Err(_) => {
                chain_next(&ctx, STAGE_ACCESS_CONTROL);
                xdp_action::XDP_PASS
            }
        }
    }
}

#[inline(always)]
unsafe fn try_access_control(ctx: &XdpContext) -> Result<u32, ()> {
    unsafe {
        let ptr = PARSED_PACKET.get_ptr(0).ok_or(())?;
        let pkt = &*ptr;
        match pkt.ip_version {
            4 => {
                if access_control::ipv4_is_whitelisted(pkt) {
                    let _ = PROGRAM_ARRAY.tail_call(ctx, STAGE_TRANSMISSION);
                    return Err(());
                }
                if access_control::ipv4_is_blacklisted(pkt) {
                    return Ok(xdp_action::XDP_DROP);
                }
            }
            6 => {
                if access_control::ipv6_is_whitelisted(pkt) {
                    let _ = PROGRAM_ARRAY.tail_call(ctx, STAGE_TRANSMISSION);
                    return Err(());
                }
                if access_control::ipv6_is_blacklisted(pkt) {
                    return Ok(xdp_action::XDP_DROP);
                }
            }
            _ => {}
        }
        chain_next(ctx, STAGE_ACCESS_CONTROL);
        Err(())
    }
}

#[xdp]
pub fn rate_limit(ctx: XdpContext) -> u32 {
    unsafe {
        match try_rate_limit(&ctx) {
            Ok(action) => action,
            Err(_) => {
                chain_next(&ctx, STAGE_RATE_LIMIT);
                xdp_action::XDP_PASS
            }
        }
    }
}

#[inline(always)]
unsafe fn try_rate_limit(ctx: &XdpContext) -> Result<u32, ()> {
    unsafe {
        let ptr = PARSED_PACKET.get_ptr(0).ok_or(())?;
        let pkt = &*ptr;
        if rate_limit::should_drop(pkt) {
            return Ok(xdp_action::XDP_DROP);
        }
        chain_next(ctx, STAGE_RATE_LIMIT);
        Err(())
    }
}

#[xdp]
pub fn protocol_filter(ctx: XdpContext) -> u32 {
    unsafe {
        match try_service(&ctx) {
            Ok(action) => action,
            Err(_) => {
                chain_next(&ctx, STAGE_SERVICE);
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
        let pkt = &*ptr;
        match pkt.ip_version {
            4 => {
                if protocol_filter::ipv4_service_rule_violation(start, end, pkt) {
                    return Ok(xdp_action::XDP_DROP);
                }
            }
            6 => {
                if protocol_filter::ipv6_service_rule_violation(start, end, pkt) {
                    return Ok(xdp_action::XDP_DROP);
                }
            }
            _ => {}
        }
        chain_next(ctx, STAGE_SERVICE);
        Err(())
    }
}

#[xdp]
pub fn transmission(ctx: XdpContext) -> u32 {
    let queue_id = unsafe { (*ctx.ctx).rx_queue_index };
    match INGRESS_XSKS_MAP.redirect(queue_id, 0) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
