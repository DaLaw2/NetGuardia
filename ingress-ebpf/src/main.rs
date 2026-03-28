#![no_std]
#![no_main]
mod action;

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{Array, PerCpuArray, ProgramArray, RingBuf, XskMap};
use common::ebpf::symmetric_hash::symmetric_queue_id;
use aya_ebpf::programs::XdpContext;
#[allow(unused_imports)]
use aya_log_ebpf::info;
use common::ebpf::parsing;
use common::define::pipeline::*;
use common::define::drop_reason::*;
use common::model::drop_event::DropEvent;
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
#[map]
static NUM_QUEUES: Array<u32> = Array::with_max_entries(1, 0);
#[map]
static DROP_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[xdp]
pub fn net_guardia(ctx: XdpContext) -> u32 {
    unsafe {
        packet_intake(&ctx);
        let _ = PROGRAM_ARRAY.tail_call(&ctx, STAGE_TRANSMISSION);
        xdp_action::XDP_PASS
    }
}

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

#[inline(always)]
unsafe fn emit_drop_event(pkt: &ParsedPacket, reason: u8) {
    if let Some(mut entry) = DROP_EVENTS.reserve::<DropEvent>(0) {
        let event = entry.as_mut_ptr();
        (*event).timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        (*event).src_ip = pkt.src_ip;
        (*event).dst_ip = pkt.dst_ip;
        (*event).src_port = pkt.src_port;
        (*event).dst_port = pkt.dst_port;
        (*event).protocol = pkt.protocol as u8;
        (*event).reason = reason;
        (*event).ip_version = pkt.ip_version;
        (*event)._pad = 0;
        entry.submit(0);
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
                if access_control::ipv4_is_geo_blocked(pkt) {
                    emit_drop_event(pkt, DROP_REASON_GEO_BLOCK);
                    return Ok(xdp_action::XDP_DROP);
                }
                if access_control::ipv4_is_blacklisted(pkt) {
                    emit_drop_event(pkt, DROP_REASON_ACL_BLACKLIST);
                    return Ok(xdp_action::XDP_DROP);
                }
            }
            6 => {
                if access_control::ipv6_is_whitelisted(pkt) {
                    let _ = PROGRAM_ARRAY.tail_call(ctx, STAGE_TRANSMISSION);
                    return Err(());
                }
                if access_control::ipv6_is_geo_blocked(pkt) {
                    emit_drop_event(pkt, DROP_REASON_GEO_BLOCK);
                    return Ok(xdp_action::XDP_DROP);
                }
                if access_control::ipv6_is_blacklisted(pkt) {
                    emit_drop_event(pkt, DROP_REASON_ACL_BLACKLIST);
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
        if let Some(reason) = rate_limit::should_drop(pkt) {
            emit_drop_event(pkt, reason);
            return Ok(xdp_action::XDP_DROP);
        }
        chain_next(ctx, STAGE_RATE_LIMIT);
        Err(())
    }
}

#[xdp]
pub fn protocol_filter(ctx: XdpContext) -> u32 {
    unsafe {
        match try_protocol_filter(&ctx) {
            Ok(action) => action,
            Err(_) => {
                chain_next(&ctx, STAGE_SERVICE);
                xdp_action::XDP_PASS
            }
        }
    }
}

#[inline(always)]
unsafe fn try_protocol_filter(ctx: &XdpContext) -> Result<u32, ()> {
    unsafe {
        let start = ctx.data();
        let end = ctx.data_end();
        let ptr = PARSED_PACKET.get_ptr(0).ok_or(())?;
        let pkt = &*ptr;

        match pkt.ip_version {
            4 => {
                if protocol_filter::ipv4_service_rule_violation(start, end, pkt) {
                    emit_drop_event(pkt, DROP_REASON_PROTOCOL_FILTER);
                    return Ok(xdp_action::XDP_DROP);
                }
            }
            6 => {
                if protocol_filter::ipv6_service_rule_violation(start, end, pkt) {
                    emit_drop_event(pkt, DROP_REASON_PROTOCOL_FILTER);
                    return Ok(xdp_action::XDP_DROP);
                }
            }
            _ => {}
        }
        chain_next(ctx, STAGE_SERVICE);
        Err(())
    }
}

#[inline(always)]
unsafe fn compute_symmetric_queue_id() -> Option<u32> {
    unsafe {
        let pkt = &*PARSED_PACKET.get_ptr(0)?;
        let num_q = *NUM_QUEUES.get(0)?;
        symmetric_queue_id(pkt, num_q)
    }
}

#[xdp]
pub fn transmission(ctx: XdpContext) -> u32 {
    let queue_id = unsafe {
        compute_symmetric_queue_id().unwrap_or((*ctx.ctx).rx_queue_index)
    };
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
