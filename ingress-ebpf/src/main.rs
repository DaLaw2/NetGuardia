#![no_std]
#![no_main]
mod action;

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{PerCpuArray, ProgramArray, RingBuf};
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::error;
use common::define::other::STANDARD_MTU;
use common::define::setting::MAX_BUFFERED_PACKETS;
use common::ebpf::parsing;
use common::model::event::Event;
use common::model::packet::Packet;

use crate::action::{access_control, service, statistics};

#[map]
static PROGRAM_ARRAY: ProgramArray = ProgramArray::with_max_entries(8, 0);
#[map]
static PARSED_PACKET: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);
#[map]
static PACKET_RING: RingBuf = RingBuf::with_byte_size((MAX_BUFFERED_PACKETS * STANDARD_MTU) as u32, 0);

#[xdp]
pub fn net_guardia(ctx: XdpContext) -> u32 {
    unsafe { packet_intake(ctx).unwrap_or(xdp_action::XDP_PASS) }
}

unsafe fn packet_intake(ctx: XdpContext) -> Result<u32, ()> {
    unsafe {
        let start = ctx.data();
        let end = ctx.data_end();
        let ptr = PARSED_PACKET.get_ptr_mut(0).ok_or(())?;
        parsing::parse_packet(start, end, ptr)?;
        let copy_size = (end - start).min(STANDARD_MTU);
        if copy_size == 0 {
            error!(&ctx, "Packet size is 0");
        }
        if let Some(mut entry) = PACKET_RING.reserve::<Packet>(0) {
            let ring_ptr = entry.as_mut_ptr();
            core::ptr::copy_nonoverlapping(
                ptr as *const u8,
                &mut (*ring_ptr).event as *mut Event as *mut u8,
                size_of::<Event>(),
            );
            core::ptr::copy_nonoverlapping(start as *const u8, (*ring_ptr).raw_data.as_mut_ptr(), copy_size);
            entry.submit(0);
        } else {
            error!(&ctx, "Ring buffer");
            Err(())?
        }
        let _ = PROGRAM_ARRAY.tail_call(&ctx, 0);
        Err(())
    }
}

#[xdp]
pub fn access_control(ctx: XdpContext) -> u32 {
    unsafe { try_access_control(ctx).unwrap_or(xdp_action::XDP_PASS) }
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
        let _ = PROGRAM_ARRAY.tail_call(&ctx, 1);
        Err(())
    }
}

#[xdp]
pub fn service(ctx: XdpContext) -> u32 {
    unsafe { try_service(ctx).unwrap_or(xdp_action::XDP_PASS) }
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
        let _ = PROGRAM_ARRAY.tail_call(&ctx, 2);
        Err(())
    }
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
