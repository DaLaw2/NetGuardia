#![no_std]
#![no_main]
mod action;
mod utils;

use crate::action::{defence, service};
use crate::utils::parsing;
use action::{access_control, monitor};
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{PerCpuArray, ProgramArray};
use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::error;
use net_guardia_common::model::event::Event;
use network_types::eth::EtherType;

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
pub fn access_control(ctx: XdpContext) -> u32 {
    match unsafe { try_access_control(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

unsafe fn try_access_control(ctx: XdpContext) -> Result<u32, ()> {
    let ptr = PARSED_PACKET.get_ptr(0).ok_or(())?;
    let parsed_packet = ptr.read();
    match parsed_packet.eth_type {
        EtherType::Ipv4 => {
            let event = parsed_packet.into_ipv4_event();
            if access_control::ipv4_is_whitelisted(&event) {
                return Ok(xdp_action::XDP_PASS);
            }
            if access_control::ipv4_is_blacklisted(&event) {
                return Ok(xdp_action::XDP_DROP);
            }
        }
        EtherType::Ipv6 => {
            let event = parsed_packet.into_ipv6_event();
            if access_control::ipv6_is_whitelisted(&event) {
                return Ok(xdp_action::XDP_PASS);
            }
            if access_control::ipv6_is_blacklisted(&event) {
                return Ok(xdp_action::XDP_DROP);
            }
        }
        _ => Err(())?,
    }
    if PROGRAM_ARRAY.tail_call(&ctx, 1).is_err() {
        error!(&ctx, "Tail call failed");
    }
    Err(())
}

#[xdp]
pub fn service(ctx: XdpContext) -> u32 {
    match unsafe { try_service(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

unsafe fn try_service(ctx: XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let ptr = PARSED_PACKET.get_ptr(0).ok_or(())?;
    let parsed_packet = ptr.read();
    match parsed_packet.eth_type {
        EtherType::Ipv4 => {
            let event = parsed_packet.into_ipv4_event();
            if service::ipv4_service_rule_violation(start, end, &event) {
                return Ok(xdp_action::XDP_DROP);
            }
        }
        EtherType::Ipv6 => {
            let event = parsed_packet.into_ipv6_event();
            if service::ipv6_service_rule_violation(start, end, &event) {
                return Ok(xdp_action::XDP_DROP);
            }
        }
        _ => Err(())?,
    }
    if PROGRAM_ARRAY.tail_call(&ctx, 3).is_err() {
        error!(&ctx, "Tail call failed");
    }
    Err(())
}

// #[xdp]
// pub fn defence(ctx: XdpContext) -> u32 {
//     match unsafe { try_defence(ctx) } {
//         Ok(ret) => ret,
//         Err(_) => xdp_action::XDP_PASS,
//     }
// }
//
// unsafe fn try_defence(ctx: XdpContext) -> Result<u32, ()> {
//     let ptr = PARSED_PACKET.get_ptr(0).ok_or(())?;
//     let parsed_packet = ptr.read();
//     match parsed_packet.eth_type {
//         EtherType::Ipv4 => {
//             let event = parsed_packet.into_ipv4_event();
//             if defence::ipv4_is_attack(&event) {
//                 return Ok(xdp_action::XDP_DROP);
//             }
//         }
//         EtherType::Ipv6 => {
//             let event = parsed_packet.into_ipv6_event();
//             if defence::ipv6_is_attack(&event) {
//                 return Ok(xdp_action::XDP_DROP);
//             }
//         }
//         _ => Err(())?
//     }
//     if PROGRAM_ARRAY.tail_call(&ctx, 3).is_err() {
//         error!(&ctx, "Tail call failed");
//     }
//     Err(())
// }

#[xdp]
pub fn sampling(ctx: XdpContext) -> u32 {
    match unsafe { try_sampling(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

unsafe fn try_sampling(ctx: XdpContext) -> Result<u32, ()> {
    if PROGRAM_ARRAY.tail_call(&ctx, 4).is_err() {
        error!(&ctx, "Tail call failed");
    }
    Err(())
}

#[xdp]
pub fn monitor(ctx: XdpContext) -> u32 {
    match unsafe { try_monitor(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

unsafe fn try_monitor(_: XdpContext) -> Result<u32, ()> {
    let ptr = PARSED_PACKET.get_ptr(0).ok_or(())?;
    let parsed_packet = ptr.read();
    match parsed_packet.eth_type {
        EtherType::Ipv4 => {
            let event = parsed_packet.into_ipv4_event();
            monitor::ipv4_update_stats(&event);
        }
        EtherType::Ipv6 => {
            let event = parsed_packet.into_ipv6_event();
            monitor::ipv6_update_stats(&event);
        }
        _ => Err(())?,
    }
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
