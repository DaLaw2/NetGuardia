#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{Array, XskMap};
use aya_ebpf::programs::XdpContext;
#[allow(unused_imports)]
use aya_log_ebpf::info;
use common::ebpf::parsing;
use common::ebpf::symmetric_hash::symmetric_queue_id;
use common::model::parsed_packet::ParsedPacket;

#[map]
static NUM_QUEUES: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EGRESS_XSKS_MAP: XskMap = XskMap::pinned(64, 0);

#[xdp]
pub fn net_guardia(ctx: XdpContext) -> u32 {
    let queue_id = unsafe {
        compute_symmetric_queue_id(&ctx).unwrap_or((*ctx.ctx).rx_queue_index)
    };
    match EGRESS_XSKS_MAP.redirect(queue_id, 0) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
unsafe fn compute_symmetric_queue_id(ctx: &XdpContext) -> Option<u32> {
    unsafe {
        let mut pkt = core::mem::zeroed::<ParsedPacket>();
        parsing::parse_packet(ctx.data(), ctx.data_end(), &mut pkt).ok()?;
        let num_q = *NUM_QUEUES.get(0)?;
        symmetric_queue_id(&pkt, num_q)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
