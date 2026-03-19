#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::XskMap;
use aya_ebpf::programs::XdpContext;
#[allow(unused_imports)]
use aya_log_ebpf::info;

#[map]
static EGRESS_XSKS_MAP: XskMap = XskMap::pinned(64, 0);

#[xdp]
pub fn net_guardia(ctx: XdpContext) -> u32 {
    let queue_id = unsafe { (*ctx.ctx).rx_queue_index };
    match EGRESS_XSKS_MAP.redirect(queue_id, 0) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
