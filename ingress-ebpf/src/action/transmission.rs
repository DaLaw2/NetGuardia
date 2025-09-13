use aya_ebpf::{macros::map, maps::RingBuf};
use common::define::other::STANDARD_MTU;
use common::define::setting::MAX_BUFFERED_PACKETS;
use common::model::event::Event;
use common::model::packet::Packet;

#[map]
static PACKET_RING: RingBuf = RingBuf::with_byte_size((MAX_BUFFERED_PACKETS * STANDARD_MTU) as u32, 0);

pub fn transmission(start: usize, end: usize, event: *mut Event) -> Result<(), ()> {
    if start + STANDARD_MTU > end {
        return Err(());
    }
    if let Some(mut entry) = PACKET_RING.reserve::<Packet>(0) {
        unsafe {
            let packet_ptr = entry.as_mut_ptr();
            core::ptr::copy_nonoverlapping(
                event as *const u8,
                &mut (*packet_ptr).event as *mut Event as *mut u8,
                size_of::<Event>(),
            );
            core::ptr::copy_nonoverlapping(start as *const u8, (*packet_ptr).raw_data.as_mut_ptr(), STANDARD_MTU);
        }
        entry.submit(0);
        Ok(())
    } else {
        Err(())
    }
}
