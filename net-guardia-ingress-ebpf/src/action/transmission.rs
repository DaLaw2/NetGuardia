use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;
use net_guardia_common::define::other::STANDARD_MTU;
use net_guardia_common::define::setting::MAX_BUFFERED_PACKETS;
use net_guardia_common::model::event::Event;
use net_guardia_common::model::packet::Packet;

#[map]
static PACKET_RING: RingBuf = RingBuf::with_byte_size((MAX_BUFFERED_PACKETS * STANDARD_MTU) as u32, 0);

pub fn transmission(start: usize, end: usize, event: Event) -> Result<(), ()> {
    if end - start != STANDARD_MTU {
        return Err(());
    }
    if let Some(mut entry) = PACKET_RING.reserve::<Packet>(0) {
        unsafe {
            let packet_ptr = entry.as_mut_ptr();
            core::ptr::write(&mut (*packet_ptr).event, event);
            core::ptr::copy_nonoverlapping(start as *const u8, (*packet_ptr).raw_data.as_mut_ptr(), STANDARD_MTU);
        }
        entry.submit(0);
        Ok(())
    } else {
        Err(())
    }
}
