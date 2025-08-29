use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;

#[map]
static PACKET_RING: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

pub fn transmission() {
    
}
