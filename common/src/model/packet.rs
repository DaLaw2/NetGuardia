use core::cmp;

use crate::define::other::STANDARD_MTU;
use crate::model::event::Event;

#[repr(C, align(8))]
pub struct Packet {
    pub event: Event,
    pub packet_len: u32,
    pub raw_data: [u8; STANDARD_MTU],
}

impl Packet {
    pub fn new(event: Event, packet_len: u32, raw_data: [u8; STANDARD_MTU]) -> Self {
        Self {
            event,
            packet_len,
            raw_data,
        }
    }

    pub fn actual_packet_size(&self) -> usize {
        cmp::min(self.packet_len as usize, STANDARD_MTU)
    }
}
