use crate::{
    define::other::STANDARD_MTU,
    model::event::Event,
};

#[repr(C, align(8))]
pub struct Packet {
    pub event: Event,
    pub raw_data: [u8; STANDARD_MTU],
}

impl Packet {
    pub fn new(event: Event, raw_data: [u8; STANDARD_MTU]) -> Self {
        Self { event, raw_data }
    }
}
