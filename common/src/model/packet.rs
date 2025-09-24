use crate::define::other::STANDARD_MTU;
use crate::model::event::Event;

#[repr(transparent)]
pub struct Packet(pub [u8; size_of::<Event>() + STANDARD_MTU]);
