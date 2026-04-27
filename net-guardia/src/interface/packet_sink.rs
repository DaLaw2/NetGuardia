use std::sync::Arc;

use crate::domain::data_plane::user_packet::UserPacket;

pub trait PacketSink: Send + Sync {
    fn process_packet(&self, packet: UserPacket, is_ingress: bool);
}

pub trait PacketSinkFactory: Send + Sync {
    fn sink_for_queue(&self, queue_id: u32) -> Option<Arc<dyn PacketSink>>;
}
