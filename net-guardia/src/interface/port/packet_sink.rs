use std::sync::Arc;

use crate::model::monitoring::user_packet::UserPacket;

/// Data-plane packet sink — receives parsed packets from the AF_XDP RX path.
///
/// Implementations wrap a `FlowTracker` (or other per-queue state) and forward
/// each packet into the ML inference pipeline. `XskManager` sees only this
/// trait, never `core::ml`, so the dependency direction stays
/// `adapter/ebpf → interface/port`.
pub trait PacketSink: Send + Sync {
    /// Process one parsed packet. The boolean says whether the packet arrived
    /// on the ingress interface (`true`) or the egress interface (`false`).
    fn process_packet(&self, packet: UserPacket, is_ingress: bool);
}

/// Factory that hands out a per-queue `PacketSink` for each AF_XDP queue the
/// manager spins up. `XskManager` calls this once per queue during bring-up.
pub trait PacketSinkFactory: Send + Sync {
    /// Return a sink bound to `queue_id`, or `None` to skip per-packet
    /// tracking on that queue.
    fn sink_for_queue(&self, queue_id: u32) -> Option<Arc<dyn PacketSink>>;
}
