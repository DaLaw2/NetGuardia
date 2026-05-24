pub mod access_control;
pub mod drop_monitor;
pub mod geo_block;
pub mod protocol_filter;
pub mod rate_limit;
pub mod xsk_manager;

use std::sync::Arc;

use arc_swap::ArcSwap;
use aya::Ebpf;
use aya::maps::{MapData, RingBuf};
use crossbeam::queue::SegQueue;
use parking_lot::Mutex;
use tokio::sync::oneshot;

use crate::adapter::ebpf::access_control::AccessControl;
use crate::adapter::ebpf::drop_monitor::DropMonitor;
use crate::adapter::ebpf::geo_block::GeoBlock;
use crate::adapter::ebpf::protocol_filter::ProtocolFilter;
use crate::adapter::ebpf::rate_limit::RateLimitConfig;
use crate::adapter::ebpf::xsk_manager::XskManager;
use crate::common::error::Error;
use crate::domain::common::config::AppConfig;
use crate::domain::data_plane::error::EbpfError;
use crate::interface::data_plane::dns_query_filter::DnsQueryFilter;
use crate::interface::data_plane::packet_sink::PacketSinkFactory;

pub struct EbpfServices {
    pub xsk_manager: Arc<XskManager>,
    pub access_control: Arc<AccessControl>,
    pub protocol_filter: Arc<ProtocolFilter>,
    pub dns_query_filter: Arc<dyn DnsQueryFilter>,
    pub geo_block: Arc<GeoBlock>,
    pub rate_limit: Arc<RateLimitConfig>,
    pub drop_monitor: Arc<DropMonitor>,
    drop_ring_buf: Mutex<Option<RingBuf<MapData>>>,
    pub shutdowns: SegQueue<oneshot::Sender<()>>,
}

impl EbpfServices {
    pub fn new(
        app_config: Arc<ArcSwap<AppConfig>>,
        ingress_ebpf: &mut Ebpf,
        egress_ebpf: &mut Ebpf,
        dns_query_filter: Arc<dyn DnsQueryFilter>,
    ) -> Result<Self, Error> {
        let xsk_manager = XskManager::new(app_config.clone(), ingress_ebpf, egress_ebpf)?;
        let access_control = AccessControl::new(ingress_ebpf)?;
        let protocol_filter = ProtocolFilter::new(ingress_ebpf)?;
        let geo_block = GeoBlock::new(ingress_ebpf, app_config.clone())?;
        let rate_limit = RateLimitConfig::new(ingress_ebpf)?;
        let drop_monitor = Arc::new(DropMonitor::new(app_config.load().observability.drop_channel_capacity));
        let drop_ring_buf = {
            let map = ingress_ebpf.take_map("DROP_EVENTS").ok_or(EbpfError::MapNotFound)?;
            RingBuf::try_from(map).map_err(EbpfError::MapOperationError)?
        };
        Ok(Self {
            xsk_manager: Arc::new(xsk_manager),
            access_control: Arc::new(access_control),
            protocol_filter: Arc::new(protocol_filter),
            dns_query_filter,
            geo_block: Arc::new(geo_block),
            rate_limit: Arc::new(rate_limit),
            drop_monitor,
            drop_ring_buf: Mutex::new(Some(drop_ring_buf)),
            shutdowns: SegQueue::new(),
        })
    }

    pub fn unavailable(app_config: Arc<ArcSwap<AppConfig>>, dns_query_filter: Arc<dyn DnsQueryFilter>) -> Self {
        Self {
            xsk_manager: Arc::new(XskManager::unavailable(app_config.clone())),
            access_control: Arc::new(AccessControl::unavailable()),
            protocol_filter: Arc::new(ProtocolFilter::unavailable()),
            dns_query_filter,
            geo_block: Arc::new(GeoBlock::unavailable(app_config.clone())),
            rate_limit: Arc::new(RateLimitConfig::unavailable()),
            drop_monitor: Arc::new(DropMonitor::new(app_config.load().observability.drop_channel_capacity)),
            drop_ring_buf: Mutex::new(None),
            shutdowns: SegQueue::new(),
        }
    }

    pub async fn run(self: Arc<Self>, sink_factory: Arc<dyn PacketSinkFactory>) -> Result<(), Error> {
        let xsk_manager = self.xsk_manager.clone();
        let dns = self.dns_query_filter.clone();
        xsk_manager.run(
            Some(sink_factory),
            Some(dns),
            Some(self.drop_monitor.clone()),
            &self.shutdowns,
        )?;

        let ring_buf = self.drop_ring_buf.lock().take();
        if let Some(ring_buf) = ring_buf {
            let shutdown = drop_monitor::start_consumer(ring_buf, self.drop_monitor.clone()).await;
            self.shutdowns.push(shutdown);
        }

        Ok(())
    }

    pub fn terminate(self: Arc<Self>) {
        while let Some(shutdown) = self.shutdowns.pop() {
            let _ = shutdown.send(());
        }
    }
}
