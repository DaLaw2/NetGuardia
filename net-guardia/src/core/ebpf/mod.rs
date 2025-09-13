pub mod access_control;
pub mod ring_buffer;
pub mod service;
pub mod statistics;

use std::sync::Arc;

use aya::Ebpf;
use crossbeam::queue::SegQueue;
use macros::log;
use tokio::sync::oneshot;

use crate::core::ebpf::access_control::AccessControl;
use crate::core::ebpf::ring_buffer::RingBuffer;
use crate::core::ebpf::service::Service;
use crate::core::ebpf::statistics::Statistics;
use crate::core::infrastructure::app_config::AppConfig;
use crate::model::error::system::SystemError;
use crate::model::error::Error;

pub struct EbpfServices {
    #[allow(dead_code)]
    pub ring_buffer: Arc<RingBuffer>,
    pub access_control: Arc<AccessControl>,
    pub service: Arc<Service>,
    pub statistics: Arc<Statistics>,
    shutdowns: SegQueue<oneshot::Sender<()>>,
}

impl EbpfServices {
    pub fn new(app_config: Arc<AppConfig>, ingress_ebpf: &mut Ebpf, egress_ebpf: &mut Ebpf) -> Result<Self, Error> {
        let ring_buffer = RingBuffer::new()?;
        let access_control = AccessControl::new(ingress_ebpf)?;
        let service = Service::new(ingress_ebpf)?;
        let statistics = Statistics::new(app_config, ingress_ebpf, egress_ebpf)?;
        let ebpf_services = Self {
            ring_buffer: Arc::new(ring_buffer),
            access_control: Arc::new(access_control),
            service: Arc::new(service),
            statistics: Arc::new(statistics),
            shutdowns: SegQueue::new(),
        };
        Ok(ebpf_services)
    }

    pub async fn run(self: Arc<Self>) {
        let statistics = self.statistics.clone();
        let statistics_shutdown = statistics.run().await;
        self.shutdowns.push(statistics_shutdown);
    }

    pub fn terminate(self: Arc<Self>) {
        while let Some(shutdown) = self.shutdowns.pop() {
            if shutdown.send(()).is_err() {
                log!(SystemError::ShutdownSignalFailed);
            }
        }
    }
}
