pub mod access_control;
pub mod rate_limit;
pub mod protocol_filter;
pub mod xsk_manager;

use std::sync::Arc;

use aya::Ebpf;
use crossbeam::queue::SegQueue;
use macros::log;
use tokio::sync::oneshot;

use crate::core::ebpf::access_control::AccessControl;
use crate::core::ebpf::rate_limit::RateLimitConfig;
use crate::core::ebpf::protocol_filter::ProtocolFilter;
use crate::core::ebpf::xsk_manager::XskManager;
use crate::core::infrastructure::app_config::AppConfig;
use crate::core::ml::engine::Engine;
use crate::model::error::system::SystemError;
use crate::model::error::Error;

pub struct EbpfServices {
    pub xsk_manager: Arc<XskManager>,
    pub access_control: Arc<AccessControl>,
    pub protocol_filter: Arc<ProtocolFilter>,
    pub rate_limit: Arc<RateLimitConfig>,
    pub shutdowns: SegQueue<oneshot::Sender<()>>,
}

impl EbpfServices {
    pub fn new(app_config: Arc<AppConfig>, ingress_ebpf: &mut Ebpf, egress_ebpf: &mut Ebpf) -> Result<Self, Error> {
        let xsk_manager = XskManager::new(app_config.clone(), ingress_ebpf, egress_ebpf)?;
        let access_control = AccessControl::new(ingress_ebpf)?;
        let protocol_filter = ProtocolFilter::new(ingress_ebpf)?;
        let rate_limit = RateLimitConfig::new(ingress_ebpf)?;
        Ok(Self {
            xsk_manager: Arc::new(xsk_manager),
            access_control: Arc::new(access_control),
            protocol_filter: Arc::new(protocol_filter),
            rate_limit: Arc::new(rate_limit),
            shutdowns: SegQueue::new(),
        })
    }

    pub async fn run(self: Arc<Self>, ml_engine: Arc<Engine>) -> Result<(), Error> {
        let xsk_manager = self.xsk_manager.clone();
        xsk_manager.run(Some(ml_engine), &self.shutdowns)?;
        Ok(())
    }

    pub fn terminate(self: Arc<Self>) {
        while let Some(shutdown) = self.shutdowns.pop() {
            if shutdown.send(()).is_err() {
                log!(SystemError::ShutdownSignalFailed);
            }
        }
    }
}
