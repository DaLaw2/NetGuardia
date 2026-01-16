pub mod access_control;
pub mod service;
pub mod statistics;
pub mod xsk_manager;

use std::sync::Arc;
use std::time::Duration;

use aya::Ebpf;
use crossbeam::queue::SegQueue;
use macros::log;
use tokio::sync::oneshot;

use crate::core::ebpf::access_control::AccessControl;
use crate::core::ebpf::service::Service;
use crate::core::ebpf::statistics::Statistics;
use crate::core::ebpf::xsk_manager::XskManager;
use crate::core::infrastructure::health::SystemHealth;
use crate::core::infrastructure::app_config::AppConfig;
use crate::model::error::system::SystemError;
use crate::model::error::Error;

pub struct EbpfServices {
    pub xsk_manager: Arc<XskManager>,
    pub access_control: Arc<AccessControl>,
    pub service: Arc<Service>,
    pub statistics: Arc<Statistics>,
    pub health: Arc<SystemHealth>,
    shutdowns: SegQueue<oneshot::Sender<()>>,
}

impl EbpfServices {
    pub fn new(
        app_config: Arc<AppConfig>,
        ingress_ebpf: &mut Ebpf,
        egress_ebpf: &mut Ebpf,
    ) -> Result<Self, Error> {
        let xsk_manager = XskManager::new(app_config.clone(), ingress_ebpf)?;
        let access_control = AccessControl::new(ingress_ebpf)?;
        let health = SystemHealth::new(&app_config)?;
        let service = Service::new(ingress_ebpf)?;
        let statistics = Statistics::new(app_config, ingress_ebpf, egress_ebpf)?;
        let ebpf_services = Self {
            xsk_manager: Arc::new(xsk_manager),
            access_control: Arc::new(access_control),
            service: Arc::new(service),
            statistics: Arc::new(statistics),
            health: Arc::new(health),
            shutdowns: SegQueue::new(),
        };
        Ok(ebpf_services)
    }

    pub async fn run(self: Arc<Self>) -> Result<(), Error> {
        let xsk_manager = self.xsk_manager.clone();
        let statistics = self.statistics.clone();
        let health = self.health.clone();

        xsk_manager.run()?;

        let statistics_shutdown = statistics.run().await;
        let health_shutdown = health.run(Duration::from_secs(3)).await;

        self.shutdowns.push(statistics_shutdown);
        self.shutdowns.push(health_shutdown);
        Ok(())
    }

    pub fn terminate(self: Arc<Self>) {
        self.xsk_manager.shutdown();
        while let Some(shutdown) = self.shutdowns.pop() {
            if shutdown.send(()).is_err() {
                log!(SystemError::ShutdownSignalFailed);
            }
        }
    }
}