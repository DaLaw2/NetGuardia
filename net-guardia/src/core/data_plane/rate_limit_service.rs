use std::sync::Arc;

use crate::domain::common::error::Error;
use crate::domain::common::system::rate_limit_settings::RateLimitSettings;
use crate::interface::app_repo::AppRepo;
use crate::interface::rate_limit_api::RateLimitPort;

/// Domain service that coordinates rate limit config updates between DB and eBPF.
pub struct RateLimitService {
    db: Arc<dyn AppRepo>,
    config: Arc<dyn RateLimitPort>,
}

impl RateLimitService {
    pub fn new(db: Arc<dyn AppRepo>, config: Arc<dyn RateLimitPort>) -> Self {
        Self { db, config }
    }

    pub fn config(&self) -> &dyn RateLimitPort {
        self.config.as_ref()
    }

    pub async fn update(&self, settings: &RateLimitSettings) -> Result<(), Error> {
        if let Some(v) = settings.packet_rate {
            self.db.set_rate_limit("packet_rate", v).await?;
            self.config.set_packet_rate(v)?;
        }
        if let Some(v) = settings.syn_rate {
            self.db.set_rate_limit("syn_rate", v).await?;
            self.config.set_syn_rate(v)?;
        }
        if let Some(v) = settings.udp_rate {
            self.db.set_rate_limit("udp_rate", v).await?;
            self.config.set_udp_rate(v)?;
        }
        if let Some(v) = settings.dns_rate {
            self.db.set_rate_limit("dns_rate", v).await?;
            self.config.set_dns_rate(v)?;
        }
        if let Some(v) = settings.window_ns {
            self.db.set_rate_limit("window_ns", v).await?;
            self.config.set_window_ns(v)?;
        }
        Ok(())
    }
}
