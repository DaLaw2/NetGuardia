use std::sync::Arc;

use macros::log;
use tokio::time::{self, Duration};

use crate::adapter::persistence::Database;
use crate::core::soar::engine::SoarEngine;
use crate::interface::port::access_control::AccessControlPort;
use crate::model::error::Error;
use crate::model::error::soar::SoarError;
use crate::model::log::soar::SoarLog;

/// TTL expiry scheduler: runs every 60 seconds, removes expired auto-block rules.
/// Before removing from eBPF, checks if a manual ACL rule exists for the same IP.
pub struct TtlScheduler {
    db: Arc<Database>,
    access_control: Arc<dyn AccessControlPort>,
    soar_engine: Arc<SoarEngine>,
}

impl TtlScheduler {
    pub fn new(
        db: Arc<Database>,
        access_control: Arc<dyn AccessControlPort>,
        soar_engine: Arc<SoarEngine>,
    ) -> Self {
        Self { db, access_control, soar_engine }
    }

    /// Spawn a background tokio task that runs the TTL sweep every 60 seconds.
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            log!(SoarLog::EngineStarted); // TTL scheduler uses same log channel
            let mut interval = time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = self.sweep().await {
                    log!(SoarLog::EventHandlingFailed(format!("TTL sweep failed: {}", e)));
                }
            }
        })
    }

    /// Sweep expired block rules and remove from eBPF if no manual ACL conflict.
    /// Also checks for expired rate limit adjustments.
    async fn sweep(&self) -> Result<(), Error> {
        // Check rate limit restoration
        if let Err(e) = self.soar_engine.check_rate_limit_restoration() {
            log!(SoarLog::EventHandlingFailed(format!("Rate limit restoration check failed: {}", e)));
        }

        let expired = self.db.get_expired_soar_blocks()?;

        if expired.is_empty() {
            return Ok(());
        }

        let mut removed = 0u32;
        let mut skipped = 0u32;

        for (id, source_ip, _playbook_id) in &expired {
            // Check if a manual ACL rule exists for this IP
            let has_manual_rule = self.db.has_manual_acl_rule(source_ip)?;

            if has_manual_rule {
                // Only mark as unblocked in SOAR records, don't remove from eBPF
                self.db.mark_soar_block_unblocked(*id)?;
                self.soar_engine.decrement_block_count();
                skipped += 1;
                log!(SoarLog::WhitelistSkipped(source_ip.clone(), "TTL expired but manual ACL exists".to_string()));
                continue;
            }

            // Remove from eBPF ACL via AccessControlPort
            if let Err(e) = self.access_control.unblock_ip(source_ip).await {
                log!(SoarLog::RecoveryFailed(source_ip.clone(), format!("unblock failed: {}", e)));
            }

            // Also remove from acl_rules DB table (the auto-added entry)
            let ip_version = crate::core::playbook_service::ip_version_from_str(source_ip);
            if let Err(e) = self.db.delete_acl_rule(ip_version, "source", "blacklist", source_ip, 0) {
                log!(SoarError::AclCleanupFailed(e));
            }

            // Mark as unblocked
            self.db.mark_soar_block_unblocked(*id)?;
            self.soar_engine.decrement_block_count();
            removed += 1;
        }

        if removed > 0 || skipped > 0 {
            log!(SoarLog::TtlSweepComplete(removed, skipped));
        }

        Ok(())
    }
}
