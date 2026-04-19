use std::sync::Arc;

use macros::log;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};

use crate::core::playbook_service::ip_version_from_str;
use crate::core::soar::engine::SoarEngine;
use crate::interface::port::access_control::AccessControlPort;
use crate::interface::port::app_repo::AppRepo;
use crate::model::error::Error;
use crate::model::log::soar::SoarLog;

/// TTL expiry scheduler: runs every 60 seconds, removes expired auto-block rules.
/// Before removing from eBPF, checks if a manual ACL rule exists for the same IP.
pub struct TtlScheduler {
    db: Arc<dyn AppRepo>,
    access_control: Arc<dyn AccessControlPort>,
    soar_engine: Arc<SoarEngine>,
}

impl TtlScheduler {
    pub fn new(db: Arc<dyn AppRepo>, access_control: Arc<dyn AccessControlPort>, soar_engine: Arc<SoarEngine>) -> Self {
        Self {
            db,
            access_control,
            soar_engine,
        }
    }

    /// Spawn a background tokio task that runs the TTL sweep every 60 seconds.
    pub fn start(self) -> JoinHandle<()> {
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
    /// Also checks for expired rate limit adjustments and cleans up stale cooldowns.
    async fn sweep(&self) -> Result<(), Error> {
        // Check rate limit restoration
        if let Err(e) = self.soar_engine.check_rate_limit_restoration().await {
            log!(SoarLog::EventHandlingFailed(format!(
                "Rate limit restoration check failed: {}",
                e
            )));
        }

        // Clean up expired cooldown + frequency tracker entries to prevent unbounded memory growth
        self.soar_engine.cleanup_expired_cooldowns();

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
                log!(SoarLog::WhitelistSkipped(
                    source_ip.clone(),
                    "TTL expired but manual ACL exists".to_string()
                ));
                continue;
            }

            // Remove from eBPF ACL via AccessControlPort
            if let Err(e) = self.access_control.unblock_ip(source_ip) {
                log!(SoarLog::RecoveryFailed(
                    source_ip.clone(),
                    format!("unblock failed: {}", e)
                ));
            }

            // Atomically drop acl_rules entry AND mark soar_block_rules
            // unblocked in one transaction.
            let ip_version = ip_version_from_str(source_ip);
            self.db.commit_soar_unblock_to_db(*id, ip_version, source_ip)?;
            self.soar_engine.decrement_block_count();
            removed += 1;
        }

        if removed > 0 || skipped > 0 {
            log!(SoarLog::TtlSweepComplete(removed, skipped));
        }

        Ok(())
    }
}
