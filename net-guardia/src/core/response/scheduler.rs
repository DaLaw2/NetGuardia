use std::sync::Arc;

use macros::log;
use tokio::task::JoinHandle;
use tokio::task::spawn_blocking;
use tokio::time::{self, Duration};

use crate::core::response::engine::SoarEngine;
use crate::domain::common::error::Error;
use crate::domain::response::log::SoarLog;
use crate::interface::access_control::AccessControlPort;
use crate::interface::app_repo::AppRepo;
use crate::utils::ip_address::ip_version_from_str;

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

        let expired = self.db.list_expired_soar_blocks().await?;

        if expired.is_empty() {
            return Ok(());
        }

        let mut removed = 0u32;
        let mut skipped = 0u32;

        for block in &expired {
            // Check if a manual ACL rule exists for this IP
            let has_manual_rule = self.db.has_manual_acl_rule(&block.source_ip).await?;

            if has_manual_rule {
                // Only mark as unblocked in SOAR records, don't remove from eBPF
                self.db.mark_soar_block_unblocked(block.id).await?;
                self.soar_engine.decrement_block_count();
                skipped += 1;
                log!(SoarLog::WhitelistSkipped(
                    block.source_ip.clone(),
                    "TTL expired but manual ACL exists".to_string()
                ));
                continue;
            }

            // Remove from eBPF ACL via AccessControlPort
            if let Err(e) = unblock_ip_blocking(Arc::clone(&self.access_control), block.source_ip.clone()).await {
                log!(SoarLog::RecoveryFailed(
                    block.source_ip.clone(),
                    format!("unblock failed: {}", e)
                ));
                self.db.insert_pending_unblock(&block.source_ip).await?;
                skipped += 1;
                continue;
            }

            // Atomically drop acl_rules entry AND mark soar_block_rules
            // unblocked in one transaction.
            let ip_version = ip_version_from_str(&block.source_ip);
            self.db
                .commit_soar_unblock_to_db(block.id, ip_version, &block.source_ip)
                .await?;
            self.soar_engine.decrement_block_count();
            removed += 1;
        }

        if removed > 0 || skipped > 0 {
            log!(SoarLog::TtlSweepComplete(removed, skipped));
        }

        Ok(())
    }
}

async fn unblock_ip_blocking(access_control: Arc<dyn AccessControlPort>, source_ip: String) -> Result<(), Error> {
    spawn_blocking(move || access_control.unblock_ip(&source_ip))
        .await
        .map_err(|e| crate::domain::response::error::SoarError::ActionFailed("unblock_ip", e))?
}
