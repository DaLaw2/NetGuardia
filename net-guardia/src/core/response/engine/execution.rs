use macros::log;

use crate::common::error::Error;
use crate::core::response::engine::SoarEngine;
use crate::core::response::rate_limit_owner::RestoreOutcome;
use crate::domain::common::event::ThreatDetectedEvent;
use crate::domain::response::log::SoarLog;
use crate::domain::response::outcome::ThreatHandleOutcome;

impl SoarEngine {
    pub fn handle_concurrency(&self) -> usize {
        self.matcher.config.load().soar.handle_concurrency.max(1)
    }

    pub async fn handle_threat_event(&self, event: &ThreatDetectedEvent) -> Result<ThreatHandleOutcome, Error> {
        let matching = self.find_matching_playbooks(event);

        if matching.is_empty() {
            if !event.source_ip.is_empty() {
                log!(SoarLog::FallbackTriggered(event.attack_type.clone()));
                let outcome = self.execute_fallback(event).await?;
                return Ok(ThreatHandleOutcome::Fallback { outcome });
            }
            return Ok(ThreatHandleOutcome::NoSourceIp);
        }

        let mut errors = 0;
        let count = matching.len();
        for playbook in matching {
            if let Err(e) = self.execute_playbook(&playbook, event).await {
                errors += 1;
                log!(SoarLog::PlaybookError(playbook.name.clone(), e.to_string()));
            }
        }

        Ok(ThreatHandleOutcome::PlaybooksExecuted { count, errors })
    }

    pub async fn recover_active_blocks(&self) -> Result<(), Error> {
        self.retry_pending_unblocks().await;

        let active_blocks = self.db.list_active_soar_blocks().await?;
        let count = active_blocks.len();

        for block in &active_blocks {
            if let Err(e) = self.access_control.block_ip(&block.source_ip) {
                log!(SoarLog::RecoveryFailed(block.source_ip.clone(), e.to_string()));
                log!(SoarLog::BlockEnforcementGap(block.source_ip.clone()));
            }
        }

        if count > 0 {
            log!(SoarLog::RecoveryComplete(count));
        }

        Ok(())
    }

    async fn retry_pending_unblocks(&self) {
        let pending = match self.db.list_pending_unblocks().await {
            Ok(p) => p,
            Err(e) => {
                log!(SoarLog::PendingUnblocksLoadFailed(e.to_string()));
                return;
            }
        };

        for pu in pending {
            if pu.exhausted_at.is_some() {
                continue;
            }
            if pu.retry_count >= self.matcher.config.load().soar.max_pending_unblock_retries {
                log!(SoarLog::PendingUnblockRetryExhausted(
                    pu.source_ip.clone(),
                    pu.retry_count,
                ));
                self.mark_pending_unblock_exhausted_or_log(pu.id, &pu.source_ip, "max retries exceeded")
                    .await;
                continue;
            }

            match self.access_control.unblock_ip(&pu.source_ip) {
                Ok(()) => {
                    self.delete_pending_unblock_or_log(pu.id, &pu.source_ip, "successful retry")
                        .await;
                    log!(SoarLog::PendingUnblockRecovered(pu.source_ip, pu.retry_count + 1));
                }
                Err(e) => {
                    self.increment_pending_unblock_retry_or_log(pu.id, &pu.source_ip).await;
                    log!(SoarLog::PendingUnblockRetryFailed(
                        pu.source_ip,
                        pu.retry_count + 1,
                        e.to_string(),
                    ));
                }
            }
        }
    }

    async fn delete_pending_unblock_or_log(&self, id: i64, source_ip: &str, reason: &str) {
        if let Err(e) = self.db.delete_pending_unblock(id).await {
            log!(SoarLog::PendingUnblockDeleteFailed(
                id,
                source_ip.to_string(),
                reason.to_string(),
                e.to_string(),
            ));
        }
    }

    async fn increment_pending_unblock_retry_or_log(&self, id: i64, source_ip: &str) {
        if let Err(e) = self.db.increment_pending_unblock_retry(id).await {
            log!(SoarLog::PendingUnblockRetryIncrementFailed(
                id,
                source_ip.to_string(),
                e.to_string(),
            ));
        }
    }

    async fn mark_pending_unblock_exhausted_or_log(&self, id: i64, source_ip: &str, reason: &str) {
        if let Err(e) = self.db.mark_pending_unblock_exhausted(id, reason).await {
            log!(SoarLog::PendingUnblockExhaustMarkFailed(
                id,
                source_ip.to_string(),
                e.to_string(),
            ));
        }
    }

    pub async fn check_rate_limit_restoration(&self) -> Result<Option<RestoreOutcome>, Error> {
        match &self.rate_limit {
            Some(owner) => owner.restore_if_expired().await.map(Some),
            None => Ok(None),
        }
    }
}
