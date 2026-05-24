use std::sync::Arc;

use crate::core::response::engine::SoarEngine;
use crate::domain::common::event::ThreatDetectedEvent;
use crate::domain::response::playbook::Playbook;
use crate::interface::response::dry_run::DryRunMatch;

impl SoarEngine {
    pub fn find_matching_playbooks(&self, event: &ThreatDetectedEvent) -> Vec<Arc<Playbook>> {
        self.matcher.find_matching_playbooks(event)
    }

    pub fn is_cooldown_active(&self, playbook_id: i64, source_ip: &str, cooldown_secs: i64) -> bool {
        self.matcher.is_cooldown_active(playbook_id, source_ip, cooldown_secs)
    }

    pub fn record_cooldown(&self, playbook_id: i64, source_ip: &str) {
        self.matcher.record_cooldown(playbook_id, source_ip)
    }

    pub fn cleanup_expired_cooldowns(&self) {
        self.matcher.cleanup_expired_cooldowns()
    }

    pub fn decrement_block_count(&self) {
        self.matcher.decrement_block_count()
    }

    pub fn dry_run(&self, event: &ThreatDetectedEvent) -> Vec<DryRunMatch> {
        self.matcher.dry_run(event)
    }
}
