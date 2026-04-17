//! SOAR domain: playbook matching, condition evaluation, cooldown tracking.
//!
//! Pure domain logic — no external I/O, no DB writes, no network calls.
//! All methods live in an `impl SoarEngine` block so they can access the
//! engine's in-memory caches (`playbooks`, `cooldowns`, `frequency_tracker`),
//! but none of them touch anything outside those fields.

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use macros::log;

use crate::core::soar::engine::SoarEngine;
use crate::model::event::ThreatDetectedEvent;
use crate::model::log::soar::SoarLog;
use crate::model::soar::condition::{ConditionType, PlaybookCondition};
use crate::model::soar::playbook::Playbook;

impl SoarEngine {
    /// Find playbooks matching the event via trigger_event + multi-condition AND logic.
    pub(super) fn find_matching_playbooks(&self, event: &ThreatDetectedEvent) -> Vec<Playbook> {
        let playbooks = self.playbooks.read();
        playbooks
            .iter()
            .filter(|pb| pb.enabled && pb.trigger_event == event.attack_type)
            .filter(|pb| self.evaluate_conditions(pb, event))
            .cloned()
            .collect()
    }

    /// Evaluate all conditions on a playbook (AND logic).
    /// If no conditions are configured, the playbook matches unconditionally.
    pub(super) fn evaluate_conditions(&self, pb: &Playbook, event: &ThreatDetectedEvent) -> bool {
        if pb.conditions.is_empty() {
            return true;
        }

        // Evaluate non-frequency conditions first (avoid recording non-matching events)
        for cond in &pb.conditions {
            if cond.condition_type == ConditionType::Frequency {
                continue;
            }
            if !self.evaluate_single_condition(cond, pb, event) {
                return false;
            }
        }

        // Evaluate frequency conditions last
        for cond in &pb.conditions {
            if cond.condition_type == ConditionType::Frequency && !self.evaluate_single_condition(cond, pb, event) {
                return false;
            }
        }

        true
    }

    /// Evaluate a single condition against the event.
    /// The `operator` field controls comparison direction:
    /// - Threshold: ">=" (default) or "<="
    /// - SourceCountry/IpPattern: "in" (default) or "not_in"
    /// - RepeatOffender: "==" only
    /// - Frequency: ">=" only
    pub(super) fn evaluate_single_condition(
        &self,
        cond: &PlaybookCondition,
        pb: &Playbook,
        event: &ThreatDetectedEvent,
    ) -> bool {
        match cond.condition_type {
            ConditionType::Threshold => {
                let threshold = match cond.value.parse::<f64>() {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                let confidence = event.confidence as f64;
                let met = if cond.operator == "<=" {
                    confidence <= threshold
                } else {
                    confidence >= threshold
                };
                if !met {
                    log!(SoarLog::ConditionNotMet(
                        "threshold".to_string(),
                        pb.name.clone(),
                        format!("{:.2}", event.confidence),
                    ));
                }
                met
            }
            ConditionType::SourceCountry => {
                let countries: Vec<&str> = cond.value.split(',').map(|s| s.trim()).collect();
                let matches = event
                    .geoip_country
                    .as_ref()
                    .is_some_and(|c| countries.iter().any(|&cc| cc.eq_ignore_ascii_case(c)));
                let met = if cond.operator == "not_in" { !matches } else { matches };
                if !met {
                    log!(SoarLog::ConditionNotMet(
                        "source_country".to_string(),
                        pb.name.clone(),
                        event.geoip_country.clone().unwrap_or_else(|| "none".to_string()),
                    ));
                }
                met
            }
            ConditionType::IpPattern => {
                let net = match cond.value.parse::<ipnetwork::IpNetwork>() {
                    Ok(n) => n,
                    Err(_) => return false,
                };
                let ip = match event.source_ip.parse::<IpAddr>() {
                    Ok(a) => a,
                    Err(_) => return false,
                };
                let matches = net.contains(ip);
                let met = if cond.operator == "not_in" { !matches } else { matches };
                if !met {
                    log!(SoarLog::ConditionNotMet(
                        "ip_pattern".to_string(),
                        pb.name.clone(),
                        event.source_ip.clone(),
                    ));
                }
                met
            }
            ConditionType::RepeatOffender => {
                let expected = cond.value.eq_ignore_ascii_case("true");
                let met = event.is_repeat_offender == expected;
                if !met {
                    log!(SoarLog::ConditionNotMet(
                        "repeat_offender".to_string(),
                        pb.name.clone(),
                        format!("{}", event.is_repeat_offender),
                    ));
                }
                met
            }
            ConditionType::Frequency => {
                let required = match cond.value.parse::<u64>() {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                let window_secs = cond.value2.as_ref().and_then(|s| s.parse::<u64>().ok()).unwrap_or(60);
                let count = self
                    .frequency_tracker
                    .record_and_count(pb.id, &event.source_ip, window_secs);
                let met = count >= required;
                if !met {
                    log!(SoarLog::FrequencyNotMet(pb.name.clone(), count, required, window_secs));
                }
                met
            }
        }
    }

    /// Check if cooldown is active for this playbook + source IP combination.
    pub(super) fn is_cooldown_active(&self, playbook_id: i64, source_ip: &str, cooldown_secs: i64) -> bool {
        let key = (playbook_id, source_ip.to_string());
        if let Some(last_exec) = self.cooldowns.get(&key) {
            let elapsed = last_exec.elapsed();
            if elapsed.as_secs() < cooldown_secs as u64 {
                return true;
            }
        }
        false
    }

    /// Record cooldown for a playbook + source IP combination.
    pub(super) fn record_cooldown(&self, playbook_id: i64, source_ip: &str) {
        let key = (playbook_id, source_ip.to_string());
        self.cooldowns.insert(key, Instant::now());
    }

    /// Remove expired cooldown entries to prevent unbounded growth.
    /// Called by TTL scheduler every 60 seconds.
    pub fn cleanup_expired_cooldowns(&self) {
        let max_cooldown_secs = {
            let playbooks = self.playbooks.read();
            playbooks.iter().map(|p| p.cooldown_secs as u64).max().unwrap_or(3600)
        };
        let expiry = Duration::from_secs(max_cooldown_secs.saturating_mul(2).max(3600));
        let before = self.cooldowns.len();
        self.cooldowns.retain(|_, instant| instant.elapsed() < expiry);
        let removed = before.saturating_sub(self.cooldowns.len());
        if removed > 0 {
            log!(SoarLog::CooldownCleanup(removed as u32));
        }

        // Also clean up empty frequency tracker entries
        let freq_removed = self.frequency_tracker.cleanup();
        if freq_removed > 0 {
            log!(SoarLog::FrequencyCleanup(freq_removed));
        }
    }

    /// Decrement the active block counter (called by TTL scheduler on unblock).
    /// Uses CAS loop to avoid underflow race condition.
    pub fn decrement_block_count(&self) {
        loop {
            let current = self.active_block_count.load(Ordering::SeqCst);
            if current == 0 {
                return; // Nothing to decrement
            }
            match self
                .active_block_count
                .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return,
                Err(_) => continue, // Retry on contention
            }
        }
    }

    /// Check if an IP address is private/loopback/link-local (SSRF protection).
    pub(super) fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()          // 127.0.0.0/8
                || v4.is_private()         // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local()      // 169.254.0.0/16
                || v4.is_unspecified()     // 0.0.0.0
                || v4.is_broadcast() // 255.255.255.255
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()           // ::1
                || v6.is_unspecified()     // ::
                // fe80::/10 (link-local)
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // fc00::/7 (unique local: fc00::/8 + fd00::/8)
                || (v6.segments()[0] & 0xfe00) == 0xfc00
            }
        }
    }
}
