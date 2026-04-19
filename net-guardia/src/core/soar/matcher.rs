//! SOAR domain: playbook matching, condition evaluation, cooldown tracking.
//!
//! Pure domain logic — no external I/O, no DB writes, no network calls.
//! All methods live in an `impl SoarEngine` block so they can access the
//! engine's in-memory caches (`playbooks`, `cooldowns`, `frequency_tracker`),
//! but none of them touch anything outside those fields.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use macros::log;

use crate::core::soar::engine::SoarEngine;
use crate::model::event::{DetectionSource, ThreatDetectedEvent};
use crate::model::log::soar::SoarLog;
use crate::model::soar::condition::{ConditionType, PlaybookCondition};
use crate::model::soar::dry_run::{DryRunAction, DryRunConditionResult, DryRunMatch};
use crate::model::soar::playbook::Playbook;

/// Default frequency-condition window when the playbook omits `value2`.
const DEFAULT_FREQUENCY_WINDOW_SECS: u64 = 60;

/// Default minimum confidence for `SingleSourceHigh` when the playbook
/// omits `value2`. Conservative enough that ad-hoc solo playbooks don't
/// auto-block noisy single-source hits.
const DEFAULT_SINGLE_SOURCE_HIGH_MIN_CONFIDENCE: f32 = 0.95;

/// Default expiry for cooldown cleanup when no playbook has a cooldown set.
const DEFAULT_COOLDOWN_EXPIRY_SECS: u64 = 3600;

impl SoarEngine {
    /// Find playbooks matching the event via trigger_event + multi-condition AND logic.
    /// Returns `Arc<Playbook>` so the per-event hot path bumps a refcount
    /// instead of cloning the playbook (with all its nested conditions and
    /// actions) on every fired detection.
    pub(super) fn find_matching_playbooks(&self, event: &ThreatDetectedEvent) -> Vec<Arc<Playbook>> {
        self.playbooks
            .load()
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
                let window_secs = cond
                    .value2
                    .as_ref()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(DEFAULT_FREQUENCY_WINDOW_SECS);
                let count = self
                    .frequency_tracker
                    .record_and_count(pb.id, &event.source_ip, window_secs);
                let met = count >= required;
                if !met {
                    log!(SoarLog::FrequencyNotMet(pb.name.clone(), count, required, window_secs));
                }
                met
            }
            ConditionType::MultiSourceMin => {
                let required = match cond.value.parse::<usize>() {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                let met = event.active_source_count >= required;
                if !met {
                    log!(SoarLog::ConditionNotMet(
                        "multi_source_min".to_string(),
                        pb.name.clone(),
                        format!("{} / {}", event.active_source_count, required),
                    ));
                }
                met
            }
            ConditionType::SingleSourceHigh => {
                // `value` names the target source (canonical Display form
                // or a common alias); `value2` is the minimum confidence.
                let target_source = match DetectionSource::from_str(&cond.value) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                let min_conf = cond
                    .value2
                    .as_ref()
                    .and_then(|s| s.parse::<f32>().ok())
                    .unwrap_or(DEFAULT_SINGLE_SOURCE_HIGH_MIN_CONFIDENCE);
                // Solo = exactly one contributing source AND it matches the
                // target source AND confidence clears the escape-hatch bar.
                let solo_match =
                    event.active_source_count == 1 && event.sources.len() == 1 && event.sources[0] == target_source;
                let conf_met = event.confidence >= min_conf;
                let met = solo_match && conf_met;
                if !met {
                    log!(SoarLog::ConditionNotMet(
                        "single_source_high".to_string(),
                        pb.name.clone(),
                        format!(
                            "sources={:?} count={} conf={:.3} target={} need_conf>={:.3}",
                            event.sources, event.active_source_count, event.confidence, cond.value, min_conf
                        ),
                    ));
                }
                met
            }
            ConditionType::FusedConfidenceAbove => {
                let threshold = match cond.value.parse::<f32>() {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                let met = if cond.operator == "<=" {
                    event.fused_confidence <= threshold
                } else {
                    event.fused_confidence >= threshold
                };
                if !met {
                    log!(SoarLog::ConditionNotMet(
                        "fused_confidence_above".to_string(),
                        pb.name.clone(),
                        format!("{:.3} vs {:.3}", event.fused_confidence, threshold),
                    ));
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
        let max_cooldown_secs = self
            .playbooks
            .load()
            .iter()
            .map(|p| p.cooldown_secs as u64)
            .max()
            .unwrap_or(DEFAULT_COOLDOWN_EXPIRY_SECS);
        let expiry = Duration::from_secs(max_cooldown_secs.saturating_mul(2).max(DEFAULT_COOLDOWN_EXPIRY_SECS));
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

    /// Simulate how each enabled playbook would react to `event` without
    /// executing any actions or recording cooldown / frequency state.
    /// Used by the dry-run endpoint so an admin can preview a rule
    /// change before committing to it.
    ///
    /// Frequency conditions are reported as met-with-note rather than
    /// evaluated, because a real evaluation requires runtime history
    /// the synthetic event doesn't carry. The `has_frequency_condition`
    /// flag on each `DryRunMatch` lets the UI flag that caveat to the
    /// admin so they don't assume a `would_fire=true` playbook will
    /// definitely fire on the next matching real event.
    pub fn dry_run(&self, event: &ThreatDetectedEvent) -> Vec<DryRunMatch> {
        self.playbooks
            .load()
            .iter()
            .map(|pb| simulate_playbook(pb, event))
            .collect()
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

/// Build a `DryRunMatch` for one playbook. Pure — no engine state
/// touched, no logs emitted, no cooldown recording. `would_fire` is
/// true when `trigger_matches` holds and every condition (including
/// the pass-through frequency branch) reports met. Any frequency
/// condition is evaluated as "passes + flagged for admin review" so
/// the preview stays conservative rather than a hard no against a
/// rule that only fails because dry-run has no history to count.
fn simulate_playbook(pb: &Playbook, event: &ThreatDetectedEvent) -> DryRunMatch {
    let trigger_matches = pb.trigger_event == event.attack_type;
    let mut has_frequency_condition = false;
    let conditions: Vec<DryRunConditionResult> = pb
        .conditions
        .iter()
        .map(|c| {
            if c.condition_type == ConditionType::Frequency {
                has_frequency_condition = true;
            }
            simulate_condition(c, event)
        })
        .collect();
    let all_conditions_met = conditions.iter().all(|r| r.met);
    let would_fire = pb.enabled && trigger_matches && all_conditions_met;
    let actions: Vec<DryRunAction> = pb
        .actions
        .iter()
        .map(|a| DryRunAction {
            action_order: a.action_order,
            action_type: a.action_type.clone(),
            params: a.params.clone(),
        })
        .collect();

    DryRunMatch {
        playbook_id: pb.id,
        playbook_name: pb.name.clone(),
        enabled: pb.enabled,
        trigger_event: pb.trigger_event.clone(),
        trigger_matches,
        has_frequency_condition,
        would_fire,
        conditions,
        actions,
    }
}

/// Evaluate one condition against a synthetic event without touching
/// shared state. Every branch mirrors the live `evaluate_single_condition`
/// logic except `Frequency`, which is reported as "passes-with-note"
/// because a real evaluation would both need historical events and
/// record a new one.
fn simulate_condition(cond: &PlaybookCondition, event: &ThreatDetectedEvent) -> DryRunConditionResult {
    let base = |met: bool, note: Option<String>| DryRunConditionResult {
        condition_type: cond.condition_type.to_string(),
        operator: cond.operator.clone(),
        value: cond.value.clone(),
        value2: cond.value2.clone(),
        met,
        note,
    };

    match cond.condition_type {
        ConditionType::Threshold => {
            let threshold = match cond.value.parse::<f64>() {
                Ok(v) => v,
                Err(_) => return base(false, Some(format!("invalid threshold value: {}", cond.value))),
            };
            let confidence = event.confidence as f64;
            let met = if cond.operator == "<=" {
                confidence <= threshold
            } else {
                confidence >= threshold
            };
            base(met, Some(format!("event.confidence={confidence:.3}")))
        }
        ConditionType::SourceCountry => {
            let countries: Vec<&str> = cond.value.split(',').map(|s| s.trim()).collect();
            let matches = event
                .geoip_country
                .as_ref()
                .is_some_and(|c| countries.iter().any(|&cc| cc.eq_ignore_ascii_case(c)));
            let met = if cond.operator == "not_in" { !matches } else { matches };
            base(
                met,
                Some(format!(
                    "event.geoip_country={}",
                    event.geoip_country.as_deref().unwrap_or("none")
                )),
            )
        }
        ConditionType::IpPattern => {
            let net = match cond.value.parse::<ipnetwork::IpNetwork>() {
                Ok(n) => n,
                Err(_) => return base(false, Some(format!("invalid CIDR: {}", cond.value))),
            };
            let ip = match event.source_ip.parse::<IpAddr>() {
                Ok(a) => a,
                Err(_) => return base(false, Some(format!("invalid source_ip: {}", event.source_ip))),
            };
            let matches = net.contains(ip);
            let met = if cond.operator == "not_in" { !matches } else { matches };
            base(met, Some(format!("event.source_ip={}", event.source_ip)))
        }
        ConditionType::RepeatOffender => {
            let expected = cond.value.eq_ignore_ascii_case("true");
            let met = event.is_repeat_offender == expected;
            base(
                met,
                Some(format!("event.is_repeat_offender={}", event.is_repeat_offender)),
            )
        }
        ConditionType::Frequency => base(
            true,
            Some("frequency condition not evaluated in dry-run — requires runtime history".to_string()),
        ),
        ConditionType::MultiSourceMin => {
            let required = match cond.value.parse::<usize>() {
                Ok(v) => v,
                Err(_) => return base(false, Some(format!("invalid required count: {}", cond.value))),
            };
            let met = event.active_source_count >= required;
            base(
                met,
                Some(format!(
                    "event.active_source_count={} required={required}",
                    event.active_source_count
                )),
            )
        }
        ConditionType::SingleSourceHigh => {
            let target_source = match DetectionSource::from_str(&cond.value) {
                Ok(s) => s,
                Err(_) => return base(false, Some(format!("unknown DetectionSource: {}", cond.value))),
            };
            let min_conf = cond
                .value2
                .as_ref()
                .and_then(|s| s.parse::<f32>().ok())
                .unwrap_or(DEFAULT_SINGLE_SOURCE_HIGH_MIN_CONFIDENCE);
            let solo_match =
                event.active_source_count == 1 && event.sources.len() == 1 && event.sources[0] == target_source;
            let conf_met = event.confidence >= min_conf;
            let met = solo_match && conf_met;
            base(
                met,
                Some(format!(
                    "sources={:?} count={} conf={:.3} target={} need_conf>={:.3}",
                    event.sources, event.active_source_count, event.confidence, cond.value, min_conf
                )),
            )
        }
        ConditionType::FusedConfidenceAbove => {
            let threshold = match cond.value.parse::<f32>() {
                Ok(v) => v,
                Err(_) => return base(false, Some(format!("invalid threshold: {}", cond.value))),
            };
            let met = if cond.operator == "<=" {
                event.fused_confidence <= threshold
            } else {
                event.fused_confidence >= threshold
            };
            base(
                met,
                Some(format!("event.fused_confidence={:.3}", event.fused_confidence)),
            )
        }
    }
}

#[cfg(test)]
mod dry_run_tests {
    use super::*;
    use crate::model::soar::playbook::PlaybookAction;

    fn event(attack_type: &str, confidence: f32, sources: Vec<DetectionSource>) -> ThreatDetectedEvent {
        let count = sources.len().max(1);
        ThreatDetectedEvent {
            attack_type: attack_type.to_string(),
            confidence,
            source_ip: "1.2.3.4".to_string(),
            dest_ip: "10.0.0.1".to_string(),
            flow_count: 1,
            packet_rate: 0.0,
            protocol: 6,
            geoip_country: None,
            is_repeat_offender: false,
            sources,
            active_source_count: count,
            fused_confidence: confidence,
            ae_score: 0.0,
            anomaly_score: 0.0,
            c2_score: 0.0,
        }
    }

    fn playbook(name: &str, trigger: &str, conditions: Vec<PlaybookCondition>) -> Playbook {
        Playbook {
            id: 1,
            name: name.to_string(),
            enabled: true,
            trigger_event: trigger.to_string(),
            cooldown_secs: 60,
            actions: vec![PlaybookAction {
                action_order: 1,
                action_type: "block_ip".to_string(),
                params: serde_json::json!({"ttl_secs": 300}),
            }],
            conditions,
        }
    }

    #[test]
    fn simulate_playbook_fires_when_trigger_matches_and_no_conditions() {
        let pb = playbook("trivial", "brute_force", vec![]);
        let ev = event("brute_force", 0.9, vec![DetectionSource::ML]);
        let result = simulate_playbook(&pb, &ev);
        assert!(result.trigger_matches);
        assert!(result.would_fire);
        assert_eq!(result.actions.len(), 1);
        assert_eq!(result.actions[0].action_type, "block_ip");
    }

    #[test]
    fn simulate_playbook_does_not_fire_on_mismatched_trigger() {
        let pb = playbook("brute-match", "brute_force", vec![]);
        let ev = event("c2_beacon", 0.9, vec![DetectionSource::ML]);
        let result = simulate_playbook(&pb, &ev);
        assert!(!result.trigger_matches);
        assert!(!result.would_fire);
    }

    #[test]
    fn simulate_playbook_does_not_fire_when_disabled() {
        let mut pb = playbook("off", "brute_force", vec![]);
        pb.enabled = false;
        let ev = event("brute_force", 0.9, vec![DetectionSource::ML]);
        let result = simulate_playbook(&pb, &ev);
        assert!(result.trigger_matches);
        assert!(!result.enabled);
        assert!(!result.would_fire);
    }

    #[test]
    fn simulate_condition_frequency_passes_with_note() {
        let cond = PlaybookCondition {
            condition_type: ConditionType::Frequency,
            operator: ">=".to_string(),
            value: "5".to_string(),
            value2: Some("60".to_string()),
        };
        let ev = event("brute_force", 0.8, vec![DetectionSource::ML]);
        let result = simulate_condition(&cond, &ev);
        assert!(result.met, "frequency must pass in dry-run");
        assert!(
            result.note.as_deref().unwrap_or("").contains("frequency"),
            "note must explain why frequency wasn't evaluated"
        );
    }

    #[test]
    fn simulate_condition_threshold_respects_operator() {
        let gte = PlaybookCondition {
            condition_type: ConditionType::Threshold,
            operator: ">=".to_string(),
            value: "0.85".to_string(),
            value2: None,
        };
        let lte = PlaybookCondition {
            condition_type: ConditionType::Threshold,
            operator: "<=".to_string(),
            value: "0.85".to_string(),
            value2: None,
        };
        let ev = event("brute_force", 0.9, vec![DetectionSource::ML]);
        assert!(simulate_condition(&gte, &ev).met);
        assert!(!simulate_condition(&lte, &ev).met);
    }

    #[test]
    fn simulate_condition_multi_source_min_counts_sources() {
        let cond = PlaybookCondition {
            condition_type: ConditionType::MultiSourceMin,
            operator: ">=".to_string(),
            value: "2".to_string(),
            value2: None,
        };
        let ev_two = event("c2_beacon", 0.9, vec![DetectionSource::Suricata, DetectionSource::ML]);
        let ev_one = event("c2_beacon", 0.9, vec![DetectionSource::ML]);
        assert!(simulate_condition(&cond, &ev_two).met);
        assert!(!simulate_condition(&cond, &ev_one).met);
    }

    #[test]
    fn simulate_condition_single_source_high_requires_solo_and_confidence() {
        let cond = PlaybookCondition {
            condition_type: ConditionType::SingleSourceHigh,
            operator: ">=".to_string(),
            value: "Suricata".to_string(),
            value2: Some("0.95".to_string()),
        };
        let solo_high = event("c2_beacon", 0.96, vec![DetectionSource::Suricata]);
        let solo_low = event("c2_beacon", 0.90, vec![DetectionSource::Suricata]);
        let multi = event("c2_beacon", 0.96, vec![DetectionSource::Suricata, DetectionSource::ML]);
        let wrong_source = event("c2_beacon", 0.96, vec![DetectionSource::ML]);
        assert!(simulate_condition(&cond, &solo_high).met);
        assert!(!simulate_condition(&cond, &solo_low).met);
        assert!(!simulate_condition(&cond, &multi).met);
        assert!(!simulate_condition(&cond, &wrong_source).met);
    }

    #[test]
    fn simulate_playbook_flags_frequency_condition_presence() {
        let cond = PlaybookCondition {
            condition_type: ConditionType::Frequency,
            operator: ">=".to_string(),
            value: "5".to_string(),
            value2: Some("60".to_string()),
        };
        let pb = playbook("brute_force_block", "brute_force", vec![cond]);
        let ev = event("brute_force", 0.9, vec![DetectionSource::ML]);
        let result = simulate_playbook(&pb, &ev);
        assert!(result.has_frequency_condition);
        assert!(
            result.would_fire,
            "frequency alone must not block would_fire in dry-run"
        );
    }
}
