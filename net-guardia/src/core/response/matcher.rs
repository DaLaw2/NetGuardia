use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use macros::log;

use crate::core::response::frequency::FrequencyTracker;
use crate::domain::common::config::AppConfig;
use crate::domain::common::event::{DetectionSource, ThreatDetectedEvent};
use crate::domain::response::condition::{ConditionType, PlaybookCondition};
use crate::domain::response::dry_run::{DryRunAction, DryRunConditionResult, DryRunMatch};
use crate::domain::response::log::SoarLog;
use crate::domain::response::playbook::Playbook;

pub type CooldownKey = (i64, String);

pub struct PlaybookMatcher {
    pub playbooks: ArcSwap<Vec<Arc<Playbook>>>,
    pub admin_whitelist: ArcSwap<HashSet<String>>,
    pub cooldowns: DashMap<CooldownKey, Instant>,
    pub frequency_tracker: FrequencyTracker,
    pub active_block_count: AtomicU32,
    pub config: Arc<ArcSwap<AppConfig>>,
}

impl PlaybookMatcher {
    pub fn new(
        config: Arc<ArcSwap<AppConfig>>,
        frequency_max_tracked_keys: usize,
        frequency_max_events_per_key: usize,
        frequency_retention_secs: u64,
    ) -> Self {
        Self {
            playbooks: ArcSwap::from_pointee(Vec::new()),
            admin_whitelist: ArcSwap::from_pointee(HashSet::new()),
            cooldowns: DashMap::new(),
            frequency_tracker: FrequencyTracker::new(
                frequency_max_tracked_keys,
                frequency_max_events_per_key,
                frequency_retention_secs,
            ),
            active_block_count: AtomicU32::new(0),
            config,
        }
    }

    pub fn find_matching_playbooks(&self, event: &ThreatDetectedEvent) -> Vec<Arc<Playbook>> {
        self.playbooks
            .load()
            .iter()
            .filter(|pb| pb.matches_trigger(event))
            .filter(|pb| self.evaluate_conditions(pb, event))
            .cloned()
            .collect()
    }

    pub fn evaluate_conditions(&self, pb: &Playbook, event: &ThreatDetectedEvent) -> bool {
        if pb.conditions.is_empty() {
            return true;
        }

        for cond in &pb.conditions {
            if cond.condition_type == ConditionType::Frequency {
                continue;
            }
            if !self.evaluate_single_condition(cond, pb, event) {
                return false;
            }
        }

        for cond in &pb.conditions {
            if cond.condition_type == ConditionType::Frequency && !self.evaluate_single_condition(cond, pb, event) {
                return false;
            }
        }

        true
    }

    fn evaluate_single_condition(&self, cond: &PlaybookCondition, pb: &Playbook, event: &ThreatDetectedEvent) -> bool {
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
                    .unwrap_or_else(|| self.config.load().soar.default_frequency_window_secs);
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
                let target_source = match DetectionSource::from_str(&cond.value) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                let min_conf = cond
                    .value2
                    .as_ref()
                    .and_then(|s| s.parse::<f32>().ok())
                    .unwrap_or_else(|| self.config.load().soar.default_single_source_high_min_confidence);
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

    pub fn is_cooldown_active(&self, playbook_id: i64, source_ip: &str, cooldown_secs: i64) -> bool {
        let key = (playbook_id, source_ip.to_string());
        if let Some(last_exec) = self.cooldowns.get(&key) {
            let elapsed = last_exec.elapsed();
            if elapsed.as_secs() < cooldown_secs.max(0) as u64 {
                return true;
            }
        }
        false
    }

    pub fn record_cooldown(&self, playbook_id: i64, source_ip: &str) {
        let key = (playbook_id, source_ip.to_string());
        self.cooldowns.insert(key, Instant::now());
    }

    pub fn cleanup_expired_cooldowns(&self) {
        let default_cooldown_expiry = self.config.load().soar.default_cooldown_expiry_secs;
        let max_cooldown_secs = self
            .playbooks
            .load()
            .iter()
            .map(|p| p.cooldown_secs.max(0) as u64)
            .max()
            .unwrap_or(default_cooldown_expiry);
        let expiry = Duration::from_secs(max_cooldown_secs.saturating_mul(2).max(default_cooldown_expiry));
        let before = self.cooldowns.len();
        self.cooldowns.retain(|_, instant| instant.elapsed() < expiry);
        let removed = before.saturating_sub(self.cooldowns.len());
        if removed > 0 {
            log!(SoarLog::CooldownCleanup(removed as u32));
        }

        let freq_removed = self.frequency_tracker.cleanup();
        if freq_removed > 0 {
            log!(SoarLog::FrequencyCleanup(freq_removed));
        }
    }

    pub fn decrement_block_count(&self) {
        loop {
            let current = self.active_block_count.load(Ordering::SeqCst);
            if current == 0 {
                return;
            }
            match self
                .active_block_count
                .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return,
                Err(_) => continue,
            }
        }
    }

    pub fn dry_run(&self, event: &ThreatDetectedEvent) -> Vec<DryRunMatch> {
        let default_min_conf = self.config.load().soar.default_single_source_high_min_confidence;
        self.playbooks
            .load()
            .iter()
            .map(|pb| simulate_playbook(pb, event, default_min_conf))
            .collect()
    }
}

fn simulate_playbook(pb: &Playbook, event: &ThreatDetectedEvent, default_single_source_min_conf: f32) -> DryRunMatch {
    let trigger_matches = pb.trigger_event == event.attack_type;
    let mut has_frequency_condition = false;
    let conditions: Vec<DryRunConditionResult> = pb
        .conditions
        .iter()
        .map(|c| {
            if c.condition_type == ConditionType::Frequency {
                has_frequency_condition = true;
            }
            simulate_condition(c, event, default_single_source_min_conf)
        })
        .collect();
    let all_conditions_met = conditions.iter().all(|r| r.met);
    let would_fire = pb.matches_trigger(event) && all_conditions_met;
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

fn simulate_condition(
    cond: &PlaybookCondition,
    event: &ThreatDetectedEvent,
    default_single_source_min_conf: f32,
) -> DryRunConditionResult {
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
                .unwrap_or(default_single_source_min_conf);
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
    use crate::domain::response::playbook::PlaybookAction;

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
        let result = simulate_playbook(&pb, &ev, 0.95);
        assert!(result.trigger_matches);
        assert!(result.would_fire);
        assert_eq!(result.actions.len(), 1);
        assert_eq!(result.actions[0].action_type, "block_ip");
    }

    #[test]
    fn simulate_playbook_does_not_fire_on_mismatched_trigger() {
        let pb = playbook("brute-match", "brute_force", vec![]);
        let ev = event("c2_beacon", 0.9, vec![DetectionSource::ML]);
        let result = simulate_playbook(&pb, &ev, 0.95);
        assert!(!result.trigger_matches);
        assert!(!result.would_fire);
    }

    #[test]
    fn simulate_playbook_does_not_fire_when_disabled() {
        let mut pb = playbook("off", "brute_force", vec![]);
        pb.enabled = false;
        let ev = event("brute_force", 0.9, vec![DetectionSource::ML]);
        let result = simulate_playbook(&pb, &ev, 0.95);
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
        let result = simulate_condition(&cond, &ev, 0.95);
        assert!(result.met);
        assert!(result.note.as_deref().unwrap_or("").contains("frequency"));
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
        assert!(simulate_condition(&gte, &ev, 0.95).met);
        assert!(!simulate_condition(&lte, &ev, 0.95).met);
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
        assert!(simulate_condition(&cond, &ev_two, 0.95).met);
        assert!(!simulate_condition(&cond, &ev_one, 0.95).met);
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
        assert!(simulate_condition(&cond, &solo_high, 0.95).met);
        assert!(!simulate_condition(&cond, &solo_low, 0.95).met);
        assert!(!simulate_condition(&cond, &multi, 0.95).met);
        assert!(!simulate_condition(&cond, &wrong_source, 0.95).met);
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
        let result = simulate_playbook(&pb, &ev, 0.95);
        assert!(result.has_frequency_condition);
        assert!(result.would_fire);
    }
}
