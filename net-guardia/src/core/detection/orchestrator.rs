use std::num::NonZero;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use lru::LruCache;
use macros::log;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::common::log::audit::AuditLog;
use crate::core::detection::metrics::FusionMetrics;
use crate::domain::common::config::AppConfig;
use crate::domain::common::config::constants::{FUSION_AUDIT_ACTION, FUSION_AUDIT_ACTOR};
use crate::domain::common::event::{
    AuditEvent, DetectionDiagnostic, DetectionEvent, DetectionSource, ThreatDetectedEvent,
};
use crate::domain::detection::attack_type::{CanonicalAttackType, translate};
use crate::domain::detection::flow_observation::FlowObservation;
use crate::domain::detection::fusion_math::{FusionWindowLengths, fused_confidence};
use crate::domain::detection::log::DetectionLog;
use crate::domain::detection::ml_detection::AlertMessage;
use crate::interface::detection::geo_lookup::GeoLookup;

#[derive(Debug, Clone)]
struct SourceSample {
    source: DetectionSource,
    confidence: f32,
    local_attack_type: String,
    diagnostics: Vec<DetectionDiagnostic>,
}

struct DedupEntry {
    sources: Vec<SourceSample>,
    first_emitted_at: Instant,
    emitted_at: Instant,
    fusion_window: Duration,
}

pub struct DetectionOrchestrator {
    rx: mpsc::Receiver<DetectionEvent>,
    threat_tx: broadcast::Sender<ThreatDetectedEvent>,
    audit_tx: broadcast::Sender<AuditEvent>,
    geoip: Option<Arc<dyn GeoLookup>>,
    metrics: Arc<FusionMetrics>,
    src_ip_counts: LruCache<String, u32>,
    repeat_tracker: LruCache<String, Instant>,
    dedup: LruCache<(String, CanonicalAttackType), DedupEntry>,
    dedup_window: Duration,
    repeat_offender_window: Duration,
    cleanup_interval_secs: u64,
    fusion_windows: FusionWindowLengths,
}

impl DetectionOrchestrator {
    pub fn new(
        app_config: &Arc<ArcSwap<AppConfig>>,
        rx: mpsc::Receiver<DetectionEvent>,
        threat_tx: broadcast::Sender<ThreatDetectedEvent>,
        audit_tx: broadcast::Sender<AuditEvent>,
        geoip: Option<Arc<dyn GeoLookup>>,
        metrics: Arc<FusionMetrics>,
    ) -> Self {
        let cfg = app_config.load();
        let fusion = &cfg.detection.fusion;
        let source_count_max_entries = nonzero_cache_size(fusion.source_count_max_entries);
        let repeat_tracker_max_entries = nonzero_cache_size(fusion.repeat_tracker_max_entries);
        let max_dedup = nonzero_cache_size(fusion.max_dedup_entries);
        Self {
            rx,
            threat_tx,
            audit_tx,
            geoip,
            metrics,
            src_ip_counts: LruCache::new(source_count_max_entries),
            repeat_tracker: LruCache::new(repeat_tracker_max_entries),
            dedup: LruCache::new(max_dedup),
            dedup_window: Duration::from_secs(fusion.dedup_window_secs),
            repeat_offender_window: Duration::from_secs(fusion.repeat_offender_window_secs),
            cleanup_interval_secs: cfg.detection.cleanup_interval_secs,
            fusion_windows: FusionWindowLengths::default(),
        }
    }

    pub async fn run(mut self) {
        log!(DetectionLog::OrchestratorStarted);

        let mut cleanup_interval = interval(Duration::from_secs(self.cleanup_interval_secs));

        loop {
            tokio::select! {
                event = self.rx.recv() => {
                    match event {
                        Some(detection) => self.handle_detection(detection).await,
                        None => break,
                    }
                }
                _ = cleanup_interval.tick() => {
                    self.cleanup_expired();
                }
            }
        }
    }

    async fn handle_detection(&mut self, mut event: DetectionEvent) {
        self.metrics.record_fire(event.source);

        let raw_label = event.attack_type.clone();
        let canonical = translate(event.source, &event.attack_type);
        event.attack_type = canonical.as_str().to_string();

        let key = (event.source_ip.clone(), canonical);
        let now = Instant::now();

        if let Some(entry) = self.dedup.get_mut(&key) {
            let since_first = now.saturating_duration_since(entry.first_emitted_at);

            if since_first >= self.dedup_window {
                self.dedup.pop(&key);
            } else if since_first < entry.fusion_window {
                let is_new_source = !entry.sources.iter().any(|s| s.source == event.source);
                if is_new_source {
                    entry.sources.push(SourceSample {
                        source: event.source,
                        confidence: event.confidence,
                        local_attack_type: raw_label.clone(),
                        diagnostics: diagnostics_for_event(&event),
                    });
                    entry.emitted_at = now;
                } else {
                    if let Some(existing) = entry.sources.iter_mut().find(|s| s.source == event.source)
                        && existing.confidence < event.confidence
                    {
                        existing.confidence = event.confidence;
                        existing.local_attack_type = raw_label.clone();
                        existing.diagnostics = diagnostics_for_event(&event);
                    }
                }

                if is_new_source {
                    self.emit_fused(&event, &key).await;
                } else {
                    log!(DetectionLog::DetectionDeduplicated(
                        event.source_ip.clone(),
                        event.attack_type.clone(),
                    ));
                }
                return;
            } else {
                log!(DetectionLog::DetectionDeduplicated(
                    event.source_ip.clone(),
                    event.attack_type.clone(),
                ));
                return;
            }
        }

        let fusion_window = Duration::from_secs(self.fusion_windows.for_source(event.source));

        let cap = self.dedup.cap().get();
        let was_full = self.dedup.len() >= cap;
        let key_was_absent = self.dedup.peek(&key).is_none();
        if was_full && key_was_absent {
            self.metrics.record_eviction();
            log!(DetectionLog::FusionWindowEvicted(
                key.0.clone(),
                key.1.as_str().to_string()
            ));
        }

        self.dedup.put(
            key.clone(),
            DedupEntry {
                sources: vec![SourceSample {
                    source: event.source,
                    confidence: event.confidence,
                    local_attack_type: raw_label,
                    diagnostics: diagnostics_for_event(&event),
                }],
                first_emitted_at: now,
                emitted_at: now,
                fusion_window,
            },
        );
        self.emit_fused(&event, &key).await;
    }

    async fn emit_fused(&mut self, trigger_event: &DetectionEvent, key: &(String, CanonicalAttackType)) {
        let per_source_samples: Vec<SourceSample> = match self.dedup.get(key) {
            Some(entry) => entry.sources.clone(),
            None => return,
        };
        let confs: Vec<f32> = per_source_samples.iter().map(|s| s.confidence).collect();
        let sources_vec: Vec<DetectionSource> = per_source_samples.iter().map(|s| s.source).collect();
        let fused = fused_confidence(&confs);

        let mut threat_event = self.enrich(trigger_event).await;
        threat_event.sources = sources_vec;
        threat_event.diagnostics = per_source_samples
            .iter()
            .flat_map(|sample| sample.diagnostics.clone())
            .collect();
        threat_event.active_source_count = threat_event.sources.len();
        threat_event.fused_confidence = fused;
        threat_event.confidence = fused;

        log!(DetectionLog::DetectionEmitted(
            trigger_event.source_ip.clone(),
            trigger_event.attack_type.clone(),
            threat_event.confidence,
            trigger_event.ae_score,
            trigger_event.anomaly_score,
            trigger_event.c2_score,
            threat_event.active_source_count,
        ));

        self.metrics.record_emit(threat_event.active_source_count);

        self.publish_fusion_audit(trigger_event, fused, &per_source_samples)
            .await;

        if let Err(err) = self.threat_tx.send(threat_event) {
            let event = err.0;
            log!(DetectionLog::ThreatPublishFailed(
                event.source_ip,
                event.attack_type,
                event.confidence,
            ));
        }
    }

    async fn publish_fusion_audit(&self, trigger_event: &DetectionEvent, fused: f32, per_source: &[SourceSample]) {
        let audit = AuditEvent {
            actor: FUSION_AUDIT_ACTOR.to_string(),
            action: FUSION_AUDIT_ACTION.to_string(),
            detail: build_fusion_audit_detail(&trigger_event.source_ip, &trigger_event.attack_type, fused, per_source),
        };

        if let Err(err) = self.audit_tx.send(audit) {
            let event = err.0;
            log!(AuditLog::AuditPublishFailed(
                "no active audit receivers",
                event.actor,
                event.action
            ));
        }
    }

    async fn enrich(&mut self, event: &DetectionEvent) -> ThreatDetectedEvent {
        let src_ip = &event.source_ip;

        let packet_rate = if event.flow_duration_us > 0 {
            event.packet_count as f64 / (event.flow_duration_us as f64 / 1_000_000.0)
        } else {
            0.0
        };

        let hit_count = match self.src_ip_counts.get_mut(src_ip) {
            Some(c) => {
                *c = c.saturating_add(1);
                *c
            }
            None => {
                self.src_ip_counts.put(src_ip.clone(), 1);
                1
            }
        };

        let now = Instant::now();
        let is_repeat = self.repeat_tracker.get(src_ip).is_some_and(|last| {
            now.checked_duration_since(*last).unwrap_or(Duration::ZERO) < self.repeat_offender_window
        });
        self.repeat_tracker.put(src_ip.clone(), now);

        let geoip_country = if let Some(ref svc) = self.geoip {
            if let Ok(ip) = src_ip.parse() {
                svc.lookup(ip).await.and_then(|loc| loc.country_code)
            } else {
                None
            }
        } else {
            None
        };

        ThreatDetectedEvent {
            attack_type: event.attack_type.clone(),
            confidence: event.confidence,
            source_ip: event.source_ip.clone(),
            dest_ip: event.dest_ip.clone(),
            flow_count: hit_count,
            packet_rate,
            protocol: event.protocol,
            geoip_country,
            is_repeat_offender: is_repeat,
            sources: vec![event.source],
            active_source_count: 1,
            fused_confidence: event.confidence,
            diagnostics: diagnostics_for_event(event),
        }
    }

    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let window = self.dedup_window;
        let mut expired: Vec<(String, CanonicalAttackType)> = Vec::new();
        for (key, entry) in self.dedup.iter() {
            if now
                .checked_duration_since(entry.first_emitted_at)
                .unwrap_or(Duration::ZERO)
                >= window
            {
                expired.push(key.clone());
            }
        }
        for key in expired {
            self.dedup.pop(&key);
        }
    }
}

fn nonzero_cache_size(value: usize) -> NonZero<usize> {
    match NonZero::new(value) {
        Some(value) => value,
        None => NonZero::<usize>::MIN,
    }
}

fn diagnostics_for_event(event: &DetectionEvent) -> Vec<DetectionDiagnostic> {
    if event.source != DetectionSource::ML {
        return Vec::new();
    }

    vec![
        DetectionDiagnostic {
            source: event.source,
            name: "ae_score".to_string(),
            value: event.ae_score,
        },
        DetectionDiagnostic {
            source: event.source,
            name: "anomaly_score".to_string(),
            value: event.anomaly_score,
        },
        DetectionDiagnostic {
            source: event.source,
            name: "c2_score".to_string(),
            value: event.c2_score,
        },
    ]
}

pub async fn bridge_ml_to_detection(mut rx: broadcast::Receiver<AlertMessage>, tx: mpsc::Sender<DetectionEvent>) {
    log!(DetectionLog::MlBridgeStarted);

    loop {
        match rx.recv().await {
            Ok(alert) => {
                let raw_type = alert.attack_type.as_deref().unwrap_or("unknown");

                if raw_type.eq_ignore_ascii_case("normal") {
                    continue;
                }

                let event = DetectionEvent {
                    source: DetectionSource::ML,
                    attack_type: raw_type.to_string(),
                    confidence: alert.confidence,
                    source_ip: alert.src_ip,
                    dest_ip: alert.dst_ip,
                    protocol: alert.protocol,
                    packet_count: alert.packet_count,
                    flow_duration_us: alert.flow_duration_us,
                    ae_score: alert.ae_score,
                    anomaly_score: alert.anomaly_score,
                    c2_score: alert.c2_score,
                };
                if !super::send_detection_or_log(&tx, event) && tx.is_closed() {
                    break;
                }
            }
            Err(RecvError::Lagged(n)) => {
                log!(DetectionLog::MlBridgeLagged(n));
            }
            Err(RecvError::Closed) => {
                log!(DetectionLog::MlAlertChannelClosed);
                break;
            }
        }
    }
}

pub async fn bridge_ml_to_flow_observation(
    mut rx: broadcast::Receiver<AlertMessage>,
    tx: broadcast::Sender<FlowObservation>,
) {
    loop {
        match rx.recv().await {
            Ok(alert) => {
                let observation = FlowObservation {
                    src_ip: alert.src_ip,
                    dst_ip: alert.dst_ip,
                    dst_port: alert.dst_port,
                    protocol: alert.protocol,
                    packet_count: alert.packet_count,
                    flow_duration_us: alert.flow_duration_us,
                };
                let _ = tx.send(observation);
            }
            Err(RecvError::Lagged(n)) => {
                log!(DetectionLog::MlBridgeLagged(n));
            }
            Err(RecvError::Closed) => {
                log!(DetectionLog::MlAlertChannelClosed);
                break;
            }
        }
    }
}

fn build_fusion_audit_detail(src_ip: &str, attack_type: &str, fused: f32, per_source: &[SourceSample]) -> String {
    let per_source_json: Vec<serde_json::Value> = per_source
        .iter()
        .map(|s| {
            serde_json::json!({
                "source": s.source.to_string(),
                "confidence": s.confidence,
                "local_attack_type": s.local_attack_type,
                "diagnostics": &s.diagnostics,
            })
        })
        .collect();
    serde_json::json!({
        "src_ip": src_ip,
        "attack_type": attack_type,
        "fused_confidence": fused,
        "per_source": per_source_json,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(source: DetectionSource, confidence: f32, local: &str) -> SourceSample {
        SourceSample {
            source,
            confidence,
            local_attack_type: local.to_string(),
            diagnostics: Vec::new(),
        }
    }

    fn detection_event() -> DetectionEvent {
        DetectionEvent {
            source: DetectionSource::ML,
            attack_type: "c2_beacon".to_string(),
            confidence: 0.9,
            source_ip: "192.0.2.10".to_string(),
            dest_ip: "198.51.100.20".to_string(),
            protocol: 6,
            packet_count: 10,
            flow_duration_us: 1_000,
            ae_score: 0.1,
            anomaly_score: 0.2,
            c2_score: 0.9,
        }
    }

    #[test]
    fn audit_detail_is_valid_json_with_required_top_level_keys() {
        let detail = build_fusion_audit_detail(
            "1.2.3.4",
            "brute_force",
            0.97,
            &[sample(DetectionSource::Suricata, 0.8, "brute-force")],
        );
        let v: serde_json::Value = serde_json::from_str(&detail).expect("audit detail must be valid JSON");
        assert_eq!(v["src_ip"], "1.2.3.4");
        assert_eq!(v["attack_type"], "brute_force");
        assert!((v["fused_confidence"].as_f64().unwrap() - 0.97).abs() < 1e-5);
        assert!(v["per_source"].is_array());
    }

    #[test]
    fn audit_detail_empty_per_source_array_is_well_formed() {
        let detail = build_fusion_audit_detail("10.0.0.1", "unknown", 0.0, &[]);
        let v: serde_json::Value = serde_json::from_str(&detail).unwrap();
        assert_eq!(v["per_source"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn audit_detail_preserves_per_source_evidence_fields() {
        let per_source = [
            sample(DetectionSource::Suricata, 0.8, "brute-force"),
            sample(DetectionSource::ML, 0.85, "Brute Force"),
        ];
        let detail = build_fusion_audit_detail("1.2.3.4", "brute_force", 0.97, &per_source);
        let v: serde_json::Value = serde_json::from_str(&detail).unwrap();
        let arr = v["per_source"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["source"], "Suricata");
        assert_eq!(arr[0]["local_attack_type"], "brute-force");
        assert!((arr[0]["confidence"].as_f64().unwrap() - 0.8).abs() < 1e-5);
        assert_eq!(arr[1]["source"], "ML");
        assert_eq!(arr[1]["local_attack_type"], "Brute Force");
    }

    #[test]
    fn audit_detail_preserves_per_source_diagnostics() {
        let per_source = [SourceSample {
            source: DetectionSource::ML,
            confidence: 0.85,
            local_attack_type: "C2".to_string(),
            diagnostics: vec![DetectionDiagnostic {
                source: DetectionSource::ML,
                name: "c2_score".to_string(),
                value: 0.91,
            }],
        }];

        let detail = build_fusion_audit_detail("1.2.3.4", "c2", 0.85, &per_source);
        let v: serde_json::Value = serde_json::from_str(&detail).unwrap();
        let diagnostics = v["per_source"][0]["diagnostics"].as_array().unwrap();

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0]["source"], "ML");
        assert_eq!(diagnostics[0]["name"], "c2_score");
        assert!((diagnostics[0]["value"].as_f64().unwrap() - 0.91).abs() < 1e-5);
    }

    #[test]
    fn audit_constants_are_stable_wire_strings() {
        assert_eq!(FUSION_AUDIT_ACTOR, "FusionEngine");
        assert_eq!(FUSION_AUDIT_ACTION, "fused_threat_emitted");
    }

    #[test]
    fn send_detection_or_log_reports_full_channel_drop() {
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(detection_event()).expect("fill channel");

        assert!(!super::super::send_detection_or_log(&tx, detection_event()));
    }

    #[test]
    fn send_detection_or_log_reports_closed_channel_drop() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);

        assert!(!super::super::send_detection_or_log(&tx, detection_event()));
    }
}
