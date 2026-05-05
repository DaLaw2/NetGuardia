use std::num::NonZero;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use lru::LruCache;
use macros::log;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::core::detection::metrics::FusionMetrics;
use crate::domain::common::config::AppConfig;
use crate::domain::common::config::constants::{FUSION_AUDIT_ACTION, FUSION_AUDIT_ACTOR};
use crate::domain::common::event::{AuditEvent, DetectionEvent, DetectionSource, ThreatDetectedEvent};
use crate::domain::detection::attack_type::translate;
use crate::domain::detection::fusion_math::{FusionWindowLengths, fused_confidence};
use crate::domain::detection::log::DetectionLog;
use crate::domain::detection::ml_detection::AlertMessage;
use crate::interface::geo_lookup::GeoLookup;

/// Per-source record within an in-flight dedup entry. Keeps the strongest
/// confidence per source so multi-hit from one source doesn't inflate the
/// fused policy. `local_attack_type` is the raw source-specific label seen
/// before canonicalization — preserved for WORM audit evidence so the
/// explain-this-block UI can show Suricata's classtype next to ML's class
/// name that both folded into the same canonical dedup key.
#[derive(Debug, Clone)]
struct SourceSample {
    source: DetectionSource,
    confidence: f32,
    local_attack_type: String,
}

struct DedupEntry {
    sources: Vec<SourceSample>,
    /// When the orchestrator first emitted for this key.
    first_emitted_at: Instant,
    /// Most recent emit (reset on each fused re-emit within the fusion window).
    emitted_at: Instant,
    /// Fusion window length for this key, fixed by the first source to arrive.
    /// Later arrivals don't reset it so the lookahead budget stays predictable.
    fusion_window: Duration,
}

/// Coordinates detections from ML / Suricata / Beaconing / Correlation.
/// Incoming events are canonicalized into a shared attack-type dictionary so
/// dedup keys collide across sources; events sharing a key inside the fusion
/// window accumulate, and additional sources arriving mid-window trigger a
/// re-emit with the combined confidence `1 − ∏(1 − c_i)`.
pub struct DetectionOrchestrator {
    rx: mpsc::Receiver<DetectionEvent>,
    threat_tx: broadcast::Sender<ThreatDetectedEvent>,
    audit_tx: broadcast::Sender<AuditEvent>,
    geoip: Option<Arc<dyn GeoLookup>>,
    metrics: Arc<FusionMetrics>,
    // Enrichment state
    src_ip_counts: LruCache<String, u32>,
    repeat_tracker: LruCache<String, Instant>,
    // Dedup state — LRU-bounded to prevent unbounded growth under sustained attack.
    dedup: lru::LruCache<(String, String), DedupEntry>,
    dedup_window: Duration,
    repeat_offender_window: Duration,
    cleanup_interval_secs: u64,
    /// Per-source fusion window lengths. Future versions may read overrides
    /// from DB; the defaults live in `FusionWindowLengths::default`.
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

    pub fn start(self) {
        tokio::spawn(async move { self.run().await });
    }

    async fn run(mut self) {
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
        // Count every ingress event per-source before dedup — this is the
        // raw firing rate, independent of whether the event survives to emit.
        self.metrics.record_fire(event.source);

        // Canonicalize the raw attack_type so Suricata's "brute-force"
        // classtype and ML's "Brute Force" class name land on the same dedup
        // key — the precondition for cross-source fusion. Keep the original
        // label for audit evidence.
        let raw_label = event.attack_type.clone();
        let canonical = translate(event.source, &event.attack_type);
        event.attack_type = canonical.as_str().to_string();

        let key = (event.source_ip.clone(), event.attack_type.clone());
        let now = Instant::now();

        // Path A: existing dedup entry. Decide re-emit (fusion window still
        // open) vs silence (window closed but dedup still active).
        if let Some(entry) = self.dedup.get_mut(&key) {
            let since_first = now.saturating_duration_since(entry.first_emitted_at);

            // Post-dedup-window — treat as a brand-new event (fall through).
            if since_first >= self.dedup_window {
                // Expired dedup; fall through to Path B by dropping the entry.
                self.dedup.pop(&key);
            } else if since_first < entry.fusion_window {
                // Still inside the fusion window — accumulate.
                let is_new_source = !entry.sources.iter().any(|s| s.source == event.source);
                if is_new_source {
                    entry.sources.push(SourceSample {
                        source: event.source,
                        confidence: event.confidence,
                        local_attack_type: raw_label.clone(),
                    });
                    entry.emitted_at = now;
                } else {
                    // Same source firing again inside the window — keep the
                    // strongest confidence (and its raw label) for fusion math.
                    if let Some(existing) = entry.sources.iter_mut().find(|s| s.source == event.source)
                        && existing.confidence < event.confidence
                    {
                        existing.confidence = event.confidence;
                        existing.local_attack_type = raw_label.clone();
                    }
                }

                // Only RE-EMIT when a new source joined — same-source
                // refires are silenced to avoid SOAR cooldown churn.
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
                // Past fusion window, still inside dedup silence → drop.
                log!(DetectionLog::DetectionDeduplicated(
                    event.source_ip.clone(),
                    event.attack_type.clone(),
                ));
                return;
            }
        }

        // Path B: brand-new key (or expired dedup). Emit single-source,
        // open a fusion window sized by this source.
        let fusion_window = Duration::from_secs(self.fusion_windows.for_source(event.source));

        // Detect LRU-pressure eviction: if the dedup map is already at capacity
        // and this key wasn't present, inserting will evict the least-recently-
        // used entry silently. That's a real lost-signal event; count it and
        // warn so the operator sees sustained-attack saturation.
        let cap = self.dedup.cap().get();
        let was_full = self.dedup.len() >= cap;
        let key_was_absent = self.dedup.peek(&key).is_none();
        if was_full && key_was_absent {
            self.metrics.record_eviction();
            log!(DetectionLog::FusionWindowEvicted(key.0.clone(), key.1.clone()));
        }

        self.dedup.put(
            key.clone(),
            DedupEntry {
                sources: vec![SourceSample {
                    source: event.source,
                    confidence: event.confidence,
                    local_attack_type: raw_label,
                }],
                first_emitted_at: now,
                emitted_at: now,
                fusion_window,
            },
        );
        self.emit_fused(&event, &key).await;
    }

    /// Build the fused ThreatDetectedEvent from the current dedup entry's
    /// per-source samples, apply enrichment (hit count / repeat / geoip),
    /// and publish. Called both on first emit (single source) and on
    /// within-window re-emit (2..=4 sources). Also emits a WORM AuditEvent
    /// carrying the full per-source evidence chain.
    async fn emit_fused(&mut self, trigger_event: &DetectionEvent, key: &(String, String)) {
        let per_source_samples: Vec<SourceSample> = match self.dedup.get(key) {
            Some(entry) => entry.sources.clone(),
            None => return,
        };
        let confs: Vec<f32> = per_source_samples.iter().map(|s| s.confidence).collect();
        let sources_vec: Vec<DetectionSource> = per_source_samples.iter().map(|s| s.source).collect();
        let fused = fused_confidence(&confs);

        let mut threat_event = self.enrich(trigger_event).await;
        threat_event.sources = sources_vec;
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

        let _ = self.threat_tx.send(threat_event);
    }

    /// Emit a WORM AuditEvent so the eventual "why was this IP blocked?"
    /// explain view can reconstruct the fusion evidence chain — which
    /// sources fired, at what confidence, and what raw label each used
    /// before the canonical dictionary folded them onto a shared key.
    async fn publish_fusion_audit(&self, trigger_event: &DetectionEvent, fused: f32, per_source: &[SourceSample]) {
        let audit = AuditEvent {
            actor: FUSION_AUDIT_ACTOR.to_string(),
            action: FUSION_AUDIT_ACTION.to_string(),
            detail: build_fusion_audit_detail(&trigger_event.source_ip, &trigger_event.attack_type, fused, per_source),
        };

        let _ = self.audit_tx.send(audit);
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
            // These three get overwritten in `emit_fused` with the
            // accumulated values; initialize to the single-source defaults
            // so a direct caller also gets a consistent shape.
            sources: vec![event.source],
            active_source_count: 1,
            fused_confidence: event.confidence,
            ae_score: event.ae_score,
            anomaly_score: event.anomaly_score,
            c2_score: event.c2_score,
        }
    }

    fn cleanup_expired(&mut self) {
        // Full scan: LRU order reflects access time, not insertion time, so
        // peek_lru + break-on-first-unexpired would skip older idle entries
        // sitting in the middle of the map. Dedup touches an entry's LRU
        // position via `get_mut` on every re-emit, which can leave an entry
        // with an older `first_emitted_at` deeper in the cache than a newly
        // inserted neighbour. A full retain is O(N) but cleanup runs every
        // 60s and `MAX_DEDUP_ENTRIES` caps N at 50_000 — one walk is cheap.
        let now = Instant::now();
        let window = self.dedup_window;
        let mut expired: Vec<(String, String)> = Vec::new();
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
    NonZero::new(value.max(1)).unwrap_or(NonZero::<usize>::MIN)
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
                if tx.send(event).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                log!(DetectionLog::MlBridgeLagged(n));
            }
            Err(broadcast::error::RecvError::Closed) => {
                log!(DetectionLog::MlAlertChannelClosed);
                break;
            }
        }
    }
}

/// Serialize the WORM audit evidence payload for a fused threat emission.
/// Extracted as a free function so tests can cover schema shape without a
/// live broadcast harness.
fn build_fusion_audit_detail(src_ip: &str, attack_type: &str, fused: f32, per_source: &[SourceSample]) -> String {
    let per_source_json: Vec<serde_json::Value> = per_source
        .iter()
        .map(|s| {
            serde_json::json!({
                "source": s.source.to_string(),
                "confidence": s.confidence,
                "local_attack_type": s.local_attack_type,
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
    //! Orchestrator unit tests. The fusion math lives in `fusion_math::tests`,
    //! canonical translation in `model::detection::attack_type::tests`, and
    //! the audit evidence schema is covered below.

    use super::*;

    fn sample(source: DetectionSource, confidence: f32, local: &str) -> SourceSample {
        SourceSample {
            source,
            confidence,
            local_attack_type: local.to_string(),
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
        // Defensive: should never happen in production (emit_fused requires a
        // dedup entry), but the helper must not panic on an empty slice.
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
    fn audit_constants_are_stable_wire_strings() {
        // Downstream audit tooling filters on these exact strings — renaming
        // is a breaking change to the WORM chain.
        assert_eq!(FUSION_AUDIT_ACTOR, "FusionEngine");
        assert_eq!(FUSION_AUDIT_ACTION, "fused_threat_emitted");
    }
}
