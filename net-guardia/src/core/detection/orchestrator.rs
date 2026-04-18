use std::num::NonZero;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;
use macros::log;
use tokio::sync::mpsc;
use tokio::time::interval;

use super::fusion_math::{FusionWindowLengths, fused_confidence};
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::infrastructure::geoip::GeoIpService;
use crate::model::detection::attack_type::translate;
use crate::model::error::system::SystemError;
use crate::model::event::{DetectionEvent, DetectionSource, ThreatDetectedEvent};
use crate::model::log::detection::DetectionLog;

/// Dedup window: detections for the same `(source_ip, canonical_attack_type)`
/// within this window are suppressed after initial fusion-window expiry.
const DEDUP_WINDOW_SECS: u64 = 30;

/// How often to sweep expired dedup entries.
const CLEANUP_INTERVAL_SECS: u64 = 60;

/// Repeat offender detection: same IP within this duration counts as repeat.
const REPEAT_OFFENDER_WINDOW_SECS: u64 = 2 * 60 * 60;

/// Maximum dedup entries to prevent unbounded memory growth under sustained attack.
const MAX_DEDUP_ENTRIES: usize = 50_000;

/// Per-source record within an in-flight dedup entry. Keeps the strongest
/// confidence per source so multi-hit from one source doesn't inflate the
/// fused policy.
#[derive(Debug, Clone)]
struct SourceSample {
    source: DetectionSource,
    confidence: f32,
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
    comm: Arc<CommunicationManager>,
    geoip: Option<Arc<GeoIpService>>,
    // Enrichment state
    src_ip_counts: lru::LruCache<String, u32>,
    repeat_tracker: lru::LruCache<String, Instant>,
    // Dedup state — LRU-bounded to prevent unbounded growth under sustained attack.
    dedup: lru::LruCache<(String, String), DedupEntry>,
    dedup_window: Duration,
    /// Per-source fusion window lengths. Future versions may read overrides
    /// from DB; the defaults live in `FusionWindowLengths::default`.
    fusion_windows: FusionWindowLengths,
}

impl DetectionOrchestrator {
    pub fn new(
        rx: mpsc::Receiver<DetectionEvent>,
        comm: Arc<CommunicationManager>,
        geoip: Option<Arc<GeoIpService>>,
    ) -> Self {
        Self {
            rx,
            comm,
            geoip,
            // SAFETY: NonZero::new on a non-zero literal is infallible.
            src_ip_counts: LruCache::new(NonZero::new(10_000).unwrap()),
            repeat_tracker: LruCache::new(NonZero::new(5_000).unwrap()),
            dedup: LruCache::new(NonZero::new(MAX_DEDUP_ENTRIES).unwrap()),
            dedup_window: Duration::from_secs(DEDUP_WINDOW_SECS),
            fusion_windows: FusionWindowLengths::default(),
        }
    }

    pub fn start(self) {
        tokio::spawn(async move { self.run().await });
    }

    async fn run(mut self) {
        log!(DetectionLog::OrchestratorStarted);

        let mut cleanup_interval = interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));

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
        // Canonicalize the raw attack_type so Suricata's "brute-force"
        // classtype and ML's "Brute Force" class name land on the same dedup
        // key — the precondition for cross-source fusion.
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
                    });
                    entry.emitted_at = now;
                } else {
                    // Same source firing again inside the window — keep the
                    // strongest confidence for fusion math.
                    if let Some(existing) = entry.sources.iter_mut().find(|s| s.source == event.source)
                        && existing.confidence < event.confidence
                    {
                        existing.confidence = event.confidence;
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
        self.dedup.put(
            key.clone(),
            DedupEntry {
                sources: vec![SourceSample {
                    source: event.source,
                    confidence: event.confidence,
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
    /// within-window re-emit (2..=4 sources).
    async fn emit_fused(&mut self, trigger_event: &DetectionEvent, key: &(String, String)) {
        let (sources_vec, fused, per_source_confs): (Vec<DetectionSource>, f32, Vec<f32>) = {
            let entry = match self.dedup.get(key) {
                Some(e) => e,
                None => return,
            };
            let confs: Vec<f32> = entry.sources.iter().map(|s| s.confidence).collect();
            let sources: Vec<DetectionSource> = entry.sources.iter().map(|s| s.source).collect();
            let fused = fused_confidence(&confs);
            (sources, fused, confs)
        };
        let _ = per_source_confs; // currently only used for the log line below

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

        if let Err(e) = self.comm.publish_event(threat_event).await {
            log!(SystemError::MlSoarBridgeFailed(e));
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

        let repeat_window = Duration::from_secs(REPEAT_OFFENDER_WINDOW_SECS);
        let now = Instant::now();
        let is_repeat = self
            .repeat_tracker
            .get(src_ip)
            .is_some_and(|last| now.checked_duration_since(*last).unwrap_or(Duration::ZERO) < repeat_window);
        self.repeat_tracker.put(src_ip.clone(), now);

        let geoip_country = if let Some(ref svc) = self.geoip {
            if let Ok(ip) = src_ip.parse() {
                svc.lookup(ip).await.ok().flatten().and_then(|loc| loc.country_code)
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
        let now = Instant::now();
        let window = self.dedup_window;
        while let Some((_, entry)) = self.dedup.peek_lru() {
            if now
                .checked_duration_since(entry.first_emitted_at)
                .unwrap_or(Duration::ZERO)
                >= window
            {
                self.dedup.pop_lru();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Orchestrator integration tests go here once we have an in-memory
    //! CommunicationManager harness. The fusion math is covered by
    //! `fusion_math::tests` and canonical translation by
    //! `model::detection::attack_type::tests`.
}
