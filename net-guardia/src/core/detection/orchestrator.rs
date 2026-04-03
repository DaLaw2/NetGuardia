use std::num::NonZero;
use std::sync::Arc;
use std::time::{Duration, Instant};

use macros::log;
use tokio::sync::mpsc;

use crate::infrastructure::communication_manager::CommunicationManager;
use crate::infrastructure::geoip::GeoIpService;
use crate::model::error::system::SystemError;
use crate::model::event::{DetectionEvent, DetectionSource, ThreatDetectedEvent};
use crate::model::log::detection::DetectionLog;

/// Dedup window: detections for the same (source_ip, attack_type) within this window
/// are suppressed after the first emission.
const DEDUP_WINDOW_SECS: u64 = 30;

/// How often to sweep expired dedup entries.
const CLEANUP_INTERVAL_SECS: u64 = 60;

/// Repeat offender detection: same IP within this duration counts as repeat.
const REPEAT_OFFENDER_WINDOW_SECS: u64 = 2 * 60 * 60; // 2 hours

/// Maximum dedup entries to prevent unbounded memory growth under sustained attack.
const MAX_DEDUP_ENTRIES: usize = 50_000;

struct DedupEntry {
    sources: Vec<DetectionSource>,
    emitted_at: Instant,
}

/// Coordinates detections from multiple sources (ML, future: rules, correlation, threat feeds).
/// Deduplicates, enriches with GeoIP/hit count/repeat offender, and emits ThreatDetectedEvent.
pub struct DetectionOrchestrator {
    rx: mpsc::Receiver<DetectionEvent>,
    comm: Arc<CommunicationManager>,
    geoip: Option<Arc<GeoIpService>>,
    // Enrichment state
    // SAFETY: NonZero::new on a literal is infallible.
    src_ip_counts: lru::LruCache<String, u32>,
    repeat_tracker: lru::LruCache<String, Instant>,
    // Dedup state — LRU-bounded to prevent unbounded growth under sustained attack
    dedup: lru::LruCache<(String, String), DedupEntry>,
    dedup_window: Duration,
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
            src_ip_counts: lru::LruCache::new(NonZero::new(10_000).unwrap()),
            repeat_tracker: lru::LruCache::new(NonZero::new(5_000).unwrap()),
            dedup: lru::LruCache::new(NonZero::new(MAX_DEDUP_ENTRIES).unwrap()),
            dedup_window: Duration::from_secs(DEDUP_WINDOW_SECS),
        }
    }

    /// Spawn the orchestrator as a background task.
    pub fn start(self) {
        tokio::spawn(async move { self.run().await });
    }

    async fn run(mut self) {
        log!(DetectionLog::OrchestratorStarted);

        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));

        loop {
            tokio::select! {
                event = self.rx.recv() => {
                    match event {
                        Some(detection) => self.handle_detection(detection).await,
                        None => break, // All senders dropped
                    }
                }
                _ = cleanup_interval.tick() => {
                    self.cleanup_expired();
                }
            }
        }
    }

    async fn handle_detection(&mut self, event: DetectionEvent) {
        let key = (event.source_ip.clone(), event.attack_type.clone());
        let now = Instant::now();

        // Dedup check
        if let Some(entry) = self.dedup.get(&key)
            && now.checked_duration_since(entry.emitted_at).unwrap_or(Duration::ZERO) < self.dedup_window
        {
            // Within window: add source attribution but don't re-emit
            if !entry.sources.contains(&event.source) {
                // Re-get as mutable to update sources
                if let Some(entry) = self.dedup.get_mut(&key) {
                    entry.sources.push(event.source.clone());
                }
            }
            log!(DetectionLog::DetectionDeduplicated {
                source_ip: event.source_ip,
                attack_type: event.attack_type,
            });
            return;
        }

        // Enrich and emit
        let threat_event = self.enrich(&event).await;
        let sources = vec![event.source.clone()];

        log!(DetectionLog::DetectionEmitted {
            source_ip: event.source_ip.clone(),
            attack_type: event.attack_type.clone(),
            confidence: event.confidence,
            sources_count: sources.len(),
        });

        // Record dedup entry (LRU-bounded)
        self.dedup.put(
            key,
            DedupEntry {
                sources,
                emitted_at: now,
            },
        );

        if let Err(e) = self.comm.publish_event(threat_event).await {
            log!(SystemError::MlSoarBridgeFailed(e));
        }
    }

    async fn enrich(&mut self, event: &DetectionEvent) -> ThreatDetectedEvent {
        let src_ip = &event.source_ip;

        // Compute packet rate
        let packet_rate = if event.flow_duration_us > 0 {
            event.packet_count as f64 / (event.flow_duration_us as f64 / 1_000_000.0)
        } else {
            0.0
        };

        // Update hit count (LRU bounded)
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

        // Check repeat offender (same IP within window)
        let repeat_window = Duration::from_secs(REPEAT_OFFENDER_WINDOW_SECS);
        let now = Instant::now();
        let is_repeat = self
            .repeat_tracker
            .get(src_ip)
            .is_some_and(|last| now.checked_duration_since(*last).unwrap_or(Duration::ZERO) < repeat_window);
        self.repeat_tracker.put(src_ip.clone(), now);

        // GeoIP lookup
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
            sources: vec![event.source.clone()],
        }
    }

    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let window = self.dedup_window;
        // Pop expired entries from the LRU (oldest entries are least recently used)
        while let Some((_, entry)) = self.dedup.peek_lru() {
            if now.checked_duration_since(entry.emitted_at).unwrap_or(Duration::ZERO) >= window {
                self.dedup.pop_lru();
            } else {
                break;
            }
        }
    }
}
