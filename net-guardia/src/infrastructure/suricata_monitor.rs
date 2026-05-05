//! Suricata eve.json tail + parse (M2) + translate to DetectionEvent (M3).
//!
//! Runs as a tokio background task. Waits for the eve.json file to appear
//! (Suricata may take a few seconds after spawn to create it), then tails
//! new lines and parses each as JSON. Only `event_type=alert` lines are
//! forwarded; everything else (flow/stats/fileinfo) is ignored for v0.9.
//!
//! Forwarded events land on the shared `detection_tx` mpsc — the same
//! channel the ML + correlation + beaconing detectors feed. The detection
//! orchestrator handles dedup, GeoIP enrichment, and publishes the final
//! `ThreatDetectedEvent` that SOAR consumes.
//!
//! File rotation is handled by detecting a shrunken file length on next
//! poll — we reopen from offset 0. Suricata itself rotates eve.json on
//! SIGHUP; we don't send SIGHUP in v0.9 so rotation will be rare.

use std::io::SeekFrom;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use macros::log;
use tokio::fs::{self, File};
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::domain::common::config::AppConfig;
use crate::domain::common::event::{DetectionEvent, DetectionSource};
use crate::domain::detection::log::{DetectionLog, SuricataLog};

/// IANA protocol numbers for Suricata's `proto` strings.
const IANA_PROTO_ICMP: u8 = 1;
const IANA_PROTO_TCP: u8 = 6;
const IANA_PROTO_UDP: u8 = 17;

/// Suricata severity numeric encoding (eve.json `alert.severity`).
const SURICATA_SEVERITY_HIGH: u64 = 1;
const SURICATA_SEVERITY_MEDIUM: u64 = 2;
const SURICATA_SEVERITY_LOW: u64 = 3;

pub struct SuricataMonitor {
    config: Arc<ArcSwap<AppConfig>>,
    detection_tx: mpsc::Sender<DetectionEvent>,
}

impl SuricataMonitor {
    pub fn new(config: Arc<ArcSwap<AppConfig>>, detection_tx: mpsc::Sender<DetectionEvent>) -> Arc<Self> {
        Arc::new(Self { config, detection_tx })
    }

    /// Spawn the tail loop. No-op if the bridge is disabled.
    pub fn start(self: Arc<Self>) {
        if !self.config.load().suricata.enabled {
            return;
        }
        tokio::spawn(async move {
            self.tail_loop().await;
        });
    }

    async fn tail_loop(self: Arc<Self>) {
        let path = self.config.load().suricata.eve_log_path.clone();
        loop {
            let file_wait = Duration::from_secs(self.config.load().suricata.file_wait_interval_secs);
            // Wait until the file exists — Suricata spawns asynchronously and
            // may take a few seconds to create eve.json.
            if !Path::new(&path).exists() {
                log!(SuricataLog::MonitorWaitingForFile(path.clone()));
                while !Path::new(&path).exists() {
                    sleep(file_wait).await;
                }
            }

            let mut file = match File::open(&path).await {
                Ok(f) => f,
                Err(_) => {
                    sleep(file_wait).await;
                    continue;
                }
            };
            // Seek to end so we only see new content from this point. Suricata
            // writes a large volume at startup that we don't want to replay.
            let mut pos: u64 = file.seek(SeekFrom::End(0)).await.unwrap_or_default();
            log!(SuricataLog::MonitorAttached(path.clone()));

            let mut reader = BufReader::new(file);
            let mut line = String::new();

            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => {
                        // EOF — check for rotation (file truncated or replaced).
                        if let Ok(meta) = fs::metadata(&path).await
                            && meta.len() < pos
                        {
                            log!(SuricataLog::MonitorFileRotated);
                            break; // reopen
                        }
                        sleep(Duration::from_millis(self.config.load().suricata.poll_interval_ms)).await;
                    }
                    Ok(n) => {
                        pos += n as u64;
                        self.handle_line(line.trim_end()).await;
                    }
                    Err(_) => {
                        // Read error — treat as rotation and reopen.
                        sleep(Duration::from_millis(self.config.load().suricata.poll_interval_ms)).await;
                        break;
                    }
                }
            }
        }
    }

    async fn handle_line(&self, raw: &str) {
        if raw.is_empty() {
            return;
        }
        // Cheap pre-filter: a busy Suricata writes flow/stats/dns/http/fileinfo
        // lines that vastly outnumber alerts. Parsing every line into
        // serde_json::Value just to drop it dominates CPU on this tail. The
        // substring match is a sound over-approximation — false positives go
        // through the full parse + the strict event_type=="alert" check below.
        if !raw.contains("\"event_type\":\"alert\"") {
            return;
        }
        let v: serde_json::Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(_) => return,
        };
        if v.get("event_type").and_then(|x| x.as_str()) != Some("alert") {
            return;
        }
        let Some(event) = self.translate_alert(&v) else {
            return;
        };
        // mpsc is bounded; if the orchestrator is backed up, drop rather than
        // block the tail (eve.json will fill the disk if we block).
        if let Err(tokio::sync::mpsc::error::TrySendError::Full(d)) = self.detection_tx.try_send(event) {
            log!(DetectionLog::DetectionChannelDrop(
                format!("{:?}", d.source),
                d.attack_type,
                d.source_ip,
            ));
        }
    }

    /// Map a Suricata alert JSON object to a DetectionEvent. Returns None if
    /// the event lacks the fields we need.
    fn translate_alert(&self, v: &serde_json::Value) -> Option<DetectionEvent> {
        let src_ip = v.get("src_ip")?.as_str()?.to_string();
        let dest_ip = v.get("dest_ip")?.as_str()?.to_string();
        let proto_str = v.get("proto").and_then(|x| x.as_str()).unwrap_or("");
        let protocol: u8 = match proto_str {
            "TCP" => IANA_PROTO_TCP,
            "UDP" => IANA_PROTO_UDP,
            "ICMP" => IANA_PROTO_ICMP,
            _ => 0,
        };

        let alert = v.get("alert")?;
        let sid = alert.get("signature_id").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
        let signature = alert
            .get("signature")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        // Suricata severity: 1=high, 2=medium, 3=low, 4=informational.
        // Map to confidence in [0.5, 1.0] so high-severity alerts tend to trip
        // SOAR condition thresholds.
        let severity = alert
            .get("severity")
            .and_then(|x| x.as_u64())
            .unwrap_or(SURICATA_SEVERITY_LOW);
        let suri_cfg = self.config.load().suricata.clone();
        let confidence = match severity {
            SURICATA_SEVERITY_HIGH => suri_cfg.confidence_high,
            SURICATA_SEVERITY_MEDIUM => suri_cfg.confidence_medium,
            SURICATA_SEVERITY_LOW => suri_cfg.confidence_low,
            _ => suri_cfg.confidence_info,
        };

        log!(SuricataLog::AlertForwarded(
            sid,
            src_ip.clone(),
            dest_ip.clone(),
            signature,
        ));

        let category = alert.get("category").and_then(|x| x.as_str()).unwrap_or("unknown");
        let canonical = crate::domain::detection::attack_type::translate(DetectionSource::Suricata, category);

        Some(DetectionEvent {
            source: DetectionSource::Suricata,
            attack_type: canonical.as_str().to_string(),
            confidence,
            source_ip: src_ip,
            dest_ip,
            protocol,
            packet_count: 0,
            flow_duration_us: 0,
            ae_score: 0.0,
            anomaly_score: 0.0,
            c2_score: 0.0,
        })
    }
}
