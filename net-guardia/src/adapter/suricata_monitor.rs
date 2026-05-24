use std::io::SeekFrom;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use macros::log;
use tokio::fs::{self, File};
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::common::log::suricata::SuricataLog;
use crate::core::detection::send_detection_or_log;
use crate::domain::common::config::AppConfig;
use crate::domain::common::event::{DetectionEvent, DetectionSource};
use crate::domain::detection::attack_type::translate;

const IANA_PROTO_ICMP: u8 = 1;
const IANA_PROTO_TCP: u8 = 6;
const IANA_PROTO_UDP: u8 = 17;
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

    pub fn start(self: Arc<Self>) -> Option<JoinHandle<()>> {
        if !self.config.load().suricata.enabled {
            return None;
        }
        Some(tokio::spawn(async move {
            self.tail_loop().await;
        }))
    }

    async fn tail_loop(self: Arc<Self>) {
        let path = self.config.load().suricata.eve_log_path.clone();
        loop {
            let file_wait = Duration::from_secs(self.config.load().suricata.file_wait_interval_secs);
            if !Path::new(&path).exists() {
                log!(SuricataLog::MonitorWaitingForFile(path.clone()));
                while !Path::new(&path).exists() {
                    sleep(file_wait).await;
                }
            }

            let mut file = match File::open(&path).await {
                Ok(f) => f,
                Err(e) => {
                    log!(SuricataLog::MonitorOpenFailed(path.clone(), e.to_string()));
                    sleep(file_wait).await;
                    continue;
                }
            };
            let mut pos: u64 = match file.seek(SeekFrom::End(0)).await {
                Ok(pos) => pos,
                Err(e) => {
                    log!(SuricataLog::MonitorSeekFailed(path.clone(), e.to_string()));
                    sleep(file_wait).await;
                    continue;
                }
            };
            log!(SuricataLog::MonitorAttached(path.clone()));

            let mut reader = BufReader::new(file);
            let mut line = String::new();

            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => {
                        if let Ok(meta) = fs::metadata(&path).await
                            && meta.len() < pos
                        {
                            log!(SuricataLog::MonitorFileRotated);
                            break;
                        }
                        sleep(Duration::from_millis(self.config.load().suricata.poll_interval_ms)).await;
                    }
                    Ok(n) => {
                        pos += n as u64;
                        self.handle_line(line.trim_end()).await;
                    }
                    Err(_) => {
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
        if !may_be_alert_event(raw) {
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
        let _ = send_detection_or_log(&self.detection_tx, event);
    }

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
        let canonical = translate(DetectionSource::Suricata, category);

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

fn may_be_alert_event(raw: &str) -> bool {
    for (field_start, _) in raw.match_indices("\"event_type\"") {
        let rest = &raw[field_start + "\"event_type\"".len()..];
        let Some(rest) = rest.trim_start().strip_prefix(':') else {
            continue;
        };
        if rest.trim_start().starts_with("\"alert\"") {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arc_swap::ArcSwap;
    use tokio::sync::mpsc;

    use super::*;
    use crate::domain::common::config::AppConfig;

    fn detection_event() -> DetectionEvent {
        DetectionEvent {
            source: DetectionSource::Suricata,
            attack_type: "c2_beacon".to_string(),
            confidence: 0.9,
            source_ip: "192.0.2.10".to_string(),
            dest_ip: "198.51.100.20".to_string(),
            protocol: IANA_PROTO_TCP,
            packet_count: 0,
            flow_duration_us: 0,
            ae_score: 0.0,
            anomaly_score: 0.0,
            c2_score: 0.0,
        }
    }

    #[test]
    fn alert_candidate_accepts_compact_and_spaced_event_type() {
        assert!(may_be_alert_event(r#"{"event_type":"alert"}"#));
        assert!(may_be_alert_event(r#"{ "event_type" : "alert" }"#));
    }

    #[test]
    fn alert_candidate_rejects_non_alert_event_type() {
        assert!(!may_be_alert_event(r#"{"event_type":"flow"}"#));
        assert!(!may_be_alert_event(r#"{ "event_type" : "stats" }"#));
    }

    #[tokio::test]
    async fn handle_line_accepts_spaced_alert_event_type() {
        let (tx, mut rx) = mpsc::channel(1);
        let monitor = SuricataMonitor {
            config: Arc::new(ArcSwap::from_pointee(AppConfig::defaults())),
            detection_tx: tx,
        };

        monitor
            .handle_line(
                r#"{
                    "event_type" : "alert",
                    "src_ip": "192.0.2.10",
                    "dest_ip": "198.51.100.20",
                    "proto": "TCP",
                    "alert": {
                        "signature_id": 42,
                        "signature": "test alert",
                        "severity": 1,
                        "category": "trojan-activity"
                    }
                }"#,
            )
            .await;

        let event = rx.try_recv().expect("spaced alert should be forwarded");
        assert_eq!(event.source, DetectionSource::Suricata);
        assert_eq!(event.source_ip, "192.0.2.10");
        assert_eq!(event.dest_ip, "198.51.100.20");
        assert_eq!(event.protocol, IANA_PROTO_TCP);
    }

    #[test]
    fn send_detection_or_log_reports_closed_channel_drop() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);

        assert!(!send_detection_or_log(&tx, detection_event()));
    }
}
