use super::helpers::{override_parsed, seed_key};
use crate::interface::port::setting::SettingRepo;
use crate::model::error::Error;

/// Shared shape for scan / lateral / botnet correlation detectors.
#[derive(Debug, Clone)]
pub struct CorrelationDetectorParams {
    pub window_secs: u64,
    pub threshold: usize,
}

#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    pub scan: CorrelationDetectorParams,
    pub lateral: CorrelationDetectorParams,
    pub botnet: CorrelationDetectorParams,
    /// Maximum tracked source/destination IPs per detector to bound memory.
    /// Shared across all three detectors since they share the same memory
    /// concern under DDoS.
    pub max_tracked_entries: usize,
}

impl CorrelationConfig {
    pub fn defaults() -> Self {
        Self {
            scan: CorrelationDetectorParams {
                window_secs: 120,
                threshold: 20,
            },
            lateral: CorrelationDetectorParams {
                window_secs: 300,
                threshold: 5,
            },
            botnet: CorrelationDetectorParams {
                window_secs: 300,
                threshold: 10,
            },
            max_tracked_entries: 10_000,
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_parsed(&mut cfg.scan.window_secs, repo, "correlation_scan_window_secs")?;
        override_parsed(&mut cfg.scan.threshold, repo, "correlation_scan_threshold")?;
        override_parsed(&mut cfg.lateral.window_secs, repo, "correlation_lateral_window_secs")?;
        override_parsed(&mut cfg.lateral.threshold, repo, "correlation_lateral_threshold")?;
        override_parsed(&mut cfg.botnet.window_secs, repo, "correlation_botnet_window_secs")?;
        override_parsed(&mut cfg.botnet.threshold, repo, "correlation_botnet_threshold")?;
        override_parsed(&mut cfg.max_tracked_entries, repo, "correlation_max_tracked_entries")?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "correlation_scan_window_secs", "120")?;
        seed_key(repo, "correlation_scan_threshold", "20")?;
        seed_key(repo, "correlation_lateral_window_secs", "300")?;
        seed_key(repo, "correlation_lateral_threshold", "5")?;
        seed_key(repo, "correlation_botnet_window_secs", "300")?;
        seed_key(repo, "correlation_botnet_threshold", "10")?;
        seed_key(repo, "correlation_max_tracked_entries", "10000")?;
        Ok(())
    }
}
