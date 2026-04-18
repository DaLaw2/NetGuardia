//! Centralized constants for the NetGuardia application.
//! Tunable parameters are grouped by subsystem. Adjust here, not in individual files.

// ── SOAR Engine ────────────────────────────────────────────────────
pub const MAX_PENDING_UNBLOCK_RETRIES: i64 = 5;

// ── ML Engine ──────────────────────────────────────────────────────
pub const ML_ALERT_CHANNEL_CAPACITY: usize = 1024;
pub const FLOW_MAX_PACKETS_PER_DIRECTION: usize = 1000;
pub const FLOW_MAX_PERIODS: usize = 1000;
pub const FLOW_IDLE_THRESHOLD_US: u64 = 1_000_000;
pub const FLOW_BULK_MIN_PACKETS: u64 = 4;
pub const FLOW_BULK_MIN_BYTES: u64 = 1000;
pub const FLOW_IDLE_TIMEOUT_US: u64 = 120_000_000;
pub const FLOW_TERMINATED_TIMEOUT_US: u64 = 5_000_000;

// ── ML Model Directory ─────────────────────────────────────────────
pub const MODELS_DIR: &str = "models";
pub const MANIFEST_FILENAME: &str = "manifest.yaml";
pub const STAGING_SUBDIR: &str = ".staging";

// ── Notification ───────────────────────────────────────────────────
pub const TELEGRAM_MAX_RETRIES: u32 = 2;

// ── HTTP Server ────────────────────────────────────────────────────
pub const HTTP_FALLBACK_PORT: u16 = 8080;

// ── Infrastructure ─────────────────────────────────────────────────
pub const DEFAULT_EVENT_CHANNEL_CAPACITY: usize = 256;
pub const DROP_CHANNEL_CAPACITY: usize = 100;
