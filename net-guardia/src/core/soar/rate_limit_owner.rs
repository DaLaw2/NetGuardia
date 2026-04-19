//! Owner task that serializes SOAR rate-limit adjustments.
//!
//! The "adjust" and "restore" sequences each touch two systems back-to-back
//! (the `soar_rate_limit_*` settings rows and the eBPF `RATE_LIMIT_CONFIG`
//! map). The atomicity that the original `TokioMutex<()>` was protecting is
//! exactly "no other adjust/restore interleaves between the read and the
//! write" — a SQLite transaction can't cover the eBPF half, so we move the
//! read-modify-write inside a single tokio task that owns both ports. All
//! callers dispatch over an mpsc channel and wait on a one-shot reply.

use std::sync::Arc;

use chrono::{Duration as ChronoDuration, NaiveDateTime, Utc};
use macros::log;
use tokio::sync::{mpsc, oneshot};

use crate::interface::port::app_repo::AppRepo;
use crate::interface::port::rate_limit_api::RateLimitPort;
use crate::model::error::Error;
use crate::model::error::soar::SoarError;
use crate::model::log::soar::SoarLog;

/// Channel depth for the owner-task command queue. SOAR rate-limit operations
/// are bursty but rare (operator action / playbook trigger), so 64 is plenty.
const RATE_LIMIT_CMD_CHANNEL_CAPACITY: usize = 64;

/// Settings keys persisted across restarts so the next process can resume the
/// same TTL window. Stable wire format with the DB.
const KEY_ORIGINAL: &str = "soar_rate_limit_original";
const KEY_EXPIRES: &str = "soar_rate_limit_expires";

enum RateLimitCmd {
    Adjust {
        factor: f64,
        ttl_secs: u64,
        source_ip: String,
        attack_type: String,
        reply: oneshot::Sender<Result<String, Error>>,
    },
    RestoreIfExpired {
        reply: oneshot::Sender<Result<(), Error>>,
    },
}

/// Lock-free handle to the rate-limit owner task. Cloning is cheap (just an
/// `mpsc::Sender`).
#[derive(Clone)]
pub struct RateLimitOwnerHandle {
    tx: mpsc::Sender<RateLimitCmd>,
}

impl RateLimitOwnerHandle {
    /// Spawn the owner task on the current tokio runtime. The owner holds
    /// the only mutating references to the DB rate-limit settings and the
    /// eBPF rate-limit map for the duration of an Adjust / Restore batch.
    ///
    /// Each command body runs inside `spawn_blocking` because both halves
    /// (rusqlite via r2d2 and eBPF map writes) are synchronous I/O — running
    /// them directly inside the async owner loop would block the tokio
    /// worker thread for the entire adjust/restore batch.
    pub fn spawn(db: Arc<dyn AppRepo>, rate_limit: Arc<dyn RateLimitPort>) -> Self {
        let (tx, mut rx) = mpsc::channel::<RateLimitCmd>(RATE_LIMIT_CMD_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    RateLimitCmd::Adjust {
                        factor,
                        ttl_secs,
                        source_ip,
                        attack_type,
                        reply,
                    } => {
                        let db_c = db.clone();
                        let rl_c = rate_limit.clone();
                        let join = tokio::task::spawn_blocking(move || {
                            adjust(&db_c, rl_c.as_ref(), factor, ttl_secs, &source_ip, &attack_type)
                        })
                        .await;
                        let result = match join {
                            Ok(r) => r,
                            Err(e) => Err(SoarError::RateLimitOwnerJoinFailed(e.to_string()).into()),
                        };
                        let _ = reply.send(result);
                    }
                    RateLimitCmd::RestoreIfExpired { reply } => {
                        let db_c = db.clone();
                        let rl_c = rate_limit.clone();
                        let join = tokio::task::spawn_blocking(move || restore_if_expired(&db_c, rl_c.as_ref())).await;
                        let result = match join {
                            Ok(r) => r,
                            Err(e) => Err(SoarError::RateLimitOwnerJoinFailed(e.to_string()).into()),
                        };
                        let _ = reply.send(result);
                    }
                }
            }
        });
        Self { tx }
    }

    pub async fn adjust(
        &self,
        factor: f64,
        ttl_secs: u64,
        source_ip: String,
        attack_type: String,
    ) -> Result<String, Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RateLimitCmd::Adjust {
                factor,
                ttl_secs,
                source_ip,
                attack_type,
                reply: reply_tx,
            })
            .await
            .map_err(|_| SoarError::RateLimitOwnerUnavailable)?;
        reply_rx.await.map_err(|_| SoarError::RateLimitOwnerUnavailable)?
    }

    pub async fn restore_if_expired(&self) -> Result<(), Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RateLimitCmd::RestoreIfExpired { reply: reply_tx })
            .await
            .map_err(|_| SoarError::RateLimitOwnerUnavailable)?;
        reply_rx.await.map_err(|_| SoarError::RateLimitOwnerUnavailable)?
    }
}

fn adjust(
    db: &Arc<dyn AppRepo>,
    rate_limit: &dyn RateLimitPort,
    factor: f64,
    ttl_secs: u64,
    source_ip: &str,
    attack_type: &str,
) -> Result<String, Error> {
    let current_packet = rate_limit.get_packet_rate().unwrap_or(10000);
    let current_syn = rate_limit.get_syn_rate().unwrap_or(1000);
    let current_udp = rate_limit.get_udp_rate().unwrap_or(5000);
    let current_dns = rate_limit.get_dns_rate().unwrap_or(2000);

    if db.get_setting(KEY_ORIGINAL)?.filter(|s| !s.is_empty()).is_none() {
        let original = serde_json::json!({
            "packet_rate": current_packet,
            "syn_rate": current_syn,
            "udp_rate": current_udp,
            "dns_rate": current_dns,
        });
        db.set_setting(KEY_ORIGINAL, &original.to_string())?;
    }

    let expires_at = Utc::now() + ChronoDuration::seconds(ttl_secs as i64);
    db.set_setting(KEY_EXPIRES, &expires_at.format("%Y-%m-%d %H:%M:%S").to_string())?;

    let new_packet = (current_packet as f64 * factor) as u64;
    let new_syn = (current_syn as f64 * factor) as u64;
    let new_udp = (current_udp as f64 * factor) as u64;
    let new_dns = (current_dns as f64 * factor) as u64;

    rate_limit.set_packet_rate(new_packet.max(1))?;
    rate_limit.set_syn_rate(new_syn.max(1))?;
    rate_limit.set_udp_rate(new_udp.max(1))?;
    rate_limit.set_dns_rate(new_dns.max(1))?;

    log!(SoarLog::RateLimitAdjusted(
        format!("{}", factor),
        ttl_secs,
        source_ip.to_string(),
        attack_type.to_string(),
        format!(
            "packet {}→{}, syn {}→{}, udp {}→{}, dns {}→{}",
            current_packet,
            new_packet.max(1),
            current_syn,
            new_syn.max(1),
            current_udp,
            new_udp.max(1),
            current_dns,
            new_dns.max(1),
        ),
    ));

    Ok(format!(
        "Rate limits reduced by factor {} for {}s (triggered by {})",
        factor, ttl_secs, source_ip
    ))
}

fn restore_if_expired(db: &Arc<dyn AppRepo>, rate_limit: &dyn RateLimitPort) -> Result<(), Error> {
    let expires_str = match db.get_setting(KEY_EXPIRES)?.filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => return Ok(()),
    };

    let expires = NaiveDateTime::parse_from_str(&expires_str, "%Y-%m-%d %H:%M:%S")
        .map(|dt| dt.and_utc())
        .unwrap_or_else(|_| Utc::now());

    if Utc::now() < expires {
        return Ok(());
    }

    let original_str = match db.get_setting(KEY_ORIGINAL)?.filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => {
            db.set_setting(KEY_EXPIRES, "")?;
            return Ok(());
        }
    };

    if let Ok(original) = serde_json::from_str::<serde_json::Value>(&original_str) {
        let mut restore_errors = Vec::new();
        if let Some(v) = original.get("packet_rate").and_then(|v| v.as_u64())
            && let Err(e) = rate_limit.set_packet_rate(v)
        {
            restore_errors.push(format!("packet_rate: {}", e));
        }
        if let Some(v) = original.get("syn_rate").and_then(|v| v.as_u64())
            && let Err(e) = rate_limit.set_syn_rate(v)
        {
            restore_errors.push(format!("syn_rate: {}", e));
        }
        if let Some(v) = original.get("udp_rate").and_then(|v| v.as_u64())
            && let Err(e) = rate_limit.set_udp_rate(v)
        {
            restore_errors.push(format!("udp_rate: {}", e));
        }
        if let Some(v) = original.get("dns_rate").and_then(|v| v.as_u64())
            && let Err(e) = rate_limit.set_dns_rate(v)
        {
            restore_errors.push(format!("dns_rate: {}", e));
        }
        if restore_errors.is_empty() {
            log!(SoarLog::RateLimitRestored);
        } else {
            log!(SoarLog::RateLimitRestoreFailed(restore_errors.join(", ")));
        }
    }

    db.set_setting(KEY_ORIGINAL, "")?;
    db.set_setting(KEY_EXPIRES, "")?;
    Ok(())
}
