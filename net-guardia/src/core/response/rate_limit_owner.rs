use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use macros::log;
use tokio::sync::{mpsc, oneshot};

use crate::domain::common::config::AppConfig;
use crate::domain::common::error::Error;
use crate::domain::response::error::SoarError;
use crate::domain::response::log::SoarLog;
use crate::interface::rate_limit_api::RateLimitPort;

struct ActiveAdjustment {
    original: [u64; 4],
    expires: Instant,
}

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

#[derive(Clone)]
pub struct RateLimitOwnerHandle {
    tx: mpsc::Sender<RateLimitCmd>,
}

impl RateLimitOwnerHandle {
    pub fn spawn(rate_limit: Arc<dyn RateLimitPort>, config: Arc<ArcSwap<AppConfig>>, channel_capacity: usize) -> Self {
        let (tx, mut rx) = mpsc::channel::<RateLimitCmd>(channel_capacity.max(1));

        tokio::spawn(async move {
            let mut state: Option<ActiveAdjustment> = None;

            while let Some(cmd) = rx.recv().await {
                match cmd {
                    RateLimitCmd::Adjust {
                        factor,
                        ttl_secs,
                        source_ip,
                        attack_type,
                        reply,
                    } => {
                        let rl_c = rate_limit.clone();
                        let cfg = config.load_full();
                        let current_state = state.is_some();
                        let join = tokio::task::spawn_blocking(move || {
                            if current_state {
                                Ok(None)
                            } else {
                                first_adjust(rl_c.as_ref(), &cfg, factor).map(Some)
                            }
                        })
                        .await;

                        let expires = Instant::now() + Duration::from_secs(ttl_secs);
                        let result = match join {
                            Ok(Ok(Some(original))) => {
                                log!(SoarLog::RateLimitAdjusted(
                                    format!("{factor}"),
                                    ttl_secs,
                                    source_ip.clone(),
                                    attack_type,
                                    format_change(&original),
                                ));
                                state = Some(ActiveAdjustment {
                                    original: original.new_snapshot,
                                    expires,
                                });
                                Ok(format!(
                                    "Rate limits reduced by factor {factor} for {ttl_secs}s (triggered by {source_ip})"
                                ))
                            }
                            Ok(Ok(None)) => {
                                if let Some(ref mut s) = state {
                                    s.expires = expires;
                                }
                                log!(SoarLog::RateLimitAdjusted(
                                    format!("{factor}"),
                                    ttl_secs,
                                    source_ip.clone(),
                                    attack_type,
                                    "TTL extended (rates already reduced)".to_string(),
                                ));
                                Ok(format!(
                                    "Rate limit TTL extended by {ttl_secs}s (triggered by {source_ip})"
                                ))
                            }
                            Ok(Err(e)) => Err(e),
                            Err(e) => Err(SoarError::RateLimitOwnerJoinFailed(e.to_string()).into()),
                        };
                        let _ = reply.send(result);
                    }
                    RateLimitCmd::RestoreIfExpired { reply } => {
                        let result = match &state {
                            Some(adj) if Instant::now() >= adj.expires => {
                                let original = adj.original;
                                let rl_c = rate_limit.clone();
                                let join = tokio::task::spawn_blocking(move || restore(rl_c.as_ref(), &original)).await;
                                match join {
                                    Ok(Ok(())) => {
                                        state = None;
                                        Ok(())
                                    }
                                    Ok(Err(e)) => Err(e),
                                    Err(e) => Err(SoarError::RateLimitOwnerJoinFailed(e.to_string()).into()),
                                }
                            }
                            _ => Ok(()),
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

struct AdjustResult {
    orig: [u64; 4],
    new_snapshot: [u64; 4],
}

fn first_adjust(rate_limit: &dyn RateLimitPort, config: &AppConfig, factor: f64) -> Result<AdjustResult, Error> {
    let ebpf = &config.ebpf;
    let orig = [
        rate_limit.get_packet_rate().unwrap_or(ebpf.default_packet_rate),
        rate_limit.get_syn_rate().unwrap_or(ebpf.default_syn_rate),
        rate_limit.get_udp_rate().unwrap_or(ebpf.default_udp_rate),
        rate_limit.get_dns_rate().unwrap_or(ebpf.default_dns_rate),
    ];

    let new: [u64; 4] = std::array::from_fn(|i| ((orig[i] as f64 * factor) as u64).max(1));

    rate_limit.set_packet_rate(new[0])?;
    rate_limit.set_syn_rate(new[1])?;
    rate_limit.set_udp_rate(new[2])?;
    rate_limit.set_dns_rate(new[3])?;

    Ok(AdjustResult {
        orig,
        new_snapshot: new,
    })
}

fn restore(rate_limit: &dyn RateLimitPort, original: &[u64; 4]) -> Result<(), Error> {
    let mut errors = Vec::new();
    if let Err(e) = rate_limit.set_packet_rate(original[0]) {
        errors.push(format!("packet_rate: {e}"));
    }
    if let Err(e) = rate_limit.set_syn_rate(original[1]) {
        errors.push(format!("syn_rate: {e}"));
    }
    if let Err(e) = rate_limit.set_udp_rate(original[2]) {
        errors.push(format!("udp_rate: {e}"));
    }
    if let Err(e) = rate_limit.set_dns_rate(original[3]) {
        errors.push(format!("dns_rate: {e}"));
    }
    if errors.is_empty() {
        log!(SoarLog::RateLimitRestored);
    } else {
        log!(SoarLog::RateLimitRestoreFailed(errors.join(", ")));
    }
    Ok(())
}

fn format_change(result: &AdjustResult) -> String {
    format!(
        "packet {}→{}, syn {}→{}, udp {}→{}, dns {}→{}",
        result.orig[0],
        result.new_snapshot[0],
        result.orig[1],
        result.new_snapshot[1],
        result.orig[2],
        result.new_snapshot[2],
        result.orig[3],
        result.new_snapshot[3],
    )
}
