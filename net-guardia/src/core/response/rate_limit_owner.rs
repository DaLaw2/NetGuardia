use std::array;
use std::sync::Arc;
use std::time::{Duration, Instant};

use macros::log;
use tokio::sync::{mpsc, oneshot};
use tokio::task;

use crate::common::error::Error;
use crate::domain::response::error::SoarError;
use crate::domain::response::log::SoarLog;
use crate::interface::data_plane::rate_limit_api::RateLimitPort;

const RATE_KEYS: [&str; 4] = ["packet_rate", "syn_rate", "udp_rate", "dns_rate"];

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
        reply: oneshot::Sender<Result<RestoreOutcome, Error>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOutcome {
    Restored,
    NotExpired,
    NoActiveAdjustment,
}

#[derive(Clone)]
pub struct RateLimitOwnerHandle {
    tx: mpsc::Sender<RateLimitCmd>,
}

pub struct RateLimitOwnerRunner {
    rate_limit: Arc<dyn RateLimitPort>,
    rx: mpsc::Receiver<RateLimitCmd>,
}

impl RateLimitOwnerHandle {
    pub fn new(rate_limit: Arc<dyn RateLimitPort>, channel_capacity: usize) -> (Self, RateLimitOwnerRunner) {
        let (tx, rx) = mpsc::channel::<RateLimitCmd>(channel_capacity.max(1));
        (Self { tx }, RateLimitOwnerRunner { rate_limit, rx })
    }
}

impl RateLimitOwnerRunner {
    pub async fn run(mut self) {
        let mut state: Option<ActiveAdjustment> = None;

        while let Some(cmd) = self.rx.recv().await {
            match cmd {
                RateLimitCmd::Adjust {
                    factor,
                    ttl_secs,
                    source_ip,
                    attack_type,
                    reply,
                } => {
                    let Some(expires) = Instant::now().checked_add(Duration::from_secs(ttl_secs)) else {
                        let _ = reply.send(Err(SoarError::TtlTooLarge(ttl_secs).into()));
                        continue;
                    };
                    let rl_c = self.rate_limit.clone();
                    let current_state = state.is_some();
                    let join = task::spawn_blocking(move || {
                        if current_state {
                            Ok(None)
                        } else {
                            first_adjust(rl_c.as_ref(), factor).map(Some)
                        }
                    })
                    .await;

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
                                original: original.orig,
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
                        Err(e) => Err(Error::from(SoarError::RateLimitOwnerJoinFailed(e))),
                    };
                    let _ = reply.send(result);
                }
                RateLimitCmd::RestoreIfExpired { reply } => {
                    let result = match &state {
                        Some(adj) if Instant::now() >= adj.expires => {
                            let original = adj.original;
                            let rl_c = self.rate_limit.clone();
                            let join = task::spawn_blocking(move || restore(rl_c.as_ref(), &original)).await;
                            match join {
                                Ok(Ok(())) => {
                                    state = None;
                                    Ok(RestoreOutcome::Restored)
                                }
                                Ok(Err(e)) => Err(e),
                                Err(e) => Err(Error::from(SoarError::RateLimitOwnerJoinFailed(e))),
                            }
                        }
                        Some(_) => Ok(RestoreOutcome::NotExpired),
                        None => Ok(RestoreOutcome::NoActiveAdjustment),
                    };
                    let _ = reply.send(result);
                }
            }
        }
    }
}

impl RateLimitOwnerHandle {
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

    pub async fn restore_if_expired(&self) -> Result<RestoreOutcome, Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RateLimitCmd::RestoreIfExpired { reply: reply_tx })
            .await
            .map_err(|_| SoarError::RateLimitOwnerUnavailable)?;
        reply_rx.await.map_err(|_| SoarError::RateLimitOwnerUnavailable)?
    }
}

#[derive(Debug)]
struct AdjustResult {
    orig: [u64; 4],
    new_snapshot: [u64; 4],
}

fn first_adjust(rate_limit: &dyn RateLimitPort, factor: f64) -> Result<AdjustResult, Error> {
    let orig = [
        rate_limit.get_packet_rate()?,
        rate_limit.get_syn_rate()?,
        rate_limit.get_udp_rate()?,
        rate_limit.get_dns_rate()?,
    ];

    let new: [u64; 4] = array::from_fn(|i| ((orig[i] as f64 * factor) as u64).max(1));

    apply_adjustment(rate_limit, &orig, &new)?;

    Ok(AdjustResult {
        orig,
        new_snapshot: new,
    })
}

fn apply_adjustment(rate_limit: &dyn RateLimitPort, original: &[u64; 4], rates: &[u64; 4]) -> Result<(), Error> {
    rate_limit.set_packet_rate(rates[0])?;
    if let Err(err) = rate_limit.set_syn_rate(rates[1]) {
        return rollback_adjustment(rate_limit, original, 1, err);
    }
    if let Err(err) = rate_limit.set_udp_rate(rates[2]) {
        return rollback_adjustment(rate_limit, original, 2, err);
    }
    if let Err(err) = rate_limit.set_dns_rate(rates[3]) {
        return rollback_adjustment(rate_limit, original, 3, err);
    }
    Ok(())
}

fn rollback_adjustment(
    rate_limit: &dyn RateLimitPort,
    original: &[u64; 4],
    applied_count: usize,
    cause: Error,
) -> Result<(), Error> {
    if let Err(rollback_err) = restore_prefix(rate_limit, original, applied_count, "adjust_rate_limit_rollback") {
        Err(SoarError::ActionFailed(
            "adjust_rate_limit",
            format!("{cause}; rollback failed: {rollback_err}"),
        ))?;
    }
    Err(cause)
}

fn restore(rate_limit: &dyn RateLimitPort, original: &[u64; 4]) -> Result<(), Error> {
    restore_prefix(rate_limit, original, original.len(), "restore_rate_limit")?;
    log!(SoarLog::RateLimitRestored);
    Ok(())
}

fn restore_prefix(
    rate_limit: &dyn RateLimitPort,
    original: &[u64; 4],
    count: usize,
    action_type: &str,
) -> Result<(), Error> {
    let mut errors = Vec::new();
    for i in (0..count).rev() {
        let result = match i {
            0 => rate_limit.set_packet_rate(original[0]),
            1 => rate_limit.set_syn_rate(original[1]),
            2 => rate_limit.set_udp_rate(original[2]),
            3 => rate_limit.set_dns_rate(original[3]),
            _ => Ok(()),
        };
        if let Err(e) = result {
            errors.push(format!("{}: {e}", RATE_KEYS[i]));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        let detail = errors.join(", ");
        log!(SoarLog::RateLimitRestoreFailed(detail.clone()));
        Err(SoarError::ActionFailed(action_type, detail))?
    }
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::domain::data_plane::error::EbpfError;

    struct FakeRateLimit {
        values: Mutex<[u64; 4]>,
        fail_get: Option<&'static str>,
        fail_set: Option<&'static str>,
    }

    impl FakeRateLimit {
        fn new(values: [u64; 4]) -> Self {
            Self {
                values: Mutex::new(values),
                fail_get: None,
                fail_set: None,
            }
        }

        fn with_fail_get(mut self, key: &'static str) -> Self {
            self.fail_get = Some(key);
            self
        }

        fn with_fail_set(mut self, key: &'static str) -> Self {
            self.fail_set = Some(key);
            self
        }

        fn get_key(&self, key: &'static str, index: usize) -> Result<u64, Error> {
            if self.fail_get == Some(key) {
                Err(EbpfError::MapOperationError(format!("forced get failure: {key}")))?;
            }
            Ok(self.values.lock().expect("test lock")[index])
        }

        fn set_key(&self, key: &'static str, index: usize, value: u64) -> Result<(), Error> {
            if self.fail_set == Some(key) {
                Err(EbpfError::MapOperationError(format!("forced set failure: {key}")))?;
            }
            self.values.lock().expect("test lock")[index] = value;
            Ok(())
        }

        fn snapshot(&self) -> [u64; 4] {
            *self.values.lock().expect("test lock")
        }
    }

    impl RateLimitPort for FakeRateLimit {
        fn set_packet_rate(&self, rate: u64) -> Result<(), Error> {
            self.set_key("packet_rate", 0, rate)
        }

        fn set_syn_rate(&self, rate: u64) -> Result<(), Error> {
            self.set_key("syn_rate", 1, rate)
        }

        fn set_udp_rate(&self, rate: u64) -> Result<(), Error> {
            self.set_key("udp_rate", 2, rate)
        }

        fn set_dns_rate(&self, rate: u64) -> Result<(), Error> {
            self.set_key("dns_rate", 3, rate)
        }

        fn set_window_ns(&self, _ns: u64) -> Result<(), Error> {
            Ok(())
        }

        fn get_packet_rate(&self) -> Result<u64, Error> {
            self.get_key("packet_rate", 0)
        }

        fn get_syn_rate(&self) -> Result<u64, Error> {
            self.get_key("syn_rate", 1)
        }

        fn get_udp_rate(&self) -> Result<u64, Error> {
            self.get_key("udp_rate", 2)
        }

        fn get_dns_rate(&self) -> Result<u64, Error> {
            self.get_key("dns_rate", 3)
        }

        fn get_window_ns(&self) -> Result<u64, Error> {
            Ok(1)
        }
    }

    #[test]
    fn first_adjust_propagates_live_read_failure() {
        let rate_limit = FakeRateLimit::new([100, 80, 60, 40]).with_fail_get("syn_rate");
        let err = first_adjust(&rate_limit, 0.5).unwrap_err();
        assert!(err.to_string().contains("forced get failure"));
        assert_eq!(rate_limit.snapshot(), [100, 80, 60, 40]);
    }

    #[test]
    fn first_adjust_rolls_back_partial_live_write_failure() {
        let rate_limit = FakeRateLimit::new([100, 80, 60, 40]).with_fail_set("syn_rate");
        let err = first_adjust(&rate_limit, 0.5).unwrap_err();
        assert!(err.to_string().contains("forced set failure"));
        assert_eq!(rate_limit.snapshot(), [100, 80, 60, 40]);
    }

    #[test]
    fn restore_reports_set_failures() {
        let rate_limit = FakeRateLimit::new([50, 40, 30, 20]).with_fail_set("udp_rate");
        let err = restore(&rate_limit, &[100, 80, 60, 40]).unwrap_err();
        assert!(err.to_string().contains("restore_rate_limit"));
    }

    #[tokio::test]
    async fn owner_restores_pre_adjustment_rates_after_expiry() {
        let rate_limit = Arc::new(FakeRateLimit::new([100, 80, 60, 40]));
        let (owner, runner) = RateLimitOwnerHandle::new(rate_limit.clone(), 4);
        let runner_task = tokio::spawn(runner.run());

        owner
            .adjust(0.5, 0, "10.0.0.8".to_string(), "brute_force".to_string())
            .await
            .expect("adjust");
        assert_eq!(rate_limit.snapshot(), [50, 40, 30, 20]);

        owner.restore_if_expired().await.expect("restore");
        assert_eq!(rate_limit.snapshot(), [100, 80, 60, 40]);

        drop(owner);
        runner_task.await.expect("runner exits after channel close");
    }

    #[tokio::test]
    async fn owner_rejects_ttl_too_large_to_schedule() {
        let rate_limit = Arc::new(FakeRateLimit::new([100, 80, 60, 40]));
        let (owner, runner) = RateLimitOwnerHandle::new(rate_limit.clone(), 4);
        let runner_task = tokio::spawn(runner.run());

        let err = owner
            .adjust(0.5, u64::MAX, "10.0.0.8".to_string(), "brute_force".to_string())
            .await
            .expect_err("oversized ttl should fail");

        assert!(
            err.to_string().contains("too large to schedule safely"),
            "unexpected error: {err}"
        );
        assert_eq!(rate_limit.snapshot(), [100, 80, 60, 40]);

        drop(owner);
        runner_task.await.expect("runner exits after channel close");
    }
}
