use std::sync::Arc;

use macros::log;

use crate::common::error::Error;
use crate::common::log::data_plane::DataPlaneLog;
use crate::domain::common::system::rate_limit_settings::RateLimitSettings;
use crate::domain::data_plane::error::EbpfError;
use crate::interface::data_plane::enforcement::RateLimitWritePort;
use crate::interface::data_plane::rate_limit_api::RateLimitPort;

const PACKET_RATE_KEY: &str = "packet_rate";
const SYN_RATE_KEY: &str = "syn_rate";
const UDP_RATE_KEY: &str = "udp_rate";
const DNS_RATE_KEY: &str = "dns_rate";
const WINDOW_NS_KEY: &str = "window_ns";

struct RateLimitChange {
    key: &'static str,
    old: u64,
    new: u64,
}

pub struct RateLimitService {
    db: Arc<dyn RateLimitWritePort>,
    config: Arc<dyn RateLimitPort>,
}

impl RateLimitService {
    pub fn new(db: Arc<dyn RateLimitWritePort>, config: Arc<dyn RateLimitPort>) -> Self {
        Self { db, config }
    }

    pub async fn restore(&self) {
        let configs = match self.db.load_rate_limit_config().await {
            Ok(c) => c,
            Err(_) => return,
        };
        for (key, value) in &configs {
            if let Err(e) = self.apply(key, *value) {
                log!(DataPlaneLog::RateLimitRestoreFailed(key.clone(), e.to_string()));
            }
        }
        if !configs.is_empty() {
            log!(DataPlaneLog::RateLimitsRestored(configs.len()));
        }
    }

    pub fn current_settings(&self) -> Result<RateLimitSettings, Error> {
        Ok(RateLimitSettings {
            packet_rate: Some(self.config.get_packet_rate()?),
            syn_rate: Some(self.config.get_syn_rate()?),
            udp_rate: Some(self.config.get_udp_rate()?),
            dns_rate: Some(self.config.get_dns_rate()?),
            window_ns: Some(self.config.get_window_ns()?),
        })
    }

    pub async fn update(&self, settings: &RateLimitSettings) -> Result<(), Error> {
        let changes = self.prepare_changes(settings)?;
        let mut applied = Vec::new();
        for change in &changes {
            if let Err(err) = self.apply(change.key, change.new) {
                self.rollback(&applied);
                return Err(err);
            }
            applied.push((change.key, change.old));
        }

        let persist_values: Vec<(String, u64)> = changes
            .iter()
            .map(|change| (change.key.to_string(), change.new))
            .collect();
        if let Err(err) = self.db.set_rate_limits(&persist_values).await {
            self.rollback(&applied);
            return Err(err);
        }

        Ok(())
    }

    fn prepare_changes(&self, settings: &RateLimitSettings) -> Result<Vec<RateLimitChange>, Error> {
        let mut changes = Vec::new();
        if let Some(v) = settings.packet_rate {
            validate_rate_limit_value(PACKET_RATE_KEY, v)?;
            changes.push(RateLimitChange {
                key: PACKET_RATE_KEY,
                old: self.config.get_packet_rate()?,
                new: v,
            });
        }
        if let Some(v) = settings.syn_rate {
            validate_rate_limit_value(SYN_RATE_KEY, v)?;
            changes.push(RateLimitChange {
                key: SYN_RATE_KEY,
                old: self.config.get_syn_rate()?,
                new: v,
            });
        }
        if let Some(v) = settings.udp_rate {
            validate_rate_limit_value(UDP_RATE_KEY, v)?;
            changes.push(RateLimitChange {
                key: UDP_RATE_KEY,
                old: self.config.get_udp_rate()?,
                new: v,
            });
        }
        if let Some(v) = settings.dns_rate {
            validate_rate_limit_value(DNS_RATE_KEY, v)?;
            changes.push(RateLimitChange {
                key: DNS_RATE_KEY,
                old: self.config.get_dns_rate()?,
                new: v,
            });
        }
        if let Some(v) = settings.window_ns {
            validate_rate_limit_value(WINDOW_NS_KEY, v)?;
            changes.push(RateLimitChange {
                key: WINDOW_NS_KEY,
                old: self.config.get_window_ns()?,
                new: v,
            });
        }
        Ok(changes)
    }

    fn apply(&self, key: &str, value: u64) -> Result<(), Error> {
        match key {
            PACKET_RATE_KEY => self.config.set_packet_rate(value),
            SYN_RATE_KEY => self.config.set_syn_rate(value),
            UDP_RATE_KEY => self.config.set_udp_rate(value),
            DNS_RATE_KEY => self.config.set_dns_rate(value),
            WINDOW_NS_KEY => self.config.set_window_ns(value),
            _ => Ok(()),
        }
    }

    fn rollback(&self, applied: &[(&'static str, u64)]) {
        for (key, old) in applied.iter().rev() {
            if let Err(err) = self.apply(key, *old) {
                log!(DataPlaneLog::RateLimitRollbackFailed(*key, err.to_string()));
            }
        }
    }
}

fn validate_rate_limit_value(key: &str, value: u64) -> Result<(), Error> {
    if value == 0 {
        Err(EbpfError::InvalidRateLimitValue(key.to_string(), value))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::common::error::database::DatabaseError;
    use crate::domain::data_plane::error::EbpfError;

    #[derive(Default)]
    struct FakeRepo {
        fail: bool,
        values: Mutex<Vec<(String, u64)>>,
    }

    #[async_trait]
    impl RateLimitWritePort for FakeRepo {
        async fn load_rate_limit_config(&self) -> Result<Vec<(String, u64)>, Error> {
            Ok(self.values.lock().expect("test lock").clone())
        }

        async fn set_rate_limits(&self, values: &[(String, u64)]) -> Result<(), Error> {
            if self.fail {
                Err(DatabaseError::QueryFailed("forced db failure"))?;
            }
            self.values.lock().expect("test lock").extend_from_slice(values);
            Ok(())
        }
    }

    struct FakeRateLimitPort {
        values: Mutex<[u64; 5]>,
        fail_key: Option<&'static str>,
    }

    impl FakeRateLimitPort {
        fn new(values: [u64; 5], fail_key: Option<&'static str>) -> Self {
            Self {
                values: Mutex::new(values),
                fail_key,
            }
        }

        fn set_key(&self, key: &'static str, index: usize, value: u64) -> Result<(), Error> {
            if self.fail_key == Some(key) {
                Err(EbpfError::MapOperationError("forced live failure"))?;
            }
            self.values.lock().expect("test lock")[index] = value;
            Ok(())
        }

        fn get_index(&self, index: usize) -> Result<u64, Error> {
            Ok(self.values.lock().expect("test lock")[index])
        }
    }

    impl RateLimitPort for FakeRateLimitPort {
        fn set_packet_rate(&self, rate: u64) -> Result<(), Error> {
            self.set_key(PACKET_RATE_KEY, 0, rate)
        }

        fn set_syn_rate(&self, rate: u64) -> Result<(), Error> {
            self.set_key(SYN_RATE_KEY, 1, rate)
        }

        fn set_udp_rate(&self, rate: u64) -> Result<(), Error> {
            self.set_key(UDP_RATE_KEY, 2, rate)
        }

        fn set_dns_rate(&self, rate: u64) -> Result<(), Error> {
            self.set_key(DNS_RATE_KEY, 3, rate)
        }

        fn set_window_ns(&self, ns: u64) -> Result<(), Error> {
            self.set_key(WINDOW_NS_KEY, 4, ns)
        }

        fn get_packet_rate(&self) -> Result<u64, Error> {
            self.get_index(0)
        }

        fn get_syn_rate(&self) -> Result<u64, Error> {
            self.get_index(1)
        }

        fn get_udp_rate(&self) -> Result<u64, Error> {
            self.get_index(2)
        }

        fn get_dns_rate(&self) -> Result<u64, Error> {
            self.get_index(3)
        }

        fn get_window_ns(&self) -> Result<u64, Error> {
            self.get_index(4)
        }
    }

    #[tokio::test]
    async fn update_rolls_back_live_values_when_later_live_write_fails() {
        let repo = Arc::new(FakeRepo::default());
        let port = Arc::new(FakeRateLimitPort::new([10, 20, 30, 40, 50], Some(UDP_RATE_KEY)));
        let service = RateLimitService::new(repo.clone(), port.clone());
        let settings = RateLimitSettings {
            packet_rate: Some(100),
            syn_rate: Some(200),
            udp_rate: Some(300),
            dns_rate: None,
            window_ns: None,
        };

        let result = service.update(&settings).await;

        assert!(result.is_err());
        assert_eq!(*port.values.lock().expect("test lock"), [10, 20, 30, 40, 50]);
        assert!(repo.values.lock().expect("test lock").is_empty());
    }

    #[tokio::test]
    async fn update_rolls_back_live_values_when_db_write_fails() {
        let repo = Arc::new(FakeRepo {
            fail: true,
            values: Mutex::new(Vec::new()),
        });
        let port = Arc::new(FakeRateLimitPort::new([10, 20, 30, 40, 50], None));
        let service = RateLimitService::new(repo, port.clone());
        let settings = RateLimitSettings {
            packet_rate: Some(100),
            syn_rate: Some(200),
            udp_rate: None,
            dns_rate: None,
            window_ns: None,
        };

        let result = service.update(&settings).await;

        assert!(result.is_err());
        assert_eq!(*port.values.lock().expect("test lock"), [10, 20, 30, 40, 50]);
    }

    #[tokio::test]
    async fn update_rejects_zero_rate_limit_values_before_live_write() {
        let repo = Arc::new(FakeRepo::default());
        let port = Arc::new(FakeRateLimitPort::new([10, 20, 30, 40, 50], None));
        let service = RateLimitService::new(repo.clone(), port.clone());
        let settings = RateLimitSettings {
            packet_rate: Some(0),
            syn_rate: None,
            udp_rate: None,
            dns_rate: None,
            window_ns: None,
        };

        let err = service.update(&settings).await.expect_err("zero value should fail");

        match err {
            Error::Ebpf(EbpfError::InvalidRateLimitValue { field, value }) => {
                assert_eq!(field, PACKET_RATE_KEY);
                assert_eq!(value, 0);
            }
            other => panic!("unexpected error: {other}"),
        }
        assert_eq!(*port.values.lock().expect("test lock"), [10, 20, 30, 40, 50]);
        assert!(repo.values.lock().expect("test lock").is_empty());
    }
}
