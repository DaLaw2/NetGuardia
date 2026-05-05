use std::collections::VecDeque;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Key for frequency tracking: (playbook_id, source_ip).
type FreqKey = (i64, String);

/// Lock-free frequency tracker using DashMap for concurrent per-IP event counting.
pub struct FrequencyTracker {
    events: DashMap<FreqKey, VecDeque<Instant>>,
    max_deque_size: usize,
    max_tracked_keys: usize,
    max_retention: Duration,
}

impl FrequencyTracker {
    pub fn new(max_tracked_keys: usize, max_events_per_key: usize, retention_secs: u64) -> Self {
        Self {
            events: DashMap::new(),
            max_deque_size: max_events_per_key.max(1),
            max_tracked_keys: max_tracked_keys.max(1),
            max_retention: Duration::from_secs(retention_secs.max(1)),
        }
    }

    /// Record an event and return the count of events within the given window.
    pub fn record_and_count(&self, playbook_id: i64, source_ip: &str, window_secs: u64) -> u64 {
        let key = (playbook_id, source_ip.to_string());
        let now = Instant::now();
        let window = Duration::from_secs(window_secs);

        let mut entry = self.events.entry(key).or_default();
        let deque = entry.value_mut();

        // Prune expired entries from the front
        while let Some(front) = deque.front() {
            if now.duration_since(*front) > window {
                deque.pop_front();
            } else {
                break;
            }
        }

        deque.push_back(now);

        // Cap deque size to prevent unbounded growth
        while deque.len() > self.max_deque_size {
            deque.pop_front();
        }

        deque.len() as u64
    }

    /// Remove empty deques and entries where all timestamps are outside the
    /// configured retention window.
    pub fn cleanup(&self) -> u32 {
        let now = Instant::now();
        let mut removed = 0u32;
        self.events.retain(|_, deque| {
            if deque.is_empty() {
                removed += 1;
                return false;
            }
            // If all entries are older than max_retention, remove the whole entry.
            if let Some(newest) = deque.back()
                && now.checked_duration_since(*newest).unwrap_or(Duration::ZERO) > self.max_retention
            {
                removed += 1;
                return false;
            }
            true
        });

        // Enforce max key cap to prevent unbounded growth under DDoS
        if self.events.len() > self.max_tracked_keys {
            let excess = self.events.len() - self.max_tracked_keys;
            let keys_to_remove: Vec<FreqKey> = self.events.iter().take(excess).map(|e| e.key().clone()).collect();
            for key in keys_to_remove {
                self.events.remove(&key);
                removed += 1;
            }
        }

        removed
    }
}

#[cfg(test)]
mod tests {
    use super::FrequencyTracker;

    #[test]
    fn record_and_count_respects_configured_per_key_cap() {
        let tracker = FrequencyTracker::new(10, 2, 60);

        assert_eq!(tracker.record_and_count(1, "10.0.0.1", 60), 1);
        assert_eq!(tracker.record_and_count(1, "10.0.0.1", 60), 2);
        assert_eq!(tracker.record_and_count(1, "10.0.0.1", 60), 2);
    }
}
