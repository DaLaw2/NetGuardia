use std::collections::VecDeque;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Key for frequency tracking: (playbook_id, source_ip).
type FreqKey = (i64, String);

/// Maximum tracked keys to bound memory under DDoS.
const MAX_TRACKED_KEYS: usize = 50_000;

/// Lock-free frequency tracker using DashMap for concurrent per-IP event counting.
pub struct FrequencyTracker {
    events: DashMap<FreqKey, VecDeque<Instant>>,
    max_deque_size: usize,
}

impl FrequencyTracker {
    pub fn new() -> Self {
        Self {
            events: DashMap::new(),
            max_deque_size: 200,
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

    /// Remove empty deques and entries where all timestamps are expired.
    /// Uses a conservative 2-hour max window for expiry detection.
    pub fn cleanup(&self) -> u32 {
        let now = Instant::now();
        let max_window = Duration::from_secs(7200); // 2 hours — conservative upper bound
        let mut removed = 0u32;
        self.events.retain(|_, deque| {
            if deque.is_empty() {
                removed += 1;
                return false;
            }
            // If all entries are older than max_window, remove the whole entry
            if let Some(newest) = deque.back()
                && now.checked_duration_since(*newest).unwrap_or(Duration::ZERO) > max_window
            {
                removed += 1;
                return false;
            }
            true
        });

        // Enforce max key cap to prevent unbounded growth under DDoS
        if self.events.len() > MAX_TRACKED_KEYS {
            let excess = self.events.len() - MAX_TRACKED_KEYS;
            let keys_to_remove: Vec<FreqKey> = self.events.iter().take(excess).map(|e| e.key().clone()).collect();
            for key in keys_to_remove {
                self.events.remove(&key);
                removed += 1;
            }
        }

        removed
    }
}
