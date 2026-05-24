use std::collections::VecDeque;
use std::time::{Duration, Instant};

use dashmap::DashMap;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FreqKey {
    playbook_id: i64,
    source_ip: String,
}

struct FrequencyEntry {
    events: VecDeque<Instant>,
    last_seen: Instant,
}

impl FrequencyEntry {
    fn new(now: Instant) -> Self {
        Self {
            events: VecDeque::new(),
            last_seen: now,
        }
    }
}

pub struct FrequencyTracker {
    events: DashMap<FreqKey, FrequencyEntry>,
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

    pub fn record_and_count(&self, playbook_id: i64, source_ip: &str, window_secs: u64) -> u64 {
        let key = FreqKey {
            playbook_id,
            source_ip: source_ip.to_string(),
        };
        let now = Instant::now();
        let window = Duration::from_secs(window_secs);

        let count = {
            let mut entry = self
                .events
                .entry(key.clone())
                .or_insert_with(|| FrequencyEntry::new(now));
            let entry = entry.value_mut();
            entry.last_seen = now;
            let deque = &mut entry.events;

            while let Some(front) = deque.front() {
                if now.duration_since(*front) > window {
                    deque.pop_front();
                } else {
                    break;
                }
            }

            deque.push_back(now);

            while deque.len() > self.max_deque_size {
                deque.pop_front();
            }

            deque.len() as u64
        };

        if self.events.len() > self.max_tracked_keys {
            self.evict_oldest_excluding(self.events.len() - self.max_tracked_keys, &key);
        }

        count
    }

    pub fn cleanup(&self) -> u32 {
        let now = Instant::now();
        let mut removed = 0u32;
        self.events.retain(|_, entry| {
            if entry.events.is_empty() {
                removed += 1;
                return false;
            }
            if let Some(newest) = entry.events.back()
                && now.checked_duration_since(*newest).unwrap_or(Duration::ZERO) > self.max_retention
            {
                removed += 1;
                return false;
            }
            true
        });

        if self.events.len() > self.max_tracked_keys {
            let excess = self.events.len() - self.max_tracked_keys;
            removed += self.evict_oldest(excess);
        }

        removed
    }

    fn evict_oldest(&self, count: usize) -> u32 {
        self.evict_oldest_inner(count, None)
    }

    fn evict_oldest_excluding(&self, count: usize, exclude: &FreqKey) -> u32 {
        self.evict_oldest_inner(count, Some(exclude))
    }

    fn evict_oldest_inner(&self, count: usize, exclude: Option<&FreqKey>) -> u32 {
        let mut entries: Vec<(FreqKey, Instant)> = self
            .events
            .iter()
            .filter(|entry| exclude.is_none_or(|ex| entry.key() != ex))
            .map(|entry| (entry.key().clone(), entry.last_seen))
            .collect();
        if count < entries.len() {
            entries.select_nth_unstable_by_key(count, |(_, last_seen)| *last_seen);
        }

        let mut removed = 0;
        for (key, _) in entries.into_iter().take(count) {
            if self.events.remove(&key).is_some() {
                removed += 1;
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use super::FrequencyTracker;

    #[test]
    fn record_and_count_respects_configured_per_key_cap() {
        let tracker = FrequencyTracker::new(10, 2, 60);

        assert_eq!(tracker.record_and_count(1, "10.0.0.1", 60), 1);
        assert_eq!(tracker.record_and_count(1, "10.0.0.1", 60), 2);
        assert_eq!(tracker.record_and_count(1, "10.0.0.1", 60), 2);
    }

    #[test]
    fn key_cap_evicts_oldest_entries() {
        let tracker = FrequencyTracker::new(2, 2, 60);

        tracker.record_and_count(1, "10.0.0.1", 60);
        thread::sleep(Duration::from_millis(1));
        tracker.record_and_count(1, "10.0.0.2", 60);
        thread::sleep(Duration::from_millis(1));
        tracker.record_and_count(1, "10.0.0.3", 60);

        assert_eq!(tracker.events.len(), 2);
        assert!(
            !tracker
                .events
                .iter()
                .any(|entry| entry.key().playbook_id == 1 && entry.key().source_ip == "10.0.0.1")
        );
    }
}
