use std::hash::Hash;
use std::time::{Duration, Instant};

use dashmap::DashMap;

pub fn capped_cleanup<K: Eq + Hash + Clone, V>(
    map: &DashMap<K, V>,
    window: Duration,
    max_tracked: usize,
    window_start: impl Fn(&V) -> Instant,
) -> usize {
    let now = Instant::now();
    let before = map.len();

    map.retain(|_, v| now.duration_since(window_start(v)) < window);

    if map.len() > max_tracked {
        let excess = map.len() - max_tracked;
        let keys_to_remove: Vec<K> = map.iter().take(excess).map(|e| e.key().clone()).collect();
        for key in keys_to_remove {
            map.remove(&key);
        }
    }

    before.saturating_sub(map.len())
}
