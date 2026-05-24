use std::cmp::Reverse;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use moka::sync::Cache;

use crate::core::inference::engine::Engine;
use crate::domain::data_plane::direction::Direction;
use crate::domain::data_plane::flow_stats::{
    FlowPushPayload, FlowStatsEntry, FlowStatsLimits, FlowSubscription, FlowSummary, StatsSummary,
};
use crate::domain::data_plane::ip_version::IpVersion;
use crate::domain::detection::flow_tracker::FlowData;

const FLOW_PAYLOAD_CACHE_MAX_ENTRIES: u64 = 256;

impl From<&FlowData> for FlowStatsEntry {
    fn from(flow: &FlowData) -> Self {
        Self {
            direction: flow.direction,
            ip_version: flow.flow_key.ip_version,
            src_ip: flow.flow_key.src_ip_string(),
            dst_ip: flow.flow_key.dst_ip_string(),
            src_port: flow.flow_key.src_port,
            dst_port: flow.flow_key.dst_port,
            protocol: flow.flow_key.protocol,
            fwd_packets: flow.fwd_packets.len(),
            bwd_packets: flow.bwd_packets.len(),
            fwd_bytes: flow.fwd_total_bytes,
            bwd_bytes: flow.bwd_total_bytes,
            duration_us: flow.duration_us(),
            last_seen_us: flow.last_time_us,
        }
    }
}

pub struct FlowStatistics {
    engine: Arc<Engine>,
    limits: FlowStatsLimits,
    payload_cache: Cache<FlowSnapshotKey, CachedFlowPayload>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowSnapshotKey {
    direction: Option<Direction>,
    window_secs: Option<u64>,
    top_n: Option<usize>,
}

impl FlowSnapshotKey {
    fn from_subscription(sub: &FlowSubscription) -> Self {
        Self {
            direction: sub.direction,
            window_secs: sub.window_secs,
            top_n: sub.top_n,
        }
    }
}

#[derive(Clone)]
struct CachedFlowPayload {
    generated_at: Instant,
    json: String,
}

impl FlowStatistics {
    pub fn new(engine: Arc<Engine>, limits: FlowStatsLimits) -> Self {
        Self {
            engine,
            limits,
            payload_cache: Cache::builder().max_capacity(FLOW_PAYLOAD_CACHE_MAX_ENTRIES).build(),
        }
    }

    pub fn get_all_flows(&self) -> Vec<FlowStatsEntry> {
        self.collect_flows(Some(self.limits.result_limit(None)))
    }

    fn collect_flows(&self, limit: Option<usize>) -> Vec<FlowStatsEntry> {
        let mut entries = Vec::new();
        for tracker in self.engine.trackers() {
            entries.extend(tracker.get_flow_stats(|flow| FlowStatsEntry::from(flow)));
            if let Some(limit) = limit
                && entries.len() >= limit
            {
                entries.truncate(limit);
                break;
            }
        }
        entries
    }

    pub fn get_filtered_flows(&self, sub: &FlowSubscription) -> Vec<FlowStatsEntry> {
        let now_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);

        let direction = sub.direction;
        let cutoff = sub
            .window_secs
            .map(|window_secs| flow_window_cutoff_us(now_us, window_secs));
        let mut flows = Vec::new();
        for tracker in self.engine.trackers() {
            flows.extend(tracker.get_filtered_flow_stats(
                |flow| {
                    direction.is_none_or(|dir| flow.direction == dir)
                        && cutoff.is_none_or(|cutoff| flow.last_time_us >= cutoff)
                },
                |flow| FlowStatsEntry::from(flow),
            ));
        }

        let limit = self.limits.result_limit(sub.top_n);
        if flows.len() > limit {
            flows.select_nth_unstable_by_key(limit, |f| Reverse(total_flow_bytes(f)));
            flows.truncate(limit);
        }
        flows.sort_by_key(|f| Reverse(total_flow_bytes(f)));

        flows
    }

    pub fn get_top_flows(&self, n: usize) -> Vec<FlowStatsEntry> {
        self.get_filtered_flows(&FlowSubscription {
            direction: None,
            window_secs: None,
            top_n: Some(n),
            interval_secs: None,
        })
    }

    pub fn get_flow_payload(&self, sub: &FlowSubscription) -> FlowPushPayload {
        let flows = self.get_filtered_flows(sub);
        let window_secs = sub.window_secs.unwrap_or(60).max(1);

        let mut ingress_bytes_v4: u64 = 0;
        let mut egress_bytes_v4: u64 = 0;
        let mut ingress_bytes_v6: u64 = 0;
        let mut egress_bytes_v6: u64 = 0;

        for f in &flows {
            let bytes = total_flow_bytes(f);
            match (f.direction, f.ip_version) {
                (Direction::Ingress, IpVersion::V6) => {
                    ingress_bytes_v6 = ingress_bytes_v6.saturating_add(bytes);
                }
                (Direction::Ingress, _) => {
                    ingress_bytes_v4 = ingress_bytes_v4.saturating_add(bytes);
                }
                (Direction::Egress, IpVersion::V6) => {
                    egress_bytes_v6 = egress_bytes_v6.saturating_add(bytes);
                }
                (Direction::Egress, _) => {
                    egress_bytes_v4 = egress_bytes_v4.saturating_add(bytes);
                }
            }
        }

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let summary = FlowSummary {
            ingress_bps_v4: ingress_bytes_v4 / window_secs,
            egress_bps_v4: egress_bytes_v4 / window_secs,
            ingress_bps_v6: ingress_bytes_v6 / window_secs,
            egress_bps_v6: egress_bytes_v6 / window_secs,
            total_flows: flows.len(),
            window_secs,
            timestamp_ms: now_ms,
        };

        FlowPushPayload { summary, flows }
    }

    pub fn get_flow_payload_json(
        &self,
        sub: &FlowSubscription,
        max_cache_age: Duration,
    ) -> Result<String, serde_json::Error> {
        let key = FlowSnapshotKey::from_subscription(sub);
        let now = Instant::now();
        if let Some(cached) = self.payload_cache.get(&key)
            && now.duration_since(cached.generated_at) <= max_cache_age
        {
            return Ok(cached.json);
        }

        let json = serde_json::to_string(&self.get_flow_payload(sub))?;
        self.payload_cache.insert(
            key,
            CachedFlowPayload {
                generated_at: now,
                json: json.clone(),
            },
        );
        Ok(json)
    }

    pub fn get_summary(&self) -> StatsSummary {
        let mut total_flows = 0usize;
        let mut total_bytes = 0u64;
        let mut total_packets = 0usize;

        for tracker in self.engine.trackers() {
            let (flows, bytes, packets) = tracker.summary_stats();
            total_flows += flows;
            total_bytes += bytes;
            total_packets += packets;
        }

        StatsSummary {
            total_flows,
            total_bytes,
            total_packets,
        }
    }
}

fn flow_window_cutoff_us(now_us: u64, window_secs: u64) -> u64 {
    now_us.saturating_sub(window_secs.saturating_mul(1_000_000))
}

fn total_flow_bytes(flow: &FlowStatsEntry) -> u64 {
    flow.fwd_bytes.saturating_add(flow.bwd_bytes)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn flow_window_cutoff_uses_saturating_arithmetic() {
        assert_eq!(flow_window_cutoff_us(10_000_000, 5), 5_000_000);
        assert_eq!(flow_window_cutoff_us(10_000_000, u64::MAX), 0);
    }

    #[test]
    fn flow_payload_cache_has_bounded_key_cardinality() {
        let now = Instant::now();
        let cache = Cache::builder().max_capacity(FLOW_PAYLOAD_CACHE_MAX_ENTRIES).build();

        for i in 0..(FLOW_PAYLOAD_CACHE_MAX_ENTRIES + 10) {
            cache.insert(
                FlowSnapshotKey {
                    direction: None,
                    window_secs: Some(i),
                    top_n: Some(i as usize),
                },
                CachedFlowPayload {
                    generated_at: now,
                    json: format!("payload-{i}"),
                },
            );
        }
        cache.run_pending_tasks();

        assert!(cache.entry_count() <= FLOW_PAYLOAD_CACHE_MAX_ENTRIES);
    }

    #[test]
    fn total_flow_bytes_saturates_on_counter_overflow() {
        let flow = FlowStatsEntry {
            direction: Direction::Ingress,
            ip_version: IpVersion::V4,
            src_ip: "192.0.2.1".to_string(),
            dst_ip: "198.51.100.1".to_string(),
            src_port: 1,
            dst_port: 2,
            protocol: 6,
            fwd_packets: 1,
            bwd_packets: 1,
            fwd_bytes: u64::MAX,
            bwd_bytes: 1,
            duration_us: 1,
            last_seen_us: 1,
        };

        assert_eq!(total_flow_bytes(&flow), u64::MAX);
    }
}
