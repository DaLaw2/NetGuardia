use super::flow_record::FlowRecord;
use serde::{Deserialize, Serialize};

/// CIC-IDS2017 Feature Set (80 features, truncated from full 83)
/// Note: Full CIC-IDS2017 has 83 features, but many datasets/models use 80
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CicFeatures {
    pub features: Vec<f64>,
}

impl CicFeatures {
    /// Extract CIC-IDS features from a flow record (returns 80 features)
    pub fn extract(flow: &FlowRecord) -> Self {
        let mut features = Vec::with_capacity(83);

        // 1. Flow Duration (microseconds)
        features.push(flow.duration() as f64);

        // 2-3. Total Fwd/Bwd Packets
        features.push(flow.forward.packets as f64);
        features.push(flow.backward.packets as f64);

        // 4-5. Total Length of Fwd/Bwd Packets
        features.push(flow.forward.bytes as f64);
        features.push(flow.backward.bytes as f64);

        // 6-9. Fwd Packet Length Max/Min/Mean/Std
        let fwd_stats = Self::calculate_stats(&flow.forward.packet_lengths);
        features.push(fwd_stats.max);
        features.push(fwd_stats.min);
        features.push(fwd_stats.mean);
        features.push(fwd_stats.std);

        // 10-13. Bwd Packet Length Max/Min/Mean/Std
        let bwd_stats = Self::calculate_stats(&flow.backward.packet_lengths);
        features.push(bwd_stats.max);
        features.push(bwd_stats.min);
        features.push(bwd_stats.mean);
        features.push(bwd_stats.std);

        // 14. Flow Bytes/s
        let duration_sec = (flow.duration() as f64) / 1_000_000.0;
        let total_bytes = flow.forward.bytes + flow.backward.bytes;
        features.push(if duration_sec > 0.0 {
            total_bytes as f64 / duration_sec
        } else {
            0.0
        });

        // 15. Flow Packets/s
        let total_packets = flow.forward.packets + flow.backward.packets;
        features.push(if duration_sec > 0.0 {
            total_packets as f64 / duration_sec
        } else {
            0.0
        });

        // 16-19. Flow IAT Mean/Std/Max/Min
        let mut all_iats = flow.forward.iats.clone();
        all_iats.extend(&flow.backward.iats);
        let flow_iat_stats = Self::calculate_stats_u64(&all_iats);
        features.push(flow_iat_stats.mean);
        features.push(flow_iat_stats.std);
        features.push(flow_iat_stats.max);
        features.push(flow_iat_stats.min);

        // 20-24. Fwd IAT Total/Mean/Std/Max/Min
        let fwd_iat_stats = Self::calculate_stats_u64(&flow.forward.iats);
        features.push(flow.forward.iats.iter().sum::<u64>() as f64);
        features.push(fwd_iat_stats.mean);
        features.push(fwd_iat_stats.std);
        features.push(fwd_iat_stats.max);
        features.push(fwd_iat_stats.min);

        // 25-29. Bwd IAT Total/Mean/Std/Max/Min
        let bwd_iat_stats = Self::calculate_stats_u64(&flow.backward.iats);
        features.push(flow.backward.iats.iter().sum::<u64>() as f64);
        features.push(bwd_iat_stats.mean);
        features.push(bwd_iat_stats.std);
        features.push(bwd_iat_stats.max);
        features.push(bwd_iat_stats.min);

        // 30-31. Fwd/Bwd PSH Flags
        features.push(flow.forward.psh_flags as f64);
        features.push(flow.backward.psh_flags as f64);

        // 32-33. Fwd/Bwd URG Flags
        features.push(flow.forward.urg_flags as f64);
        features.push(flow.backward.urg_flags as f64);

        // 34-35. Fwd/Bwd Header Length
        features.push(flow.forward.header_bytes as f64);
        features.push(flow.backward.header_bytes as f64);

        // 36-37. Fwd/Bwd Packets/s
        features.push(if duration_sec > 0.0 {
            flow.forward.packets as f64 / duration_sec
        } else {
            0.0
        });
        features.push(if duration_sec > 0.0 {
            flow.backward.packets as f64 / duration_sec
        } else {
            0.0
        });

        // 38-42. Min/Max/Mean/Std/Variance Packet Length
        let all_lengths: Vec<u32> = flow
            .forward
            .packet_lengths
            .iter()
            .chain(&flow.backward.packet_lengths)
            .copied()
            .collect();
        let all_stats = Self::calculate_stats(&all_lengths);
        features.push(all_stats.min);
        features.push(all_stats.max);
        features.push(all_stats.mean);
        features.push(all_stats.std);
        features.push(all_stats.variance);

        // 43-50. FIN/SYN/RST/PSH/ACK/URG/CWE/ECE Flag Count
        features.push(flow.tcp_flags.fin as f64);
        features.push(flow.tcp_flags.syn as f64);
        features.push(flow.tcp_flags.rst as f64);
        features.push(flow.tcp_flags.psh as f64);
        features.push(flow.tcp_flags.ack as f64);
        features.push(flow.tcp_flags.urg as f64);
        features.push(flow.tcp_flags.cwe as f64);
        features.push(flow.tcp_flags.ece as f64);

        // 51. Down/Up Ratio
        let down_up_ratio = if flow.forward.packets > 0 {
            flow.backward.packets as f64 / flow.forward.packets as f64
        } else {
            0.0
        };
        features.push(down_up_ratio);

        // 52. Average Packet Size
        features.push(if total_packets > 0 {
            total_bytes as f64 / total_packets as f64
        } else {
            0.0
        });

        // 53-54. Avg Fwd/Bwd Segment Size
        features.push(if flow.forward.packets > 0 {
            flow.forward.bytes as f64 / flow.forward.packets as f64
        } else {
            0.0
        });
        features.push(if flow.backward.packets > 0 {
            flow.backward.bytes as f64 / flow.backward.packets as f64
        } else {
            0.0
        });

        // 55. Fwd Header Length (redundant with 34, but kept for compatibility)
        features.push(flow.forward.header_bytes as f64);

        // 56-58. Fwd Avg Bytes/Packets/Rate per Bulk
        features.push(Self::avg_bulk_bytes(&flow.fwd_bulk_state));
        features.push(Self::avg_bulk_packets(&flow.fwd_bulk_state));
        features.push(Self::avg_bulk_rate(&flow.fwd_bulk_state, duration_sec));

        // 59-61. Bwd Avg Bytes/Packets/Rate per Bulk
        features.push(Self::avg_bulk_bytes(&flow.bwd_bulk_state));
        features.push(Self::avg_bulk_packets(&flow.bwd_bulk_state));
        features.push(Self::avg_bulk_rate(&flow.bwd_bulk_state, duration_sec));

        // 62-65. Subflow Fwd/Bwd Packets/Bytes
        features.push(flow.forward.packets as f64);
        features.push(flow.forward.bytes as f64);
        features.push(flow.backward.packets as f64);
        features.push(flow.backward.bytes as f64);

        // 66-67. Init_Win_bytes_forward/backward (TCP window size)
        // Note: In real implementation, extract from first SYN packet
        features.push(0.0); // Placeholder
        features.push(0.0); // Placeholder

        // 68. act_data_pkt_fwd (Active data packets in forward direction)
        let act_data_pkt_fwd = flow.forward.packets.saturating_sub(flow.tcp_flags.syn as u64);
        features.push(act_data_pkt_fwd as f64);

        // 69. min_seg_size_forward (Minimum segment size in forward direction)
        features.push(fwd_stats.min);

        // 70-73. Active Mean/Std/Max/Min
        let active_stats = Self::calculate_stats_u64(&flow.active_times);
        features.push(active_stats.mean);
        features.push(active_stats.std);
        features.push(active_stats.max);
        features.push(active_stats.min);

        // 74-77. Idle Mean/Std/Max/Min
        let idle_stats = Self::calculate_stats_u64(&flow.idle_times);
        features.push(idle_stats.mean);
        features.push(idle_stats.std);
        features.push(idle_stats.max);
        features.push(idle_stats.min);

        // 78-83. Additional features (may vary by dataset)
        // Using header lengths and packet counts as placeholders
        features.push(flow.forward.header_bytes as f64);  // 78
        features.push(flow.backward.header_bytes as f64); // 79
        features.push(total_packets as f64);              // 80
        features.push(total_bytes as f64);                // 81
        features.push(duration_sec);                      // 82
        features.push(0.0);                               // 83 - Reserved

        assert_eq!(features.len(), 83, "Expected 83 features");

        // Truncate to 80 features to match the model's expectation
        // (Some CIC-IDS2017 datasets use 80 features instead of full 83)
        features.truncate(80);

        CicFeatures { features }
    }

    // Helper: Calculate basic statistics for u32 values
    fn calculate_stats(values: &[u32]) -> Stats {
        if values.is_empty() {
            return Stats::default();
        }

        let n = values.len() as f64;
        let sum: u64 = values.iter().map(|&x| x as u64).sum();
        let mean = sum as f64 / n;

        let variance = values
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / n;

        let std = variance.sqrt();

        let max = values.iter().max().copied().unwrap_or(0) as f64;
        let min = values.iter().min().copied().unwrap_or(0) as f64;

        Stats {
            mean,
            std,
            variance,
            max,
            min,
        }
    }

    // Helper: Calculate basic statistics for u64 values
    fn calculate_stats_u64(values: &[u64]) -> Stats {
        if values.is_empty() {
            return Stats::default();
        }

        let n = values.len() as f64;
        let sum: u64 = values.iter().sum();
        let mean = sum as f64 / n;

        let variance = values
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / n;

        let std = variance.sqrt();

        let max = values.iter().max().copied().unwrap_or(0) as f64;
        let min = values.iter().min().copied().unwrap_or(0) as f64;

        Stats {
            mean,
            std,
            variance,
            max,
            min,
        }
    }

    // Helper: Average bulk bytes
    fn avg_bulk_bytes(bulk: &super::flow_record::BulkState) -> f64 {
        if bulk.bulk_count > 0 {
            bulk.bulk_bytes as f64 / bulk.bulk_count as f64
        } else {
            0.0
        }
    }

    // Helper: Average bulk packets
    fn avg_bulk_packets(bulk: &super::flow_record::BulkState) -> f64 {
        if bulk.bulk_count > 0 {
            bulk.bulk_packets as f64 / bulk.bulk_count as f64
        } else {
            0.0
        }
    }

    // Helper: Average bulk rate
    fn avg_bulk_rate(bulk: &super::flow_record::BulkState, duration_sec: f64) -> f64 {
        if duration_sec > 0.0 && bulk.bulk_count > 0 {
            bulk.bulk_count as f64 / duration_sec
        } else {
            0.0
        }
    }

    /// Convert to JSON-serializable format for WebSocket
    pub fn to_vec(&self) -> Vec<f64> {
        self.features.clone()
    }

    /// Get feature count
    pub fn len(&self) -> usize {
        self.features.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }
}

/// Statistics helper struct
#[derive(Debug, Clone, Default)]
struct Stats {
    mean: f64,
    std: f64,
    variance: f64,
    max: f64,
    min: f64,
}
