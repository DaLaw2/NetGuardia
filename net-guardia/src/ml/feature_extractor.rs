use crate::model::ml_detection::PacketData;
use super::flow_tracker::FlowData;

#[derive(Debug, Clone)]
pub struct FlowFeatures {
    pub features: Vec<f64>,
    pub feature_num: usize,
}

impl FlowFeatures {
    pub fn extract(flow: &FlowData, feature_num: usize) -> Self {
        let mut features = vec![0.0; feature_num];

        let mut set_feature = |idx: usize, val: f64| {
            if idx < feature_num {
                features[idx] = val;
            }
        };

        let safe_div = |a: f64, b: f64| if b > 0.0 { a / b } else { 0.0 };

        let fwd_count = flow.fwd_packets.len() as f64;
        let bwd_count = flow.bwd_packets.len() as f64;
        let total_count = fwd_count + bwd_count;

        let duration_us = flow.duration_us() as f64;
        let duration_s = duration_us / 1_000_000.0;
        let duration_s = if duration_s > 0.0 { duration_s } else { 1e-6 };

        set_feature(0, flow.flow_key.dst_port as f64);
        set_feature(1, duration_us);
        set_feature(2, fwd_count);
        set_feature(3, bwd_count);
        set_feature(4, flow.fwd_total_bytes as f64);
        set_feature(5, flow.bwd_total_bytes as f64);

        let fwd_lengths: Vec<f64> = flow.fwd_packets.iter().map(|p| p.length as f64).collect();
        let (fwd_max, fwd_min, fwd_mean, fwd_std) = compute_stats(&fwd_lengths);

        set_feature(6, fwd_max);
        set_feature(7, fwd_min);
        set_feature(8, fwd_mean);
        set_feature(9, fwd_std);

        let bwd_lengths: Vec<f64> = flow.bwd_packets.iter().map(|p| p.length as f64).collect();
        let (bwd_max, bwd_min, bwd_mean, bwd_std) = compute_stats(&bwd_lengths);

        set_feature(10, bwd_max);
        set_feature(11, bwd_min);
        set_feature(12, bwd_mean);
        set_feature(13, bwd_std);

        let total_bytes = (flow.fwd_total_bytes + flow.bwd_total_bytes) as f64;

        set_feature(14, total_bytes / duration_s);
        set_feature(15, total_count / duration_s);

        let flow_iats = compute_flow_iats(&flow.fwd_packets, &flow.bwd_packets);
        let (flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min) = compute_stats(&flow_iats);

        set_feature(16, flow_iat_mean);
        set_feature(17, flow_iat_std);
        set_feature(18, flow_iat_max);
        set_feature(19, flow_iat_min);

        let fwd_iats = compute_iats(&flow.fwd_packets);
        let fwd_iat_total: f64 = fwd_iats.iter().sum();
        let (fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min) = compute_stats(&fwd_iats);

        set_feature(20, fwd_iat_total);
        set_feature(21, fwd_iat_mean);
        set_feature(22, fwd_iat_std);
        set_feature(23, fwd_iat_max);
        set_feature(24, fwd_iat_min);

        let bwd_iats = compute_iats(&flow.bwd_packets);
        let bwd_iat_total: f64 = bwd_iats.iter().sum();
        let (bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min) = compute_stats(&bwd_iats);

        set_feature(20, bwd_iat_total);
        set_feature(21, bwd_iat_mean);
        set_feature(22, bwd_iat_std);
        set_feature(23, bwd_iat_max);
        set_feature(24, bwd_iat_min);

        let fwd_psh = flow.fwd_packets.iter().filter(|p| p.flags.psh).count() as f64;
        let bwd_psh = flow.bwd_packets.iter().filter(|p| p.flags.psh).count() as f64;
        let fwd_urg = flow.fwd_packets.iter().filter(|p| p.flags.urg).count() as f64;
        let bwd_urg = flow.bwd_packets.iter().filter(|p| p.flags.urg).count() as f64;

        set_feature(30, fwd_psh);
        set_feature(31, bwd_psh);
        set_feature(32, fwd_urg);
        set_feature(33, bwd_urg);
        set_feature(34, flow.fwd_header_bytes as f64);
        set_feature(35, flow.bwd_header_bytes as f64);
        set_feature(36, fwd_count / duration_s);
        set_feature(37, bwd_count / duration_s);

        let all_lengths: Vec<f64> = flow
            .fwd_packets
            .iter()
            .chain(flow.bwd_packets.iter())
            .map(|p| p.length as f64)
            .collect();

        let (max_len, min_len, mean_len, std_len) = compute_stats(&all_lengths);

        set_feature(38, min_len);
        set_feature(39, max_len);
        set_feature(40, mean_len);
        set_feature(41, std_len);
        set_feature(42, std_len * std_len);

        set_feature(43, flow.fin_count as f64);
        set_feature(44, flow.syn_count as f64);
        set_feature(45, flow.rst_count as f64);
        set_feature(46, flow.psh_count as f64);
        set_feature(47, flow.ack_count as f64);
        set_feature(48, flow.urg_count as f64);
        set_feature(49, flow.cwe_count as f64);
        set_feature(50, flow.ece_count as f64);

        set_feature(51, safe_div(bwd_count, fwd_count));
        set_feature(52, safe_div(total_bytes, total_count));
        set_feature(53, safe_div(flow.fwd_total_bytes as f64, fwd_count));
        set_feature(54, safe_div(flow.bwd_total_bytes as f64, bwd_count));

        set_feature(55, flow.fwd_header_bytes as f64);

        let fwd_bulk = &flow.fwd_bulk_state;
        let bwd_bulk = &flow.bwd_bulk_state;

        set_feature(56, safe_div(fwd_bulk.total_bytes as f64, fwd_bulk.bulk_count as f64));
        set_feature(57, safe_div(fwd_bulk.total_packets as f64, fwd_bulk.bulk_count as f64));
        set_feature(58, safe_div(fwd_bulk.total_bytes as f64, duration_s));

        set_feature(59, safe_div(bwd_bulk.total_bytes as f64, bwd_bulk.bulk_count as f64));
        set_feature(60, safe_div(bwd_bulk.total_packets as f64, bwd_bulk.bulk_count as f64));
        set_feature(61, safe_div(bwd_bulk.total_bytes as f64, duration_s));

        set_feature(62, fwd_count);
        set_feature(63, flow.fwd_total_bytes as f64);
        set_feature(64, bwd_count);
        set_feature(65, flow.bwd_total_bytes as f64);
        set_feature(66, flow.init_win_bytes_fwd as f64);
        set_feature(67, flow.init_win_bytes_bwd as f64);

        let fwd_seg_sizes: Vec<f64> = flow.fwd_packets
            .iter()
            .filter(|p| p.payload_length > 0)
            .map(|p| p.header_length as f64)
            .collect();

        set_feature(68, fwd_seg_sizes.len() as f64);
        set_feature(69, fwd_seg_sizes.iter()
            .min_by(|a, b| a.total_cmp(b))
            .copied()
            .unwrap_or(0.0)
        );

        let (active_mean, active_std, active_max, active_min) = compute_stats(
            &flow
                .active_periods
                .iter()
                .map(|&x| x as f64)
                .collect::<Vec<_>>(),
        );

        set_feature(70, active_mean);
        set_feature(71, active_std);
        set_feature(72, active_max);
        set_feature(73, active_min);

        let (idle_mean, idle_std, idle_max, idle_min) = compute_stats(
            &flow
                .idle_periods
                .iter()
                .map(|&x| x as f64)
                .collect::<Vec<_>>(),
        );

        set_feature(74, idle_mean);
        set_feature(75, idle_std);
        set_feature(76, idle_max);
        set_feature(77, idle_min);

        Self { features, feature_num }
    }

    pub fn normalize(&mut self, means: &[f64], stds: &[f64]) {
        for i in 0..self.feature_num {
            if stds[i] > 0.0 {
                self.features[i] = (self.features[i] - means[i]) / stds[i];
            } else {
                self.features[i] = 0.0;
            }
        }
    }

    pub fn clip(&mut self, clip_min: f64, clip_max: f64) {
        for i in 0..self.feature_num {
            self.features[i] = self.features[i].max(clip_min).min(clip_max);
        }
    }
}

fn compute_stats(values: &[f64]) -> (f64, f64, f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0, 0.0, 0.0);
    }

    let n = values.len() as f64;
    let sum: f64 = values.iter().sum();
    let mean = sum / n;

    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let min = values.iter().cloned().fold(f64::INFINITY, f64::min);

    let variance: f64 = values.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
    let std = variance.sqrt();

    (max, min, mean, std)
}

fn compute_iats(packets: &[PacketData]) -> Vec<f64> {
    if packets.len() < 2 {
        return vec![0.0];
    }

    packets
        .windows(2)
        .map(|w| (w[1].timestamp_us - w[0].timestamp_us) as f64)
        .collect()
}

fn compute_flow_iats(fwd_packets: &[PacketData], bwd_packets: &[PacketData]) -> Vec<f64> {
    let mut all_packets: Vec<&PacketData> = fwd_packets.iter().chain(bwd_packets.iter()).collect();
    all_packets.sort_by_key(|p| p.timestamp_us);

    if all_packets.len() < 2 {
        return vec![0.0];
    }

    all_packets
        .windows(2)
        .map(|w| (w[1].timestamp_us - w[0].timestamp_us) as f64)
        .collect()
}