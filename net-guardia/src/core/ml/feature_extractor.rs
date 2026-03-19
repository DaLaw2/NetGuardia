use std::collections::HashMap;

use common::define::tcp_flags::*;

use super::flow_tracker::FlowData;
use crate::model::ml_detection::{ClipParams, PacketData};

#[derive(Debug, Clone)]
pub struct FlowFeatures {
    pub features: Vec<f64>,
    pub feature_num: usize,
}

impl FlowFeatures {
    pub fn extract(flow: &FlowData, feature_names: &[String]) -> Self {
        let feature_num = feature_names.len();
        let mut features = Vec::with_capacity(feature_num);

        for name in feature_names {
            let value = Self::get_feature_by_name(flow, name.trim());
            features.push(value);
        }

        Self { features, feature_num }
    }

    fn get_feature_by_name(flow: &FlowData, feature_name: &str) -> f64 {
        let safe_div = |a: f64, b: f64| if b > 0.0 { a / b } else { 0.0 };

        // 1-5
        let fwd_count = flow.fwd_packets.len() as f64;
        let bwd_count = flow.bwd_packets.len() as f64;
        let total_count = fwd_count + bwd_count;

        let duration_us = flow.duration_us() as f64;
        let duration_s = duration_us / 1_000_000.0;
        let duration_s = if duration_s > 0.0 { duration_s } else { 1e-6 };

        // 6-9
        let fwd_lengths: Vec<f64> = flow.fwd_packets.iter().map(|p| p.length as f64).collect();
        let (fwd_max, fwd_min, fwd_mean, fwd_std) = compute_stats(&fwd_lengths);

        // 10-13
        let bwd_lengths: Vec<f64> = flow.bwd_packets.iter().map(|p| p.length as f64).collect();
        let (bwd_max, bwd_min, bwd_mean, bwd_std) = compute_stats(&bwd_lengths);

        // 14-15
        let total_bytes = (flow.fwd_total_bytes + flow.bwd_total_bytes) as f64;

        // 16-19
        let flow_iats = compute_flow_iats(&flow.fwd_packets, &flow.bwd_packets);
        let (flow_iat_max, flow_iat_min, flow_iat_mean, flow_iat_std) = compute_stats(&flow_iats);

        // 20-24
        let fwd_iats = compute_iats(&flow.fwd_packets);
        let fwd_iat_total: f64 = fwd_iats.iter().sum();
        let (fwd_iat_max, fwd_iat_min, fwd_iat_mean, fwd_iat_std) = compute_stats(&fwd_iats);

        // 25-29
        let bwd_iats = compute_iats(&flow.bwd_packets);
        let bwd_iat_total: f64 = bwd_iats.iter().sum();
        let (bwd_iat_max, bwd_iat_min, bwd_iat_mean, bwd_iat_std) = compute_stats(&bwd_iats);

        // 30-37
        let fwd_psh = flow.fwd_packets.iter().filter(|p| p.flags & TCP_PSH != 0).count() as f64;
        let bwd_psh = flow.bwd_packets.iter().filter(|p| p.flags & TCP_PSH != 0).count() as f64;
        let fwd_urg = flow.fwd_packets.iter().filter(|p| p.flags & TCP_URG != 0).count() as f64;
        let bwd_urg = flow.bwd_packets.iter().filter(|p| p.flags & TCP_URG != 0).count() as f64;

        // 38-55
        let all_lengths: Vec<f64> = flow
            .fwd_packets
            .iter()
            .chain(flow.bwd_packets.iter())
            .map(|p| p.length as f64)
            .collect();

        let (max_len, min_len, mean_len, std_len) = compute_stats(&all_lengths);

        // 56-67
        let fwd_bulk = &flow.fwd_bulk_state;
        let bwd_bulk = &flow.bwd_bulk_state;

        // 68-69
        let fwd_seg_sizes: Vec<f64> = flow
            .fwd_packets
            .iter()
            .filter(|p| p.payload_length > 0)
            .map(|p| p.payload_length as f64)
            .collect();

        // 70-73
        let (active_max, active_min, active_mean, active_std) =
            compute_stats(&flow.active_periods.iter().map(|&x| x as f64).collect::<Vec<_>>());

        // 74-77
        let (idle_max, idle_min, idle_mean, idle_std) =
            compute_stats(&flow.idle_periods.iter().map(|&x| x as f64).collect::<Vec<_>>());

        match feature_name {
            "Destination Port" | "Dst Port" | "dst_port" => flow.flow_key.dst_port as f64,
            "Protocol" | "protocol" => flow.flow_key.protocol as f64,
            "Flow Duration" | "flow_duration" => duration_us,
            "Total Fwd Packets" | "Tot Fwd Pkts" | "fwd_packets" => fwd_count,
            "Total Backward Packets" | "Tot Bwd Pkts" | "bwd_packets" => bwd_count,
            "Total Length of Fwd Packets" | "TotLen Fwd Pkts" | "fwd_bytes" => flow.fwd_total_bytes as f64,
            "Total Length of Bwd Packets" | "TotLen Bwd Pkts" | "bwd_bytes" => flow.bwd_total_bytes as f64,
            "Fwd Packet Length Max" => fwd_max,
            "Fwd Packet Length Min" => fwd_min,
            "Fwd Packet Length Mean" | "Fwd Pkt Len Mean" | "fwd_pkt_len_mean" => fwd_mean,
            "Fwd Packet Length Std" | "Fwd Pkt Len Std" | "fwd_pkt_len_std" => fwd_std,
            "Bwd Packet Length Max" => bwd_max,
            "Bwd Packet Length Min" => bwd_min,
            "Bwd Packet Length Mean" | "Bwd Pkt Len Mean" | "bwd_pkt_len_mean" => bwd_mean,
            "Bwd Packet Length Std" | "Bwd Pkt Len Std" | "bwd_pkt_len_std" => bwd_std,
            "Flow Bytes/s" | "Flow Byts/s" | "flow_bytes_per_sec" => safe_div(total_bytes, duration_s),
            "Flow Packets/s" | "Flow Pkts/s" | "flow_pkts_per_sec" => safe_div(total_count, duration_s),
            "Flow IAT Mean" | "flow_iat_mean" => flow_iat_mean,
            "Flow IAT Std" => flow_iat_std,
            "Flow IAT Max" => flow_iat_max,
            "Flow IAT Min" => flow_iat_min,
            "Fwd IAT Total" => fwd_iat_total,
            "Fwd IAT Mean" | "fwd_iat_mean" => fwd_iat_mean,
            "Fwd IAT Std" => fwd_iat_std,
            "Fwd IAT Max" => fwd_iat_max,
            "Fwd IAT Min" => fwd_iat_min,
            "Bwd IAT Total" => bwd_iat_total,
            "Bwd IAT Mean" | "bwd_iat_mean" => bwd_iat_mean,
            "Bwd IAT Std" => bwd_iat_std,
            "Bwd IAT Max" => bwd_iat_max,
            "Bwd IAT Min" => bwd_iat_min,
            "Fwd PSH Flags" => fwd_psh,
            "Bwd PSH Flags" => bwd_psh,
            "Fwd URG Flags" => fwd_urg,
            "Bwd URG Flags" => bwd_urg,
            "Fwd Header Length" => flow.fwd_header_bytes as f64,
            "Bwd Header Length" => flow.bwd_header_bytes as f64,
            "Fwd Packets/s" => safe_div(fwd_count, duration_s),
            "Bwd Packets/s" => safe_div(bwd_count, duration_s),
            "Min Packet Length" => min_len,
            "Max Packet Length" => max_len,
            "Packet Length Mean" | "Pkt Len Mean" | "pkt_len_mean" => mean_len,
            "Packet Length Std" | "Pkt Len Std" | "pkt_len_std" => std_len,
            "Packet Length Variance" => std_len * std_len,
            "FIN Flag Count" | "FIN Flag Cnt" | "fin_flag_cnt" => flow.fin_count as f64,
            "SYN Flag Count" | "SYN Flag Cnt" | "syn_flag_cnt" => flow.syn_count as f64,
            "RST Flag Count" | "RST Flag Cnt" | "rst_flag_cnt" => flow.rst_count as f64,
            "PSH Flag Count" | "PSH Flag Cnt" | "psh_flag_cnt" => flow.psh_count as f64,
            "ACK Flag Count" | "ACK Flag Cnt" | "ack_flag_cnt" => flow.ack_count as f64,
            "URG Flag Count" => flow.urg_count as f64,
            "CWE Flag Count" => flow.cwe_count as f64,
            "ECE Flag Count" => flow.ece_count as f64,
            "Down/Up Ratio" => safe_div(bwd_count, fwd_count),
            "Average Packet Size" => safe_div(total_bytes, total_count),
            "Avg Fwd Segment Size" => safe_div(flow.fwd_total_bytes as f64, fwd_count),
            "Avg Bwd Segment Size" => safe_div(flow.bwd_total_bytes as f64, bwd_count),
            "Fwd Header Length.1" => flow.fwd_header_bytes as f64,
            "Fwd Avg Bytes/Bulk" => safe_div(fwd_bulk.total_bytes as f64, fwd_bulk.bulk_count as f64),
            "Fwd Avg Packets/Bulk" => safe_div(fwd_bulk.total_packets as f64, fwd_bulk.bulk_count as f64),
            "Fwd Avg Bulk Rate" => safe_div(
                fwd_bulk.total_bytes as f64,
                fwd_bulk.total_duration_us as f64 / 1_000_000.0,
            ),
            "Bwd Avg Bytes/Bulk" => safe_div(bwd_bulk.total_bytes as f64, bwd_bulk.bulk_count as f64),
            "Bwd Avg Packets/Bulk" => safe_div(bwd_bulk.total_packets as f64, bwd_bulk.bulk_count as f64),
            "Bwd Avg Bulk Rate" => safe_div(
                bwd_bulk.total_bytes as f64,
                bwd_bulk.total_duration_us as f64 / 1_000_000.0,
            ),
            "Subflow Fwd Packets" => fwd_count,
            "Subflow Fwd Bytes" => flow.fwd_total_bytes as f64,
            "Subflow Bwd Packets" => bwd_count,
            "Subflow Bwd Bytes" => flow.bwd_total_bytes as f64,
            "Init_Win_bytes_forward" | "Init Fwd Win Byts" | "fwd_win_bytes" => flow.init_win_bytes_fwd as f64,
            "Init_Win_bytes_backward" | "Init Bwd Win Byts" | "bwd_win_bytes" => flow.init_win_bytes_bwd as f64,
            "act_data_pkt_fwd" | "Fwd Act Data Pkts" | "fwd_act_data_pkts" => fwd_seg_sizes.len() as f64,
            "min_seg_size_forward" | "Fwd Seg Size Min" | "fwd_seg_size_min" => fwd_seg_sizes
                .iter()
                .min_by(|a, b| a.total_cmp(b))
                .copied()
                .unwrap_or(0.0),
            "Active Mean" => active_mean,
            "Active Std" => active_std,
            "Active Max" => active_max,
            "Active Min" => active_min,
            "Idle Mean" => idle_mean,
            "Idle Std" => idle_std,
            "Idle Max" => idle_max,
            "Idle Min" => idle_min,

            _ => 0.0,
        }
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

    pub fn winsorize(&mut self, clip_params: &HashMap<String, ClipParams>, feature_names: &[String]) {
        for (i, feature_name) in feature_names.iter().enumerate() {
            if i < self.feature_num {
                if let Some(params) = clip_params.get(feature_name) {
                    self.features[i] = self.features[i].clamp(params.lower, params.upper);
                }
            }
        }
    }

    pub fn all_feature_names() -> Vec<&'static str> {
        vec![
            "Destination Port",
            "Protocol",
            "Flow Duration",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Total Length of Fwd Packets",
            "Total Length of Bwd Packets",
            "Fwd Packet Length Max",
            "Fwd Packet Length Min",
            "Fwd Packet Length Mean",
            "Fwd Packet Length Std",
            "Bwd Packet Length Max",
            "Bwd Packet Length Min",
            "Bwd Packet Length Mean",
            "Bwd Packet Length Std",
            "Flow Bytes/s",
            "Flow Packets/s",
            "Flow IAT Mean",
            "Flow IAT Std",
            "Flow IAT Max",
            "Flow IAT Min",
            "Fwd IAT Total",
            "Fwd IAT Mean",
            "Fwd IAT Std",
            "Fwd IAT Max",
            "Fwd IAT Min",
            "Bwd IAT Total",
            "Bwd IAT Mean",
            "Bwd IAT Std",
            "Bwd IAT Max",
            "Bwd IAT Min",
            "Fwd PSH Flags",
            "Bwd PSH Flags",
            "Fwd URG Flags",
            "Bwd URG Flags",
            "Fwd Header Length",
            "Bwd Header Length",
            "Fwd Packets/s",
            "Bwd Packets/s",
            "Min Packet Length",
            "Max Packet Length",
            "Packet Length Mean",
            "Packet Length Std",
            "Packet Length Variance",
            "FIN Flag Count",
            "SYN Flag Count",
            "RST Flag Count",
            "PSH Flag Count",
            "ACK Flag Count",
            "URG Flag Count",
            "CWE Flag Count",
            "ECE Flag Count",
            "Down/Up Ratio",
            "Average Packet Size",
            "Avg Fwd Segment Size",
            "Avg Bwd Segment Size",
            "Fwd Header Length.1",
            "Fwd Avg Bytes/Bulk",
            "Fwd Avg Packets/Bulk",
            "Fwd Avg Bulk Rate",
            "Bwd Avg Bytes/Bulk",
            "Bwd Avg Packets/Bulk",
            "Bwd Avg Bulk Rate",
            "Subflow Fwd Packets",
            "Subflow Fwd Bytes",
            "Subflow Bwd Packets",
            "Subflow Bwd Bytes",
            "Init_Win_bytes_forward",
            "Init_Win_bytes_backward",
            "act_data_pkt_fwd",
            "min_seg_size_forward",
            "Active Mean",
            "Active Std",
            "Active Max",
            "Active Min",
            "Idle Mean",
            "Idle Std",
            "Idle Max",
            "Idle Min",
        ]
    }

    pub fn all_feature_names_owned() -> Vec<String> {
        Self::all_feature_names().iter().map(|s| s.to_string()).collect()
    }

    pub fn to_csv_record(&self) -> Vec<String> {
        let mut record: Vec<String> = self.features.iter().map(|f| f.to_string()).collect();
        record.push("BENIGN".to_string());
        record
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
