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
        let precomputed = PrecomputedStats::compute(flow);
        let feature_num = feature_names.len();
        let mut features = Vec::with_capacity(feature_num);

        for name in feature_names {
            let value = precomputed.get(name.trim());
            features.push(value);
        }

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

    pub fn winsorize(&mut self, clip_params: &HashMap<String, ClipParams>, feature_names: &[String]) {
        for (i, feature_name) in feature_names.iter().enumerate() {
            if i < self.feature_num
                && let Some(params) = clip_params.get(feature_name) {
                    self.features[i] = self.features[i].clamp(params.lower, params.upper);
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

/// All statistics pre-computed once from a FlowData, then looked up by feature name.
struct PrecomputedStats {
    // Basic counts and durations
    dst_port: f64,
    protocol: f64,
    duration_us: f64,
    fwd_count: f64,
    bwd_count: f64,
    total_count: f64,
    fwd_total_bytes: f64,
    bwd_total_bytes: f64,
    total_bytes: f64,
    duration_s: f64,

    // Forward packet length stats
    fwd_len_max: f64,
    fwd_len_min: f64,
    fwd_len_mean: f64,
    fwd_len_std: f64,

    // Backward packet length stats
    bwd_len_max: f64,
    bwd_len_min: f64,
    bwd_len_mean: f64,
    bwd_len_std: f64,

    // Combined packet length stats
    all_len_max: f64,
    all_len_min: f64,
    all_len_mean: f64,
    all_len_std: f64,

    // Flow IAT stats
    flow_iat_max: f64,
    flow_iat_min: f64,
    flow_iat_mean: f64,
    flow_iat_std: f64,

    // Forward IAT stats
    fwd_iat_total: f64,
    fwd_iat_max: f64,
    fwd_iat_min: f64,
    fwd_iat_mean: f64,
    fwd_iat_std: f64,

    // Backward IAT stats
    bwd_iat_total: f64,
    bwd_iat_max: f64,
    bwd_iat_min: f64,
    bwd_iat_mean: f64,
    bwd_iat_std: f64,

    // Flag counts (per-direction)
    fwd_psh: f64,
    bwd_psh: f64,
    fwd_urg: f64,
    bwd_urg: f64,

    // Header bytes
    fwd_header_bytes: f64,
    bwd_header_bytes: f64,

    // Flag counts (global)
    fin_count: f64,
    syn_count: f64,
    rst_count: f64,
    psh_count: f64,
    ack_count: f64,
    urg_count: f64,
    cwe_count: f64,
    ece_count: f64,

    // Bulk stats
    fwd_avg_bytes_bulk: f64,
    fwd_avg_packets_bulk: f64,
    fwd_avg_bulk_rate: f64,
    bwd_avg_bytes_bulk: f64,
    bwd_avg_packets_bulk: f64,
    bwd_avg_bulk_rate: f64,

    // Window sizes
    init_win_bytes_fwd: f64,
    init_win_bytes_bwd: f64,

    // Active data packets
    act_data_pkt_fwd: f64,

    // Min forward header (segment) size
    min_seg_size_forward: f64,

    // Active/idle period stats
    active_max: f64,
    active_min: f64,
    active_mean: f64,
    active_std: f64,
    idle_max: f64,
    idle_min: f64,
    idle_mean: f64,
    idle_std: f64,
}

impl PrecomputedStats {
    fn compute(flow: &FlowData) -> Self {
        let safe_div = |a: f64, b: f64| if b > 0.0 { a / b } else { 0.0 };

        let fwd_count = flow.fwd_packets.len() as f64;
        let bwd_count = flow.bwd_packets.len() as f64;
        let total_count = fwd_count + bwd_count;

        let duration_us = flow.duration_us() as f64;
        let duration_s = {
            let s = duration_us / 1_000_000.0;
            if s > 0.0 { s } else { 1e-6 }
        };

        let fwd_total_bytes = flow.fwd_total_bytes as f64;
        let bwd_total_bytes = flow.bwd_total_bytes as f64;
        let total_bytes = fwd_total_bytes + bwd_total_bytes;

        // Packet length stats
        let fwd_lengths: Vec<f64> = flow.fwd_packets.iter().map(|p| p.payload_length as f64).collect();
        let (fwd_len_max, fwd_len_min, fwd_len_mean, fwd_len_std) = compute_stats(&fwd_lengths);

        let bwd_lengths: Vec<f64> = flow.bwd_packets.iter().map(|p| p.payload_length as f64).collect();
        let (bwd_len_max, bwd_len_min, bwd_len_mean, bwd_len_std) = compute_stats(&bwd_lengths);

        let all_lengths: Vec<f64> = flow
            .fwd_packets
            .iter()
            .chain(flow.bwd_packets.iter())
            .map(|p| p.payload_length as f64)
            .collect();
        let (all_len_max, all_len_min, all_len_mean, all_len_std) = compute_stats(&all_lengths);

        // IAT stats
        let flow_iats = compute_flow_iats(&flow.fwd_packets, &flow.bwd_packets);
        let (flow_iat_max, flow_iat_min, flow_iat_mean, flow_iat_std) = compute_stats(&flow_iats);

        let fwd_iats = compute_iats(&flow.fwd_packets);
        let fwd_iat_total: f64 = fwd_iats.iter().sum();
        let (fwd_iat_max, fwd_iat_min, fwd_iat_mean, fwd_iat_std) = compute_stats(&fwd_iats);

        let bwd_iats = compute_iats(&flow.bwd_packets);
        let bwd_iat_total: f64 = bwd_iats.iter().sum();
        let (bwd_iat_max, bwd_iat_min, bwd_iat_mean, bwd_iat_std) = compute_stats(&bwd_iats);

        // Per-direction flag counts
        let fwd_psh = flow.fwd_packets.iter().filter(|p| p.flags & TCP_PSH != 0).count() as f64;
        let bwd_psh = flow.bwd_packets.iter().filter(|p| p.flags & TCP_PSH != 0).count() as f64;
        let fwd_urg = flow.fwd_packets.iter().filter(|p| p.flags & TCP_URG != 0).count() as f64;
        let bwd_urg = flow.bwd_packets.iter().filter(|p| p.flags & TCP_URG != 0).count() as f64;

        // Bulk stats
        let fwd_bulk = &flow.fwd_bulk_state;
        let bwd_bulk = &flow.bwd_bulk_state;

        let fwd_avg_bytes_bulk = safe_div(fwd_bulk.total_bytes as f64, fwd_bulk.bulk_count as f64);
        let fwd_avg_packets_bulk = safe_div(fwd_bulk.total_packets as f64, fwd_bulk.bulk_count as f64);
        let fwd_avg_bulk_rate = safe_div(
            fwd_bulk.total_bytes as f64,
            fwd_bulk.total_duration_us as f64 / 1_000_000.0,
        );
        let bwd_avg_bytes_bulk = safe_div(bwd_bulk.total_bytes as f64, bwd_bulk.bulk_count as f64);
        let bwd_avg_packets_bulk = safe_div(bwd_bulk.total_packets as f64, bwd_bulk.bulk_count as f64);
        let bwd_avg_bulk_rate = safe_div(
            bwd_bulk.total_bytes as f64,
            bwd_bulk.total_duration_us as f64 / 1_000_000.0,
        );

        // Min forward segment (header) size
        let min_seg_size_forward = flow
            .fwd_packets
            .iter()
            .map(|p| p.header_length as f64)
            .min_by(|a, b| a.total_cmp(b))
            .unwrap_or(0.0);

        // Active/idle period stats
        let (active_max, active_min, active_mean, active_std) =
            compute_stats(&flow.active_periods.iter().map(|&x| x as f64).collect::<Vec<_>>());
        let (idle_max, idle_min, idle_mean, idle_std) =
            compute_stats(&flow.idle_periods.iter().map(|&x| x as f64).collect::<Vec<_>>());

        Self {
            dst_port: flow.flow_key.dst_port as f64,
            protocol: flow.flow_key.protocol as f64,
            duration_us,
            fwd_count,
            bwd_count,
            total_count,
            fwd_total_bytes,
            bwd_total_bytes,
            total_bytes,
            duration_s,
            fwd_len_max,
            fwd_len_min,
            fwd_len_mean,
            fwd_len_std,
            bwd_len_max,
            bwd_len_min,
            bwd_len_mean,
            bwd_len_std,
            all_len_max,
            all_len_min,
            all_len_mean,
            all_len_std,
            flow_iat_max,
            flow_iat_min,
            flow_iat_mean,
            flow_iat_std,
            fwd_iat_total,
            fwd_iat_max,
            fwd_iat_min,
            fwd_iat_mean,
            fwd_iat_std,
            bwd_iat_total,
            bwd_iat_max,
            bwd_iat_min,
            bwd_iat_mean,
            bwd_iat_std,
            fwd_psh,
            bwd_psh,
            fwd_urg,
            bwd_urg,
            fwd_header_bytes: flow.fwd_header_bytes as f64,
            bwd_header_bytes: flow.bwd_header_bytes as f64,
            fin_count: flow.fin_count as f64,
            syn_count: flow.syn_count as f64,
            rst_count: flow.rst_count as f64,
            psh_count: flow.psh_count as f64,
            ack_count: flow.ack_count as f64,
            urg_count: flow.urg_count as f64,
            cwe_count: flow.cwe_count as f64,
            ece_count: flow.ece_count as f64,
            fwd_avg_bytes_bulk,
            fwd_avg_packets_bulk,
            fwd_avg_bulk_rate,
            bwd_avg_bytes_bulk,
            bwd_avg_packets_bulk,
            bwd_avg_bulk_rate,
            init_win_bytes_fwd: flow.init_win_bytes_fwd as f64,
            init_win_bytes_bwd: flow.init_win_bytes_bwd as f64,
            act_data_pkt_fwd: flow.act_data_pkt_fwd as f64,
            min_seg_size_forward,
            active_max,
            active_min,
            active_mean,
            active_std,
            idle_max,
            idle_min,
            idle_mean,
            idle_std,
        }
    }

    fn get(&self, feature_name: &str) -> f64 {
        let safe_div = |a: f64, b: f64| if b > 0.0 { a / b } else { 0.0 };

        match feature_name {
            "Destination Port" | "Dst Port" | "dst_port" => self.dst_port,
            "Protocol" | "protocol" => self.protocol,
            "Flow Duration" | "flow_duration" => self.duration_us,
            "Total Fwd Packets" | "Tot Fwd Pkts" | "fwd_packets" => self.fwd_count,
            "Total Backward Packets" | "Tot Bwd Pkts" | "bwd_packets" => self.bwd_count,
            "Total Length of Fwd Packets" | "TotLen Fwd Pkts" | "fwd_bytes" => self.fwd_total_bytes,
            "Total Length of Bwd Packets" | "TotLen Bwd Pkts" | "bwd_bytes" => self.bwd_total_bytes,
            "Fwd Packet Length Max" => self.fwd_len_max,
            "Fwd Packet Length Min" => self.fwd_len_min,
            "Fwd Packet Length Mean" | "Fwd Pkt Len Mean" | "fwd_pkt_len_mean" => self.fwd_len_mean,
            "Fwd Packet Length Std" | "Fwd Pkt Len Std" | "fwd_pkt_len_std" => self.fwd_len_std,
            "Bwd Packet Length Max" => self.bwd_len_max,
            "Bwd Packet Length Min" => self.bwd_len_min,
            "Bwd Packet Length Mean" | "Bwd Pkt Len Mean" | "bwd_pkt_len_mean" => self.bwd_len_mean,
            "Bwd Packet Length Std" | "Bwd Pkt Len Std" | "bwd_pkt_len_std" => self.bwd_len_std,
            "Flow Bytes/s" | "Flow Byts/s" | "flow_bytes_per_sec" => safe_div(self.total_bytes, self.duration_s),
            "Flow Packets/s" | "Flow Pkts/s" | "flow_pkts_per_sec" => safe_div(self.total_count, self.duration_s),
            "Flow IAT Mean" | "flow_iat_mean" => self.flow_iat_mean,
            "Flow IAT Std" => self.flow_iat_std,
            "Flow IAT Max" => self.flow_iat_max,
            "Flow IAT Min" => self.flow_iat_min,
            "Fwd IAT Total" => self.fwd_iat_total,
            "Fwd IAT Mean" | "fwd_iat_mean" => self.fwd_iat_mean,
            "Fwd IAT Std" => self.fwd_iat_std,
            "Fwd IAT Max" => self.fwd_iat_max,
            "Fwd IAT Min" => self.fwd_iat_min,
            "Bwd IAT Total" => self.bwd_iat_total,
            "Bwd IAT Mean" | "bwd_iat_mean" => self.bwd_iat_mean,
            "Bwd IAT Std" => self.bwd_iat_std,
            "Bwd IAT Max" => self.bwd_iat_max,
            "Bwd IAT Min" => self.bwd_iat_min,
            "Fwd PSH Flags" => self.fwd_psh,
            "Bwd PSH Flags" => self.bwd_psh,
            "Fwd URG Flags" => self.fwd_urg,
            "Bwd URG Flags" => self.bwd_urg,
            "Fwd Header Length" => self.fwd_header_bytes,
            "Bwd Header Length" => self.bwd_header_bytes,
            "Fwd Packets/s" => safe_div(self.fwd_count, self.duration_s),
            "Bwd Packets/s" => safe_div(self.bwd_count, self.duration_s),
            "Min Packet Length" => self.all_len_min,
            "Max Packet Length" => self.all_len_max,
            "Packet Length Mean" | "Pkt Len Mean" | "pkt_len_mean" => self.all_len_mean,
            "Packet Length Std" | "Pkt Len Std" | "pkt_len_std" => self.all_len_std,
            "Packet Length Variance" => self.all_len_std * self.all_len_std,
            "FIN Flag Count" | "FIN Flag Cnt" | "fin_flag_cnt" => self.fin_count,
            "SYN Flag Count" | "SYN Flag Cnt" | "syn_flag_cnt" => self.syn_count,
            "RST Flag Count" | "RST Flag Cnt" | "rst_flag_cnt" => self.rst_count,
            "PSH Flag Count" | "PSH Flag Cnt" | "psh_flag_cnt" => self.psh_count,
            "ACK Flag Count" | "ACK Flag Cnt" | "ack_flag_cnt" => self.ack_count,
            "URG Flag Count" => self.urg_count,
            "CWE Flag Count" => self.cwe_count,
            "ECE Flag Count" => self.ece_count,
            "Down/Up Ratio" => safe_div(self.bwd_count, self.fwd_count),
            "Average Packet Size" => safe_div(self.total_bytes, self.total_count),
            "Avg Fwd Segment Size" => safe_div(self.fwd_total_bytes, self.fwd_count),
            "Avg Bwd Segment Size" => safe_div(self.bwd_total_bytes, self.bwd_count),
            "Fwd Header Length.1" => self.fwd_header_bytes,
            "Fwd Avg Bytes/Bulk" => self.fwd_avg_bytes_bulk,
            "Fwd Avg Packets/Bulk" => self.fwd_avg_packets_bulk,
            "Fwd Avg Bulk Rate" => self.fwd_avg_bulk_rate,
            "Bwd Avg Bytes/Bulk" => self.bwd_avg_bytes_bulk,
            "Bwd Avg Packets/Bulk" => self.bwd_avg_packets_bulk,
            "Bwd Avg Bulk Rate" => self.bwd_avg_bulk_rate,
            "Subflow Fwd Packets" => self.fwd_count,
            "Subflow Fwd Bytes" => self.fwd_total_bytes,
            "Subflow Bwd Packets" => self.bwd_count,
            "Subflow Bwd Bytes" => self.bwd_total_bytes,
            "Init_Win_bytes_forward" | "Init Fwd Win Byts" | "fwd_win_bytes" => self.init_win_bytes_fwd,
            "Init_Win_bytes_backward" | "Init Bwd Win Byts" | "bwd_win_bytes" => self.init_win_bytes_bwd,
            "act_data_pkt_fwd" | "Fwd Act Data Pkts" | "fwd_act_data_pkts" => self.act_data_pkt_fwd,
            "min_seg_size_forward" | "Fwd Seg Size Min" | "fwd_seg_size_min" => self.min_seg_size_forward,
            "Active Mean" => self.active_mean,
            "Active Std" => self.active_std,
            "Active Max" => self.active_max,
            "Active Min" => self.active_min,
            "Idle Mean" => self.idle_mean,
            "Idle Std" => self.idle_std,
            "Idle Max" => self.idle_max,
            "Idle Min" => self.idle_min,

            _ => 0.0,
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

    let variance: f64 = if n > 1.0 {
        values.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0)
    } else {
        0.0
    };
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
