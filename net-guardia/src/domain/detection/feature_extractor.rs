use std::collections::HashMap;
use std::sync::LazyLock;

use net_guardia_abi::define::tcp_flags::*;

use super::flow_tracker::FlowData;
use crate::domain::detection::flow_features::FlowFeatures;
use crate::domain::detection::ml_detection::PacketData;

type FeatureGetter = fn(&FeatureStats) -> f64;

pub fn feature_is_known(name: &str) -> bool {
    FEATURE_REGISTRY.contains_key(name)
}

pub fn feature_registry_names() -> &'static [&'static str] {
    FEATURE_REGISTRY_NAMES.as_slice()
}

static FEATURE_REGISTRY_NAMES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let mut names: Vec<&'static str> = FEATURE_REGISTRY.keys().copied().collect();
    names.sort_unstable();
    names
});

impl FlowFeatures {
    pub fn extract_from_stats(precomputed: &FeatureStats, feature_names: &[String]) -> Self {
        let feature_num = feature_names.len();
        let mut features = Vec::with_capacity(feature_num);

        for name in feature_names {
            let value = precomputed.get(name.trim());
            features.push(value);
        }

        Self { features, feature_num }
    }
}

#[derive(Debug, Clone)]
pub struct FeatureStats {
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

    fwd_len_max: f64,
    fwd_len_min: f64,
    fwd_len_mean: f64,
    fwd_len_std: f64,

    bwd_len_max: f64,
    bwd_len_min: f64,
    bwd_len_mean: f64,
    bwd_len_std: f64,

    all_len_max: f64,
    all_len_min: f64,
    all_len_mean: f64,
    all_len_std: f64,

    flow_iat_max: f64,
    flow_iat_min: f64,
    flow_iat_mean: f64,
    flow_iat_std: f64,

    fwd_iat_total: f64,
    fwd_iat_max: f64,
    fwd_iat_min: f64,
    fwd_iat_mean: f64,
    fwd_iat_std: f64,

    bwd_iat_total: f64,
    bwd_iat_max: f64,
    bwd_iat_min: f64,
    bwd_iat_mean: f64,
    bwd_iat_std: f64,

    fwd_psh: f64,
    bwd_psh: f64,
    fwd_urg: f64,
    bwd_urg: f64,

    fwd_header_bytes: f64,
    bwd_header_bytes: f64,

    fin_count: f64,
    syn_count: f64,
    rst_count: f64,
    psh_count: f64,
    ack_count: f64,
    urg_count: f64,
    cwe_count: f64,
    ece_count: f64,

    fwd_avg_bytes_bulk: f64,
    fwd_avg_packets_bulk: f64,
    fwd_avg_bulk_rate: f64,
    bwd_avg_bytes_bulk: f64,
    bwd_avg_packets_bulk: f64,
    bwd_avg_bulk_rate: f64,

    init_win_bytes_fwd: f64,
    init_win_bytes_bwd: f64,

    act_data_pkt_fwd: f64,

    min_seg_size_forward: f64,

    active_max: f64,
    active_min: f64,
    active_mean: f64,
    active_std: f64,
    idle_max: f64,
    idle_min: f64,
    idle_mean: f64,
    idle_std: f64,

    fwd_bwd_bytes_ratio: f64,
    fwd_iat_skewness: f64,
}

impl FeatureStats {
    pub fn compute(flow: &FlowData) -> Self {
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

        let mut fwd_len_stats = StreamingStats::new();
        for p in &flow.fwd_packets {
            fwd_len_stats.push(p.payload_length as f64);
        }
        let (fwd_len_max, fwd_len_min, fwd_len_mean, fwd_len_std) = fwd_len_stats.finalize();

        let mut bwd_len_stats = StreamingStats::new();
        for p in &flow.bwd_packets {
            bwd_len_stats.push(p.payload_length as f64);
        }
        let (bwd_len_max, bwd_len_min, bwd_len_mean, bwd_len_std) = bwd_len_stats.finalize();

        let mut all_len_stats = StreamingStats::new();
        for p in flow.fwd_packets.iter().chain(flow.bwd_packets.iter()) {
            all_len_stats.push(p.payload_length as f64);
        }
        let (all_len_max, all_len_min, all_len_mean, all_len_std) = all_len_stats.finalize();

        let (flow_iat_max, flow_iat_min, flow_iat_mean, flow_iat_std) =
            compute_flow_iat_stats(&flow.fwd_packets, &flow.bwd_packets);

        let mut fwd_iats = compute_iats(&flow.fwd_packets);
        let (fwd_iat_total, fwd_iat_max, fwd_iat_min, fwd_iat_mean, fwd_iat_std) = iat_stats(&fwd_iats);
        let fwd_iat_skewness = compute_bowley_skewness(&mut fwd_iats);

        let bwd_iat_values = flow.bwd_packets.windows(2).map(|w| packet_iat(&w[0], &w[1]) as f64);
        let (bwd_iat_total, bwd_iat_max, bwd_iat_min, bwd_iat_mean, bwd_iat_std) = iat_stats_from_iter(bwd_iat_values);

        let fwd_psh = flow.fwd_packets.iter().filter(|p| p.flags & TCP_PSH != 0).count() as f64;
        let bwd_psh = flow.bwd_packets.iter().filter(|p| p.flags & TCP_PSH != 0).count() as f64;
        let fwd_urg = flow.fwd_packets.iter().filter(|p| p.flags & TCP_URG != 0).count() as f64;
        let bwd_urg = flow.bwd_packets.iter().filter(|p| p.flags & TCP_URG != 0).count() as f64;

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

        let min_seg_size_forward = flow
            .fwd_packets
            .iter()
            .map(|p| p.header_length as f64)
            .min_by(|a, b| a.total_cmp(b))
            .unwrap_or(0.0);

        let mut active_stats = StreamingStats::new();
        for &x in &flow.active_periods {
            active_stats.push(x as f64);
        }
        let (active_max, active_min, active_mean, active_std) = active_stats.finalize();

        let mut idle_stats = StreamingStats::new();
        for &x in &flow.idle_periods {
            idle_stats.push(x as f64);
        }
        let (idle_max, idle_min, idle_mean, idle_std) = idle_stats.finalize();

        let fwd_bwd_bytes_ratio = safe_div(fwd_total_bytes, fwd_total_bytes + bwd_total_bytes);

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
            fwd_bwd_bytes_ratio,
            fwd_iat_skewness,
        }
    }

    pub fn get(&self, feature_name: &str) -> f64 {
        FEATURE_REGISTRY.get(feature_name).map(|g| g(self)).unwrap_or(0.0)
    }
}

fn reg_safe_div(a: f64, b: f64) -> f64 {
    if b > 0.0 { a / b } else { 0.0 }
}

fn reg_insert(m: &mut HashMap<&'static str, FeatureGetter>, names: &[&'static str], g: FeatureGetter) {
    for n in names {
        m.insert(*n, g);
    }
}

static FEATURE_REGISTRY: LazyLock<HashMap<&'static str, FeatureGetter>> = LazyLock::new(|| {
    let mut m: HashMap<&'static str, FeatureGetter> = HashMap::new();

    reg_insert(&mut m, &["Destination Port", "Dst Port", "dst_port"], |s| s.dst_port);
    reg_insert(&mut m, &["Protocol", "protocol"], |s| s.protocol);
    reg_insert(&mut m, &["Flow Duration", "flow_duration"], |s| s.duration_us);

    reg_insert(
        &mut m,
        &[
            "Total Fwd Packets",
            "Tot Fwd Pkts",
            "fwd_packets",
            "Subflow Fwd Packets",
        ],
        |s| s.fwd_count,
    );
    reg_insert(
        &mut m,
        &[
            "Total Backward Packets",
            "Tot Bwd Pkts",
            "bwd_packets",
            "Subflow Bwd Packets",
        ],
        |s| s.bwd_count,
    );
    reg_insert(
        &mut m,
        &[
            "Total Length of Fwd Packets",
            "TotLen Fwd Pkts",
            "fwd_bytes",
            "Subflow Fwd Bytes",
        ],
        |s| s.fwd_total_bytes,
    );
    reg_insert(
        &mut m,
        &[
            "Total Length of Bwd Packets",
            "TotLen Bwd Pkts",
            "bwd_bytes",
            "Subflow Bwd Bytes",
        ],
        |s| s.bwd_total_bytes,
    );

    reg_insert(&mut m, &["Fwd Packet Length Max"], |s| s.fwd_len_max);
    reg_insert(&mut m, &["Fwd Packet Length Min"], |s| s.fwd_len_min);
    reg_insert(
        &mut m,
        &["Fwd Packet Length Mean", "Fwd Pkt Len Mean", "fwd_pkt_len_mean"],
        |s| s.fwd_len_mean,
    );
    reg_insert(
        &mut m,
        &["Fwd Packet Length Std", "Fwd Pkt Len Std", "fwd_pkt_len_std"],
        |s| s.fwd_len_std,
    );

    reg_insert(&mut m, &["Bwd Packet Length Max"], |s| s.bwd_len_max);
    reg_insert(&mut m, &["Bwd Packet Length Min"], |s| s.bwd_len_min);
    reg_insert(
        &mut m,
        &["Bwd Packet Length Mean", "Bwd Pkt Len Mean", "bwd_pkt_len_mean"],
        |s| s.bwd_len_mean,
    );
    reg_insert(
        &mut m,
        &["Bwd Packet Length Std", "Bwd Pkt Len Std", "bwd_pkt_len_std"],
        |s| s.bwd_len_std,
    );

    reg_insert(&mut m, &["Flow Bytes/s", "Flow Byts/s", "flow_bytes_per_sec"], |s| {
        reg_safe_div(s.total_bytes, s.duration_s)
    });
    reg_insert(&mut m, &["Flow Packets/s", "Flow Pkts/s", "flow_pkts_per_sec"], |s| {
        reg_safe_div(s.total_count, s.duration_s)
    });

    reg_insert(&mut m, &["Flow IAT Mean", "flow_iat_mean"], |s| s.flow_iat_mean);
    reg_insert(&mut m, &["Flow IAT Std", "flow_iat_std"], |s| s.flow_iat_std);
    reg_insert(&mut m, &["Flow IAT Max"], |s| s.flow_iat_max);
    reg_insert(&mut m, &["Flow IAT Min"], |s| s.flow_iat_min);

    reg_insert(&mut m, &["Fwd IAT Total"], |s| s.fwd_iat_total);
    reg_insert(&mut m, &["Fwd IAT Mean", "fwd_iat_mean"], |s| s.fwd_iat_mean);
    reg_insert(&mut m, &["Fwd IAT Std", "fwd_iat_std"], |s| s.fwd_iat_std);
    reg_insert(&mut m, &["Fwd IAT Max"], |s| s.fwd_iat_max);
    reg_insert(&mut m, &["Fwd IAT Min"], |s| s.fwd_iat_min);

    reg_insert(&mut m, &["Bwd IAT Total"], |s| s.bwd_iat_total);
    reg_insert(&mut m, &["Bwd IAT Mean", "bwd_iat_mean"], |s| s.bwd_iat_mean);
    reg_insert(&mut m, &["Bwd IAT Std", "bwd_iat_std"], |s| s.bwd_iat_std);
    reg_insert(&mut m, &["Bwd IAT Max"], |s| s.bwd_iat_max);
    reg_insert(&mut m, &["Bwd IAT Min"], |s| s.bwd_iat_min);

    reg_insert(&mut m, &["Fwd PSH Flags"], |s| s.fwd_psh);
    reg_insert(&mut m, &["Bwd PSH Flags"], |s| s.bwd_psh);
    reg_insert(&mut m, &["Fwd URG Flags"], |s| s.fwd_urg);
    reg_insert(&mut m, &["Bwd URG Flags"], |s| s.bwd_urg);
    reg_insert(&mut m, &["Fwd Header Length", "Fwd Header Length.1"], |s| {
        s.fwd_header_bytes
    });
    reg_insert(&mut m, &["Bwd Header Length"], |s| s.bwd_header_bytes);

    reg_insert(&mut m, &["Fwd Packets/s"], |s| reg_safe_div(s.fwd_count, s.duration_s));
    reg_insert(&mut m, &["Bwd Packets/s"], |s| reg_safe_div(s.bwd_count, s.duration_s));

    reg_insert(&mut m, &["Min Packet Length"], |s| s.all_len_min);
    reg_insert(&mut m, &["Max Packet Length"], |s| s.all_len_max);
    reg_insert(&mut m, &["Packet Length Mean", "Pkt Len Mean", "pkt_len_mean"], |s| {
        s.all_len_mean
    });
    reg_insert(&mut m, &["Packet Length Std", "Pkt Len Std", "pkt_len_std"], |s| {
        s.all_len_std
    });
    reg_insert(&mut m, &["Packet Length Variance", "pkt_len_variance"], |s| {
        s.all_len_std * s.all_len_std
    });

    reg_insert(&mut m, &["FIN Flag Count", "FIN Flag Cnt", "fin_flag_cnt"], |s| {
        s.fin_count
    });
    reg_insert(&mut m, &["SYN Flag Count", "SYN Flag Cnt", "syn_flag_cnt"], |s| {
        s.syn_count
    });
    reg_insert(&mut m, &["RST Flag Count", "RST Flag Cnt", "rst_flag_cnt"], |s| {
        s.rst_count
    });
    reg_insert(&mut m, &["PSH Flag Count", "PSH Flag Cnt", "psh_flag_cnt"], |s| {
        s.psh_count
    });
    reg_insert(&mut m, &["ACK Flag Count", "ACK Flag Cnt", "ack_flag_cnt"], |s| {
        s.ack_count
    });
    reg_insert(&mut m, &["URG Flag Count"], |s| s.urg_count);
    reg_insert(&mut m, &["CWE Flag Count"], |s| s.cwe_count);
    reg_insert(&mut m, &["ECE Flag Count"], |s| s.ece_count);

    reg_insert(&mut m, &["Down/Up Ratio"], |s| reg_safe_div(s.bwd_count, s.fwd_count));
    reg_insert(&mut m, &["Average Packet Size"], |s| {
        reg_safe_div(s.total_bytes, s.total_count)
    });
    reg_insert(&mut m, &["Avg Fwd Segment Size"], |s| {
        reg_safe_div(s.fwd_total_bytes, s.fwd_count)
    });
    reg_insert(&mut m, &["Avg Bwd Segment Size"], |s| {
        reg_safe_div(s.bwd_total_bytes, s.bwd_count)
    });

    reg_insert(&mut m, &["Fwd Avg Bytes/Bulk"], |s| s.fwd_avg_bytes_bulk);
    reg_insert(&mut m, &["Fwd Avg Packets/Bulk"], |s| s.fwd_avg_packets_bulk);
    reg_insert(&mut m, &["Fwd Avg Bulk Rate"], |s| s.fwd_avg_bulk_rate);
    reg_insert(&mut m, &["Bwd Avg Bytes/Bulk"], |s| s.bwd_avg_bytes_bulk);
    reg_insert(&mut m, &["Bwd Avg Packets/Bulk"], |s| s.bwd_avg_packets_bulk);
    reg_insert(&mut m, &["Bwd Avg Bulk Rate"], |s| s.bwd_avg_bulk_rate);

    reg_insert(&mut m, &["Init_Win_bytes_forward", "fwd_win_bytes"], |s| {
        s.init_win_bytes_fwd
    });
    reg_insert(&mut m, &["Init_Win_bytes_backward", "bwd_win_bytes"], |s| {
        s.init_win_bytes_bwd
    });
    reg_insert(&mut m, &["act_data_pkt_fwd", "fwd_act_data_pkts"], |s| {
        s.act_data_pkt_fwd
    });
    reg_insert(&mut m, &["min_seg_size_forward", "fwd_seg_size_min"], |s| {
        s.min_seg_size_forward
    });

    reg_insert(&mut m, &["Active Mean"], |s| s.active_mean);
    reg_insert(&mut m, &["Active Std"], |s| s.active_std);
    reg_insert(&mut m, &["Active Max"], |s| s.active_max);
    reg_insert(&mut m, &["Active Min"], |s| s.active_min);
    reg_insert(&mut m, &["Idle Mean"], |s| s.idle_mean);
    reg_insert(&mut m, &["Idle Std"], |s| s.idle_std);
    reg_insert(&mut m, &["Idle Max"], |s| s.idle_max);
    reg_insert(&mut m, &["Idle Min"], |s| s.idle_min);

    reg_insert(&mut m, &["fwd_bwd_bytes_ratio"], |s| s.fwd_bwd_bytes_ratio);
    reg_insert(&mut m, &["fwd_iat_skewness"], |s| s.fwd_iat_skewness);
    reg_insert(&mut m, &["iat_cv"], |s| reg_safe_div(s.flow_iat_std, s.flow_iat_mean));

    m
});
struct StreamingStats {
    count: u64,
    min: f64,
    max: f64,
    mean: f64,
    m2: f64,
}

impl StreamingStats {
    fn new() -> Self {
        Self {
            count: 0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            mean: 0.0,
            m2: 0.0,
        }
    }

    fn push(&mut self, x: f64) {
        self.count += 1;
        if x < self.min {
            self.min = x;
        }
        if x > self.max {
            self.max = x;
        }
        let delta = x - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }

    fn finalize(self) -> (f64, f64, f64, f64) {
        if self.count == 0 {
            return (0.0, 0.0, 0.0, 0.0);
        }
        let variance = if self.count > 1 {
            self.m2 / (self.count - 1) as f64
        } else {
            0.0
        };
        (self.max, self.min, self.mean, variance.sqrt())
    }
}

fn compute_iats(packets: &[PacketData]) -> Vec<f64> {
    packets.windows(2).map(|w| packet_iat(&w[0], &w[1]) as f64).collect()
}

fn packet_iat(prev: &PacketData, current: &PacketData) -> u64 {
    current.timestamp_us.saturating_sub(prev.timestamp_us)
}

fn iat_stats(values: &[f64]) -> (f64, f64, f64, f64, f64) {
    iat_stats_from_iter(values.iter().copied())
}

fn iat_stats_from_iter(values: impl Iterator<Item = f64>) -> (f64, f64, f64, f64, f64) {
    let mut stats = StreamingStats::new();
    let mut total = 0.0;
    for value in values {
        stats.push(value);
        total += value;
    }
    let (max, min, mean, std) = stats.finalize();
    (total, max, min, mean, std)
}

fn compute_bowley_skewness(values: &mut [f64]) -> f64 {
    let n = values.len();
    if n < 4 {
        return 0.0;
    }

    let i_q1 = n / 4;
    let i_q2 = n / 2;
    let i_q3 = 3 * n / 4;

    values.select_nth_unstable_by(i_q2, |a, b| a.total_cmp(b));
    let q2 = values[i_q2];

    values[..i_q2].select_nth_unstable_by(i_q1, |a, b| a.total_cmp(b));
    let q1 = values[i_q1];

    let q3 = {
        let offset = i_q2 + 1;
        let local_idx = i_q3 - offset;
        values[offset..].select_nth_unstable_by(local_idx, |a, b| a.total_cmp(b));
        values[i_q3]
    };

    let iqr = q3 - q1;
    if iqr <= 0.0 { 0.0 } else { (q3 + q1 - 2.0 * q2) / iqr }
}

fn compute_flow_iat_stats(fwd_packets: &[PacketData], bwd_packets: &[PacketData]) -> (f64, f64, f64, f64) {
    let mut fi = fwd_packets.iter().peekable();
    let mut bi = bwd_packets.iter().peekable();
    let mut stats = StreamingStats::new();
    let mut prev_ts: Option<u64> = None;

    loop {
        let ts = match (fi.peek(), bi.peek()) {
            (Some(f), Some(b)) => {
                if f.timestamp_us <= b.timestamp_us {
                    let t = f.timestamp_us;
                    fi.next();
                    t
                } else {
                    let t = b.timestamp_us;
                    bi.next();
                    t
                }
            }
            (Some(f), None) => {
                let t = f.timestamp_us;
                fi.next();
                t
            }
            (None, Some(b)) => {
                let t = b.timestamp_us;
                bi.next();
                t
            }
            (None, None) => break,
        };
        if let Some(prev) = prev_ts {
            stats.push(ts.saturating_sub(prev) as f64);
        }
        prev_ts = Some(ts);
    }

    if stats.count == 0 {
        return (0.0, 0.0, 0.0, 0.0);
    }
    stats.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bowley_skewness_insufficient_data() {
        assert_eq!(compute_bowley_skewness(&mut []), 0.0);
        assert_eq!(compute_bowley_skewness(&mut [1.0]), 0.0);
        assert_eq!(compute_bowley_skewness(&mut [1.0, 2.0, 3.0]), 0.0);
    }

    #[test]
    fn bowley_skewness_zero_iqr() {
        assert_eq!(compute_bowley_skewness(&mut [5.0, 5.0, 5.0, 5.0]), 0.0);
        assert_eq!(compute_bowley_skewness(&mut [1.0, 1.0, 1.0, 1.0, 1.0, 1.0]), 0.0);
    }

    #[test]
    fn packet_iat_saturates_out_of_order_timestamps() {
        let prev = PacketData {
            timestamp_us: 200,
            length: 0,
            header_length: 0,
            payload_length: 0,
            flags: 0,
        };
        let current = PacketData {
            timestamp_us: 100,
            length: 0,
            header_length: 0,
            payload_length: 0,
            flags: 0,
        };

        assert_eq!(packet_iat(&prev, &current), 0);
    }

    fn sample_stats() -> FeatureStats {
        FeatureStats {
            dst_port: 443.0,
            protocol: 6.0,
            duration_us: 1_000_000.0,
            fwd_count: 10.0,
            bwd_count: 4.0,
            total_count: 14.0,
            fwd_total_bytes: 2000.0,
            bwd_total_bytes: 800.0,
            total_bytes: 2800.0,
            duration_s: 1.0,
            fwd_len_max: 1500.0,
            fwd_len_min: 40.0,
            fwd_len_mean: 200.0,
            fwd_len_std: 300.0,
            bwd_len_max: 1200.0,
            bwd_len_min: 60.0,
            bwd_len_mean: 200.0,
            bwd_len_std: 250.0,
            all_len_max: 1500.0,
            all_len_min: 40.0,
            all_len_mean: 200.0,
            all_len_std: 280.0,
            flow_iat_max: 50_000.0,
            flow_iat_min: 100.0,
            flow_iat_mean: 10_000.0,
            flow_iat_std: 5_000.0,
            fwd_iat_total: 90_000.0,
            fwd_iat_max: 40_000.0,
            fwd_iat_min: 200.0,
            fwd_iat_mean: 10_000.0,
            fwd_iat_std: 6_000.0,
            bwd_iat_total: 30_000.0,
            bwd_iat_max: 15_000.0,
            bwd_iat_min: 300.0,
            bwd_iat_mean: 7_500.0,
            bwd_iat_std: 4_000.0,
            fwd_psh: 2.0,
            bwd_psh: 1.0,
            fwd_urg: 0.0,
            bwd_urg: 0.0,
            fwd_header_bytes: 200.0,
            bwd_header_bytes: 80.0,
            fin_count: 1.0,
            syn_count: 1.0,
            rst_count: 0.0,
            psh_count: 3.0,
            ack_count: 10.0,
            urg_count: 0.0,
            cwe_count: 0.0,
            ece_count: 0.0,
            fwd_avg_bytes_bulk: 500.0,
            fwd_avg_packets_bulk: 5.0,
            fwd_avg_bulk_rate: 5000.0,
            bwd_avg_bytes_bulk: 400.0,
            bwd_avg_packets_bulk: 4.0,
            bwd_avg_bulk_rate: 4000.0,
            init_win_bytes_fwd: 65535.0,
            init_win_bytes_bwd: 65000.0,
            act_data_pkt_fwd: 8.0,
            min_seg_size_forward: 40.0,
            active_max: 1000.0,
            active_min: 50.0,
            active_mean: 300.0,
            active_std: 200.0,
            idle_max: 500.0,
            idle_min: 10.0,
            idle_mean: 100.0,
            idle_std: 80.0,
            fwd_bwd_bytes_ratio: 0.71,
            fwd_iat_skewness: 0.15,
        }
    }

    #[test]
    fn registry_unknown_name_returns_zero() {
        let s = sample_stats();
        assert_eq!(s.get("not_a_feature"), 0.0);
    }

    #[test]
    fn registry_aliases_resolve_identically() {
        let s = sample_stats();
        for group in [
            [
                "Total Fwd Packets",
                "Tot Fwd Pkts",
                "fwd_packets",
                "Subflow Fwd Packets",
            ],
            [
                "Total Length of Fwd Packets",
                "TotLen Fwd Pkts",
                "fwd_bytes",
                "Subflow Fwd Bytes",
            ],
            ["Flow IAT Std", "flow_iat_std", "Flow IAT Std", "Flow IAT Std"],
            ["Fwd IAT Std", "fwd_iat_std", "Fwd IAT Std", "Fwd IAT Std"],
            ["Bwd IAT Std", "bwd_iat_std", "Bwd IAT Std", "Bwd IAT Std"],
            [
                "Packet Length Variance",
                "pkt_len_variance",
                "Packet Length Variance",
                "Packet Length Variance",
            ],
            [
                "Fwd Header Length",
                "Fwd Header Length.1",
                "Fwd Header Length",
                "Fwd Header Length",
            ],
        ] {
            let expected = s.get(group[0]);
            for name in &group[1..] {
                assert_eq!(
                    s.get(name),
                    expected,
                    "alias '{name}' should resolve to same value as '{}'",
                    group[0]
                );
            }
        }
    }

    #[test]
    fn registry_safe_div_returns_zero_on_zero_denominator() {
        let mut s = sample_stats();
        s.flow_iat_mean = 0.0;
        s.flow_iat_std = 500.0;
        assert_eq!(s.get("iat_cv"), 0.0);
        s.duration_s = 0.0;
        assert_eq!(s.get("flow_bytes_per_sec"), 0.0);
        assert_eq!(s.get("flow_pkts_per_sec"), 0.0);
    }

    #[test]
    fn registry_covers_v10_manifest_features() {
        const V10_FEATURES: &[&str] = &[
            "flow_duration",
            "fwd_packets",
            "bwd_packets",
            "fwd_bytes",
            "bwd_bytes",
            "flow_bytes_per_sec",
            "flow_pkts_per_sec",
            "fwd_win_bytes",
            "bwd_win_bytes",
            "fwd_pkt_len_mean",
            "bwd_pkt_len_mean",
            "fwd_iat_mean",
            "bwd_iat_mean",
            "flow_iat_mean",
            "pkt_len_mean",
            "dst_port",
            "protocol",
            "psh_flag_cnt",
            "ack_flag_cnt",
            "syn_flag_cnt",
            "fin_flag_cnt",
            "rst_flag_cnt",
            "pkt_len_std",
            "fwd_pkt_len_std",
            "bwd_pkt_len_std",
            "fwd_seg_size_min",
            "fwd_act_data_pkts",
            "fwd_iat_std",
            "bwd_iat_std",
            "fwd_bwd_bytes_ratio",
            "iat_cv",
        ];
        for f in V10_FEATURES {
            assert!(feature_is_known(f), "v10 feature '{f}' missing from FEATURE_REGISTRY");
        }
    }

    #[test]
    fn registry_covers_exported_flow_trace_header() {
        for feature in FlowFeatures::all_feature_names() {
            assert!(
                feature_is_known(feature),
                "flow trace feature '{feature}' missing from FEATURE_REGISTRY"
            );
        }
    }

    #[test]
    fn feature_registry_names_returns_sorted_unique_list() {
        let names = feature_registry_names();
        assert!(
            names.len() > 30,
            "FEATURE_REGISTRY should carry at least the v10 feature set plus aliases"
        );
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "feature_registry_names must be sorted");
        let mut dedup = names.to_vec();
        dedup.dedup();
        assert_eq!(
            names.len(),
            dedup.len(),
            "feature_registry_names must have no duplicates"
        );
        assert!(names.contains(&"Flow Duration"));
        assert!(names.contains(&"flow_duration"));
    }

    fn naive_stats(values: &[f64]) -> (f64, f64, f64, f64) {
        if values.is_empty() {
            return (0.0, 0.0, 0.0, 0.0);
        }
        let n = values.len() as f64;
        let sum: f64 = values.iter().sum();
        let mean = sum / n;
        let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
        let variance = if n > 1.0 {
            values.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0)
        } else {
            0.0
        };
        (max, min, mean, variance.sqrt())
    }

    #[test]
    fn streaming_stats_matches_naive() {
        let cases: Vec<Vec<f64>> = vec![
            vec![],
            vec![42.0],
            vec![1.0, 2.0],
            vec![10.0, 20.0, 30.0, 40.0, 50.0],
            vec![100.0, 100.0, 100.0],
            vec![1.0, 1000.0, 0.5, 500.0, 250.0],
        ];
        for values in &cases {
            let expected = naive_stats(values);
            let mut s = StreamingStats::new();
            for &v in values {
                s.push(v);
            }
            let got = s.finalize();
            assert!((got.0 - expected.0).abs() < 1e-10, "max mismatch for {values:?}");
            assert!((got.1 - expected.1).abs() < 1e-10, "min mismatch for {values:?}");
            assert!((got.2 - expected.2).abs() < 1e-10, "mean mismatch for {values:?}");
            assert!((got.3 - expected.3).abs() < 1e-10, "std mismatch for {values:?}");
        }
    }

    #[test]
    fn bowley_skewness_known_output() {
        let mut symmetric = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        assert!((compute_bowley_skewness(&mut symmetric)).abs() < 1e-10);

        let mut right_skewed = vec![1.0, 1.0, 1.0, 1.0, 2.0, 5.0, 10.0, 20.0];
        let skew = compute_bowley_skewness(&mut right_skewed);
        assert!((skew - 7.0 / 9.0).abs() < 1e-10);
    }
}
