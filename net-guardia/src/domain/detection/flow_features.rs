use std::fmt::Write as _;
use std::sync::LazyLock;

static ALL_FEATURE_NAMES_OWNED: LazyLock<Vec<String>> = LazyLock::new(|| {
    FlowFeatures::all_feature_names()
        .iter()
        .map(|s| s.to_string())
        .collect()
});

const ALL_FEATURE_NAMES: &[&str] = &[
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
    "fwd_iat_std",
    "bwd_iat_std",
    "flow_iat_std",
    "fwd_bwd_bytes_ratio",
    "pkt_len_variance",
    "fwd_iat_skewness",
];

#[derive(Debug, Clone)]
pub struct FlowFeatures {
    pub features: Vec<f64>,
    pub feature_num: usize,
}

impl FlowFeatures {
    pub fn all_feature_names() -> &'static [&'static str] {
        ALL_FEATURE_NAMES
    }

    pub fn all_feature_names_owned() -> &'static [String] {
        &ALL_FEATURE_NAMES_OWNED
    }

    pub fn to_csv_line(&self) -> String {
        let mut buf = String::with_capacity(self.feature_num * 12);
        for (i, f) in self.features.iter().enumerate() {
            if i > 0 {
                buf.push(',');
            }
            let _ = write!(buf, "{f}");
        }
        buf.push_str(",BENIGN");
        buf
    }
}
