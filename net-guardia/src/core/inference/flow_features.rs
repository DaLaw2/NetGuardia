use std::collections::HashMap;

use crate::domain::detection::ml_detection::ClipParams;

#[derive(Debug, Clone)]
pub struct FlowFeatures {
    pub features: Vec<f64>,
    pub feature_num: usize,
}

impl FlowFeatures {
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
                && let Some(params) = clip_params.get(feature_name)
            {
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
            // Phase 2: new features
            "fwd_iat_std",
            "bwd_iat_std",
            "flow_iat_std",
            "fwd_bwd_bytes_ratio",
            "pkt_len_variance",
            "fwd_iat_skewness",
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
