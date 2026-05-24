use crate::domain::common::config::acl::AclConfig;
use crate::domain::common::config::correlation::CorrelationConfig;
use crate::domain::common::config::detection::{BeaconingConfig, DetectionConfig, FusionConfig};
use crate::domain::common::config::dns_filter::DnsFilterConfig;
use crate::domain::common::config::ebpf::EbpfConfig;
use crate::domain::common::config::http_server::HttpServerConfig;
use crate::domain::common::config::ml::MlConfig;
use crate::domain::common::config::ml::circuit_breaker::CircuitBreakerConfig;
use crate::domain::common::config::ml::drift::DriftConfig;
use crate::domain::common::config::ml::flow::FlowConfig;
use crate::domain::common::config::ml::flow_trace::FlowTraceConfig;
use crate::domain::common::config::ml::inference::InferenceConfig;
use crate::domain::common::config::ml::model_upload::ModelUploadConfig;
use crate::domain::common::config::notification::{SmtpConfig, TelegramConfig};
use crate::domain::common::config::observability::ObservabilityConfig;
use crate::domain::common::config::soar::SoarConfig;
use crate::domain::common::config::suricata::SuricataConfig;

#[derive(Clone, Copy)]
pub enum ConfigSection {
    Network,
    Http,
    Inference,
    Xdp,
    Models,
    Misc,
    Soar,
    Ml,
    FlowTrace,
    ModelUpload,
    Telegram,
    Dns,
    Smtp,
    Suricata,
    Detection,
    Fusion,
    Beaconing,
    Correlation,
    Observability,
}

impl ConfigSection {
    pub const ALL: &[Self] = &[
        Self::Network,
        Self::Http,
        Self::Inference,
        Self::Xdp,
        Self::Models,
        Self::Misc,
        Self::Soar,
        Self::Ml,
        Self::FlowTrace,
        Self::ModelUpload,
        Self::Telegram,
        Self::Dns,
        Self::Smtp,
        Self::Suricata,
        Self::Detection,
        Self::Fusion,
        Self::Beaconing,
        Self::Correlation,
        Self::Observability,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Http => "http",
            Self::Inference => "inference",
            Self::Xdp => "xdp",
            Self::Models => "models",
            Self::Misc => "misc",
            Self::Soar => "soar",
            Self::Ml => "ml",
            Self::FlowTrace => "flow_trace",
            Self::ModelUpload => "model_upload",
            Self::Telegram => "telegram",
            Self::Dns => "dns",
            Self::Smtp => "smtp",
            Self::Suricata => "suricata",
            Self::Detection => "detection",
            Self::Fusion => "fusion",
            Self::Beaconing => "beaconing",
            Self::Correlation => "correlation",
            Self::Observability => "observability",
        }
    }

    pub fn for_each_key(self, mut visit: impl FnMut(&'static str)) {
        match self {
            Self::Network => visit_keys(EbpfConfig::NETWORK_KEYS, &mut visit),
            Self::Http => visit_keys(HttpServerConfig::API_KEYS, &mut visit),
            Self::Inference => visit_keys(InferenceConfig::INFERENCE_KEYS, &mut visit),
            Self::Xdp => visit_keys(EbpfConfig::XDP_KEYS, &mut visit),
            Self::Models => visit_keys(MlConfig::MODELS_KEYS, &mut visit),
            Self::Misc => visit_keys(AclConfig::API_KEYS, &mut visit),
            Self::Soar => visit_keys(SoarConfig::API_KEYS, &mut visit),
            Self::Ml => {
                visit_keys(InferenceConfig::ML_KEYS, &mut visit);
                visit_keys(DriftConfig::API_KEYS, &mut visit);
                visit_keys(MlConfig::ML_KEYS, &mut visit);
                visit_keys(CircuitBreakerConfig::API_KEYS, &mut visit);
                visit_keys(FlowConfig::API_KEYS, &mut visit);
            }
            Self::FlowTrace => visit_keys(FlowTraceConfig::API_KEYS, &mut visit),
            Self::ModelUpload => visit_keys(ModelUploadConfig::API_KEYS, &mut visit),
            Self::Telegram => visit_keys(TelegramConfig::API_KEYS, &mut visit),
            Self::Dns => visit_keys(DnsFilterConfig::API_KEYS, &mut visit),
            Self::Smtp => visit_keys(SmtpConfig::API_KEYS, &mut visit),
            Self::Suricata => visit_keys(SuricataConfig::API_KEYS, &mut visit),
            Self::Detection => visit_keys(DetectionConfig::API_KEYS, &mut visit),
            Self::Fusion => visit_keys(FusionConfig::API_KEYS, &mut visit),
            Self::Beaconing => visit_keys(BeaconingConfig::API_KEYS, &mut visit),
            Self::Correlation => visit_keys(CorrelationConfig::API_KEYS, &mut visit),
            Self::Observability => visit_keys(ObservabilityConfig::API_KEYS, &mut visit),
        }
    }
}

fn visit_keys(keys: &'static [&'static str], visit: &mut impl FnMut(&'static str)) {
    for key in keys {
        visit(key);
    }
}
