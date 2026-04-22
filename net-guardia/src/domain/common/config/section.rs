use crate::domain::common::config::acl::AclConfig;
use crate::domain::common::config::correlation::CorrelationConfig;
use crate::domain::common::config::detection::{BeaconingConfig, DetectionConfig, FusionConfig};
use crate::domain::common::config::dns_filter::DnsFilterConfig;
use crate::domain::common::config::ebpf::EbpfConfig;
use crate::domain::common::config::http_server::HttpServerConfig;
use crate::domain::common::config::ml::MlConfig;
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

    pub fn keys(self) -> &'static [&'static str] {
        match self {
            Self::Network => EbpfConfig::NETWORK_KEYS,
            Self::Http => HttpServerConfig::API_KEYS,
            Self::Inference => MlConfig::INFERENCE_KEYS,
            Self::Xdp => EbpfConfig::XDP_KEYS,
            Self::Models => MlConfig::MODELS_KEYS,
            Self::Misc => AclConfig::API_KEYS,
            Self::Soar => SoarConfig::API_KEYS,
            Self::Ml => MlConfig::ML_KEYS,
            Self::FlowTrace => MlConfig::FLOW_TRACE_KEYS,
            Self::ModelUpload => MlConfig::MODEL_UPLOAD_KEYS,
            Self::Telegram => TelegramConfig::API_KEYS,
            Self::Dns => DnsFilterConfig::API_KEYS,
            Self::Smtp => SmtpConfig::API_KEYS,
            Self::Suricata => SuricataConfig::API_KEYS,
            Self::Detection => DetectionConfig::API_KEYS,
            Self::Fusion => FusionConfig::API_KEYS,
            Self::Beaconing => BeaconingConfig::API_KEYS,
            Self::Correlation => CorrelationConfig::API_KEYS,
            Self::Observability => ObservabilityConfig::API_KEYS,
        }
    }
}
