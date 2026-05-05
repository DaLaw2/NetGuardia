use macros::config_settings;

#[config_settings(section = "pipeline")]
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    #[setting(key = "pipeline_ingress", default = "access_control,rate_limit,service", api = false)]
    pub ingress: Vec<String>,
    #[setting(key = "pipeline_egress", default = "", api = false)]
    pub egress: Vec<String>,
}
