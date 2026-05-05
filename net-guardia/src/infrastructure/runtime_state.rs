#[derive(Debug, Clone)]
pub struct RuntimeState {
    pub xdp: XdpRuntimeState,
}

#[derive(Debug, Clone)]
pub struct XdpRuntimeState {
    pub ingress_mode: String,
    pub egress_mode: String,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            xdp: XdpRuntimeState {
                ingress_mode: "unknown".to_string(),
                egress_mode: "unknown".to_string(),
            },
        }
    }
}
