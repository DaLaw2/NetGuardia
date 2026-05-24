use arc_swap::ArcSwap;

use crate::interface::system::system_control::{XdpModeQuery, XdpModes};

#[derive(Debug, Clone)]
pub struct RuntimeState {
    pub xdp: XdpRuntimeState,
}

impl XdpModeQuery for ArcSwap<RuntimeState> {
    fn get_xdp_modes(&self) -> XdpModes {
        let xdp = self.load().xdp.clone();
        XdpModes {
            ingress_mode: xdp.ingress_mode,
            egress_mode: xdp.egress_mode,
        }
    }
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
