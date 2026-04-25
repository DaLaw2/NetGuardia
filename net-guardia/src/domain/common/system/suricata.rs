use serde::Serialize;

/// Runtime health of the Suricata subprocess bridge.
///
/// `Disabled`: Suricata bridge is off by config — no process is launched.
/// `Running`: subprocess is alive and eve.json tail is active.
/// `Stopped`: subprocess exited (crashed or graceful) and no auto-restart
/// is pending, or the bridge was shut down. `reason` carries context.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SuricataHealth {
    Disabled,
    Running {
        /// OS process id of the Suricata child. Useful for operator debugging.
        pid: u32,
    },
    Stopped {
        reason: String,
    },
}
