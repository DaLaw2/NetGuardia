use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SuricataHealth {
    Disabled,
    Running { pid: u32 },
    Stopped { reason: String },
}
