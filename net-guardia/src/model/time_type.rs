use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TimeType {
    #[serde(rename = "1min")]
    _1Min = 60 * 1_000_000_000,
    #[serde(rename = "10min")]
    _10Min = 600 * 1_000_000_000,
    #[serde(rename = "1hour")]
    _1Hour = 3600 * 1_000_000_000,
}

impl TimeType {
    #[inline]
    pub fn duration(&self) -> u64 {
        *self as u64
    }
}
