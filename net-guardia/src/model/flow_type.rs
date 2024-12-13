use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum FlowType {
    #[serde(rename = "src_1min")]
    Src1Min,
    #[serde(rename = "src_10min")]
    Src10Min,
    #[serde(rename = "src_1hour")]
    Src1Hour,
    #[serde(rename = "dst_1min")]
    Dst1Min,
    #[serde(rename = "dst_10min")]
    Dst10Min,
    #[serde(rename = "dst_1hour")]
    Dst1Hour,
}
