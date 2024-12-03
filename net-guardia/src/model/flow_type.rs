use serde::Deserialize;

#[derive(Deserialize, Debug, Copy, Clone)]
pub enum IPv4FlowType {
    Src1Min,
    Src10Min,
    Src1Hour,
    Dst1Min,
    Dst10Min,
    Dst1Hour,
}

#[derive(Deserialize, Debug, Copy, Clone)]
pub enum IPv6FlowType {
    Src1Min,
    Src10Min,
    Src1Hour,
    Dst1Min,
    Dst10Min,
    Dst1Hour,
}
