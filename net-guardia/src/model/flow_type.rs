#[derive(Copy, Clone)]
pub enum IPv4FlowType {
    SrcIPv4_1Min,
    SrcIPv4_10Min,
    SrcIPv4_1Hour,
    DstIPv4_1Min,
    DstIPv4_10Min,
    DstIPv4_1Hour,
}
#[derive(Copy, Clone)]
pub enum IPv6FlowType {
    SrcIPv6_1Min,
    SrcIPv6_10Min,
    SrcIPv6_1Hour,
    DstIPv6_1Min,
    DstIPv6_10Min,
    DstIPv6_1Hour,
}
