use crate::domain::data_plane::direction::FlowDirection;
use crate::domain::data_plane::ip_version::IpVersion;
use crate::domain::data_plane::list_type::ListType;

#[derive(Debug, Clone, PartialEq)]
pub struct AclRuleView {
    pub ip_version: IpVersion,
    pub direction: FlowDirection,
    pub list_type: ListType,
    pub ip_address: String,
    pub port: u16,
}
