/// Stored ACL rule view.
#[derive(Debug, Clone, PartialEq)]
pub struct AclRuleView {
    pub ip_version: u8,
    pub direction: String,
    pub list_type: String,
    pub ip_address: String,
    pub port: u16,
}
