use crate::interface::communication::command::Command;
use crate::interface::communication::message::Message;

// ── ACL Commands ─────────────────────────────────────────────────────

pub struct AddAclRuleCommand {
    pub ip_version: u8,
    pub direction: String,
    pub list_type: String,
    pub ip_address: String,
    pub port: u16,
}

impl Message for AddAclRuleCommand {
    type Response = ();
}
impl Command for AddAclRuleCommand {}

pub struct RemoveAclRuleCommand {
    pub ip_version: u8,
    pub direction: String,
    pub list_type: String,
    pub ip_address: String,
    pub port: u16,
}

impl Message for RemoveAclRuleCommand {
    type Response = ();
}
impl Command for RemoveAclRuleCommand {}

// ── Geo Commands ─────────────────────────────────────────────────────

pub struct BlockGeoCountriesCommand {
    pub country_codes: Vec<String>,
}

impl Message for BlockGeoCountriesCommand {
    type Response = ();
}
impl Command for BlockGeoCountriesCommand {}

pub struct UnblockGeoCountriesCommand {
    pub country_codes: Vec<String>,
}

impl Message for UnblockGeoCountriesCommand {
    type Response = ();
}
impl Command for UnblockGeoCountriesCommand {}

// ── DNS Commands ─────────────────────────────────────────────────────

pub struct AddDnsDomainCommand {
    pub domain: String,
}

impl Message for AddDnsDomainCommand {
    type Response = ();
}
impl Command for AddDnsDomainCommand {}

pub struct RemoveDnsDomainCommand {
    pub domain: String,
}

impl Message for RemoveDnsDomainCommand {
    type Response = ();
}
impl Command for RemoveDnsDomainCommand {}

// ── Rate Limit Commands ──────────────────────────────────────────────

pub struct SetRateLimitCommand {
    pub key: String,
    pub value: u64,
}

impl Message for SetRateLimitCommand {
    type Response = ();
}
impl Command for SetRateLimitCommand {}

// ── System Commands ──────────────────────────────────────────────────

pub struct ChangeEnforceModeCommand {
    pub mode: String,
}

impl Message for ChangeEnforceModeCommand {
    type Response = ();
}
impl Command for ChangeEnforceModeCommand {}

// ── Auth Commands ────────────────────────────────────────────────────

pub struct ChangePasswordCommand {
    pub user_id: i64,
    pub new_password_hash: String,
}

impl Message for ChangePasswordCommand {
    type Response = ();
}
impl Command for ChangePasswordCommand {}

pub struct RegisterUserCommand {
    pub username: String,
    pub password_hash: String,
    pub role: String,
}

impl Message for RegisterUserCommand {
    type Response = ();
}
impl Command for RegisterUserCommand {}
