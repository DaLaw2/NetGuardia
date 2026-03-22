use crate::interface::communication::message::Message;
use crate::interface::communication::query::Query;
use crate::model::health::{SystemHealthMetrics, SystemHealthStatus};

// ── System Queries ───────────────────────────────────────────────────

pub struct GetEnforceModeQuery;

impl Message for GetEnforceModeQuery {
    type Response = String;
}
impl Query for GetEnforceModeQuery {}

pub struct GetXdpModeQuery;

impl Message for GetXdpModeQuery {
    type Response = XdpModeResponse;
}
impl Query for GetXdpModeQuery {}

#[derive(Debug, Clone)]
pub struct XdpModeResponse {
    pub ingress_mode: String,
    pub egress_mode: String,
}

// ── Health Queries ───────────────────────────────────────────────────

pub struct GetHealthMetricsQuery;

impl Message for GetHealthMetricsQuery {
    type Response = SystemHealthMetrics;
}
impl Query for GetHealthMetricsQuery {}

pub struct GetHealthStatusQuery;

impl Message for GetHealthStatusQuery {
    type Response = SystemHealthStatus;
}
impl Query for GetHealthStatusQuery {}

// ── ACL Queries ──────────────────────────────────────────────────────

pub struct GetAclRulesQuery;

impl Message for GetAclRulesQuery {
    type Response = Vec<(u8, String, String, String, u16)>;
}
impl Query for GetAclRulesQuery {}

// ── Settings Queries ─────────────────────────────────────────────────

pub struct GetSettingQuery {
    pub key: String,
}

impl Message for GetSettingQuery {
    type Response = Option<String>;
}
impl Query for GetSettingQuery {}

// ── Rate Limit Queries ───────────────────────────────────────────────

pub struct GetRateLimitConfigQuery;

impl Message for GetRateLimitConfigQuery {
    type Response = Vec<(String, u64)>;
}
impl Query for GetRateLimitConfigQuery {}

// ── DNS Queries ──────────────────────────────────────────────────────

pub struct GetDnsDomainsQuery;

impl Message for GetDnsDomainsQuery {
    type Response = Vec<String>;
}
impl Query for GetDnsDomainsQuery {}

// ── Geo Queries ──────────────────────────────────────────────────────

pub struct GetGeoBlockedCountriesQuery;

impl Message for GetGeoBlockedCountriesQuery {
    type Response = Vec<String>;
}
impl Query for GetGeoBlockedCountriesQuery {}
