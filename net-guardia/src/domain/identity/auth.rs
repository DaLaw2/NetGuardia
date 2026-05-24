use serde::{Deserialize, Serialize};

pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_VIEWER: &str = "viewer";
pub const GROUP_ADMIN: &str = "Administrator";
pub const GROUP_VIEWER: &str = "Viewer";
pub const DEFAULT_ADMIN_USERNAME: &str = "admin";
pub const LOGIN_MAX_FAILURES: u32 = 5;
pub const LOGIN_LOCKOUT_SECS: u64 = 900;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionLevel {
    ReadOnly,
    ReadWrite,
    FullAccess,
}

impl PermissionLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::ReadWrite => "read_write",
            Self::FullAccess => "full_access",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "read_only" => Some(Self::ReadOnly),
            "read_write" => Some(Self::ReadWrite),
            "full_access" => Some(Self::FullAccess),
            _ => None,
        }
    }

    pub fn permissions(self) -> &'static [&'static str] {
        match self {
            Self::ReadOnly => API_KEY_READ_ONLY_PERMISSIONS,
            Self::ReadWrite => API_KEY_READ_WRITE_PERMISSIONS,
            Self::FullAccess => API_KEY_FULL_ACCESS_PERMISSIONS,
        }
    }
}

pub const ADMIN_PERMISSIONS: &[&str] = &[
    "dashboard:read",
    "statistics:read",
    "traffic_map:read",
    "drops:read",
    "ai_detection:read",
    "ai_detection:write",
    "access_control:read",
    "access_control:write",
    "geo_block:read",
    "geo_block:write",
    "dns_filter:read",
    "dns_filter:write",
    "rate_limit:read",
    "rate_limit:write",
    "protocol_filter:read",
    "protocol_filter:write",
    "system:read",
    "system:write",
    "system:admin",
    "api_keys:admin",
    "users:read",
    "users:write",
    "users:admin",
    "fusion:read",
    "fusion:write",
    "flow_trace:read",
    "flow_trace:write",
];

pub const VIEWER_PERMISSIONS: &[&str] = &[
    "dashboard:read",
    "statistics:read",
    "traffic_map:read",
    "drops:read",
    "ai_detection:read",
    "access_control:read",
    "geo_block:read",
    "dns_filter:read",
    "rate_limit:read",
    "protocol_filter:read",
    "system:read",
    "fusion:read",
    "flow_trace:read",
];

pub const API_KEY_READ_WRITE_PERMISSIONS: &[&str] = &[
    "dashboard:read",
    "statistics:read",
    "ai_detection:read",
    "ai_detection:write",
    "access_control:read",
    "access_control:write",
    "geo_block:read",
    "geo_block:write",
    "dns_filter:read",
    "dns_filter:write",
    "rate_limit:read",
    "rate_limit:write",
    "system:read",
    "system:write",
];

pub const API_KEY_READ_ONLY_PERMISSIONS: &[&str] = &[
    "dashboard:read",
    "statistics:read",
    "ai_detection:read",
    "access_control:read",
    "geo_block:read",
    "dns_filter:read",
    "rate_limit:read",
    "system:read",
];

pub const API_KEY_FULL_ACCESS_PERMISSIONS: &[&str] = ADMIN_PERMISSIONS;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: i64,
    pub username: String,
    pub role: String,
    pub permissions: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::PermissionLevel;

    #[test]
    fn read_write_api_keys_do_not_receive_admin_permissions() {
        let permissions = PermissionLevel::ReadWrite.permissions();

        assert!(!permissions.contains(&"api_keys:admin"));
        assert!(!permissions.contains(&"system:admin"));
        assert!(!permissions.contains(&"users:admin"));
    }

    #[test]
    fn full_access_api_keys_receive_admin_permissions() {
        let permissions = PermissionLevel::FullAccess.permissions();

        assert!(permissions.contains(&"api_keys:admin"));
        assert!(permissions.contains(&"system:admin"));
        assert!(permissions.contains(&"users:admin"));
    }

    #[test]
    fn full_access_has_more_permissions_than_read_write() {
        assert!(PermissionLevel::FullAccess.permissions().len() > PermissionLevel::ReadWrite.permissions().len());
    }
}
