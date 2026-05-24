pub const HTTP_FALLBACK_PORT: u16 = 8080;
pub const FUSION_AUDIT_ACTOR: &str = "FusionEngine";
pub const FUSION_AUDIT_ACTION: &str = "fused_threat_emitted";
pub const AUDIT_ACTOR_SECURITY_ADMIN_PREFIX: &str = "SecurityAdmin";
pub const PERMISSION_SYSTEM_ADMIN: &str = "system:admin";
pub const PERMISSION_USERS_ADMIN: &str = "users:admin";
pub const PERMISSION_API_KEYS_ADMIN: &str = "api_keys:admin";
pub const PERMISSION_ACCESS_CONTROL_WRITE: &str = "access_control:write";
pub const PERMISSION_DASHBOARD_READ: &str = "dashboard:read";
pub const PERMISSION_AI_DETECTION_READ: &str = "ai_detection:read";
pub const PERMISSION_FUSION_READ: &str = "fusion:read";
pub const PERMISSION_TRAFFIC_MAP_READ: &str = "traffic_map:read";
pub const PERMISSION_DROPS_READ: &str = "drops:read";
pub const ENFORCE_MODE_MONITOR: &str = "monitor";
pub const ENFORCE_MODE_ML_ONLY: &str = "ml_only";
pub const ENFORCE_MODE_ENFORCE: &str = "enforce";

pub const KNOWN_C2_PORTS: &[u16] = &[4444, 8443, 8080, 1337, 31337];
