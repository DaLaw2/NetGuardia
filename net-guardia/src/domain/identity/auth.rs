use serde::{Deserialize, Serialize};

pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_VIEWER: &str = "viewer";
pub const GROUP_ADMIN: &str = "Administrator";
pub const GROUP_VIEWER: &str = "Viewer";
pub const DEFAULT_ADMIN_USERNAME: &str = "admin";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: i64,
    pub username: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub exp: usize,
}
