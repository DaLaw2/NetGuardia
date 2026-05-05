/// Stored user record.
#[derive(Debug, Clone)]
pub struct UserView {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub force_password_change: bool,
}

/// User with resolved group memberships.
#[derive(Debug, Clone)]
pub struct UserWithGroupsView {
    pub id: i64,
    pub username: String,
    pub force_password_change: bool,
    pub created_at: String,
    pub groups: Vec<UserGroupMembership>,
}

/// Minimal group membership info embedded in user views.
#[derive(Debug, Clone)]
pub struct UserGroupMembership {
    pub group_id: i64,
    pub group_name: String,
}

/// Stored user group record.
#[derive(Debug, Clone)]
pub struct UserGroupView {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub permissions: String,
    pub created_at: String,
}

/// Minimal group member info for group detail views.
#[derive(Debug, Clone)]
pub struct GroupMemberView {
    pub id: i64,
    pub username: String,
}

/// API key list entry.
#[derive(Debug, Clone)]
pub struct ApiKeyView {
    pub id: i64,
    pub name: String,
    pub permission_level: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}
