#[derive(Debug, Clone)]
pub struct UserView {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub force_password_change: bool,
}

#[derive(Debug, Clone)]
pub struct UserWithGroupsView {
    pub id: i64,
    pub username: String,
    pub force_password_change: bool,
    pub created_at: String,
    pub groups: Vec<UserGroupMembership>,
}

#[derive(Debug, Clone)]
pub struct UserGroupMembership {
    pub group_id: i64,
    pub group_name: String,
}

#[derive(Debug, Clone)]
pub struct UserGroupView {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub permissions: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct GroupMemberView {
    pub id: i64,
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct ApiKeyView {
    pub id: i64,
    pub name: String,
    pub permission_level: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}
