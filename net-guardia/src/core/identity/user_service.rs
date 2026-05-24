use std::sync::Arc;

use serde::Serialize;

use crate::common::error::Error;
use crate::common::error::codec::CodecError;
use crate::domain::identity::auth::{DEFAULT_ADMIN_USERNAME, GROUP_ADMIN, ROLE_ADMIN, ROLE_VIEWER};
use crate::domain::identity::error::UserError;
use crate::domain::identity::validation::validate_password;
use crate::interface::identity::auth_repo::{UserGroupRepo, UserRepo};
use crate::interface::identity::password_hasher::PasswordHasher;

#[derive(Serialize)]
pub struct UserProfile {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub groups: Vec<String>,
}

#[derive(Serialize)]
pub struct UserListResponse {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub force_password_change: bool,
    pub created_at: String,
    pub groups: Vec<UserGroupMembershipResponse>,
}

#[derive(Serialize)]
pub struct UserGroupMembershipResponse {
    pub id: i64,
    pub name: String,
}

pub struct UserService {
    db: Arc<dyn UserRepo>,
    group_db: Arc<dyn UserGroupRepo>,
    password_hasher: Arc<dyn PasswordHasher>,
}

impl UserService {
    pub fn new(
        db: Arc<dyn UserRepo>,
        group_db: Arc<dyn UserGroupRepo>,
        password_hasher: Arc<dyn PasswordHasher>,
    ) -> Self {
        Self {
            db,
            group_db,
            password_hasher,
        }
    }

    pub async fn user_profile(&self, user_id: i64, username: &str) -> Result<UserProfile, Error> {
        let groups_raw = self.group_db.list_groups_for_user(user_id).await?;
        let role = role_from_group_names(groups_raw.iter().map(|group| group.name.as_str())).to_string();
        let groups = groups_raw.into_iter().map(|group| group.name).collect();
        let permissions = self.group_db.list_user_permissions(user_id).await?;

        Ok(UserProfile {
            id: user_id,
            username: username.to_string(),
            role,
            permissions,
            groups,
        })
    }

    pub async fn list_users(&self) -> Result<Vec<UserListResponse>, Error> {
        let users = self.db.list_users_with_groups().await?;
        Ok(users
            .into_iter()
            .map(|user| {
                let role = role_from_group_names(user.groups.iter().map(|group| group.group_name.as_str())).to_string();
                let groups: Vec<UserGroupMembershipResponse> = user
                    .groups
                    .into_iter()
                    .map(|group| UserGroupMembershipResponse {
                        id: group.group_id,
                        name: group.group_name,
                    })
                    .collect();
                UserListResponse {
                    id: user.id,
                    username: user.username,
                    role,
                    force_password_change: user.force_password_change,
                    created_at: user.created_at,
                    groups,
                }
            })
            .collect())
    }

    pub async fn change_password(
        &self,
        user_id: i64,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), UserError> {
        validate_password(new_password).map_err(|msg| UserError::Validation(msg.to_string()))?;

        let user = self
            .db
            .find_user_by_id(user_id)
            .await
            .map_err(UserError::Internal)?
            .ok_or_else(|| UserError::NotFound("User not found".to_string()))?;

        match self
            .password_hasher
            .verify_password(current_password, &user.password_hash)
        {
            Ok(true) => {}
            _ => return Err(UserError::Unauthorized),
        }

        let new_hash = self
            .password_hasher
            .hash_password(new_password)
            .map_err(|_| UserError::HashFailed)?;
        self.db
            .update_user_password(user_id, &new_hash)
            .await
            .map_err(UserError::Internal)
    }

    pub async fn delete_user(&self, caller_user_id: i64, target_user_id: i64) -> Result<bool, UserError> {
        if caller_user_id == target_user_id {
            return Err(UserError::Validation("Cannot delete your own account".to_string()));
        }

        let user = self
            .db
            .find_user_by_id(target_user_id)
            .await
            .map_err(UserError::Internal)?;
        if let Some(user) = user.as_ref()
            && user.username == DEFAULT_ADMIN_USERNAME
        {
            return Err(UserError::Forbidden(
                "Cannot delete the built-in admin account".to_string(),
            ));
        }

        self.db.delete_user(target_user_id).await.map_err(UserError::Internal)
    }

    pub async fn update_role(&self, caller_user_id: i64, target_user_id: i64, role: &str) -> Result<(), UserError> {
        if caller_user_id == target_user_id {
            return Err(UserError::Validation("Cannot change your own role".to_string()));
        }
        if role != ROLE_ADMIN && role != ROLE_VIEWER {
            return Err(UserError::Validation("Role must be 'admin' or 'viewer'".to_string()));
        }

        let user = self
            .db
            .find_user_by_id(target_user_id)
            .await
            .map_err(UserError::Internal)?
            .ok_or_else(|| UserError::NotFound("User not found".to_string()))?;

        if user.username == DEFAULT_ADMIN_USERNAME {
            return Err(UserError::Forbidden(
                "Cannot change the built-in admin account role".to_string(),
            ));
        }

        self.db
            .update_user_role(target_user_id, role)
            .await
            .map_err(UserError::Internal)
    }

    pub async fn reset_password(&self, target_user_id: i64, new_password: &str) -> Result<(), UserError> {
        validate_password(new_password).map_err(|msg| UserError::Validation(msg.to_string()))?;

        self.db
            .find_user_by_id(target_user_id)
            .await
            .map_err(UserError::Internal)?
            .ok_or_else(|| UserError::NotFound("User not found".to_string()))?;

        let hash = self
            .password_hasher
            .hash_password(new_password)
            .map_err(|_| UserError::HashFailed)?;
        self.db
            .reset_user_password(target_user_id, &hash)
            .await
            .map_err(UserError::Internal)
    }

    pub async fn set_user_groups(
        &self,
        caller_user_id: i64,
        target_user_id: i64,
        group_ids: &[i64],
    ) -> Result<(), UserError> {
        if caller_user_id == target_user_id {
            return Err(UserError::Validation("Cannot modify your own groups".to_string()));
        }

        let user = self
            .db
            .find_user_by_id(target_user_id)
            .await
            .map_err(UserError::Internal)?
            .ok_or_else(|| UserError::NotFound("User not found".to_string()))?;

        if user.username == DEFAULT_ADMIN_USERNAME {
            return Err(UserError::Forbidden(
                "Cannot modify groups for the built-in admin account".to_string(),
            ));
        }

        self.group_db
            .set_user_groups(target_user_id, group_ids)
            .await
            .map_err(UserError::Internal)
    }
}

pub fn parse_permissions(raw: &str) -> Result<serde_json::Value, Error> {
    let parsed = serde_json::from_str(raw).map_err(CodecError::DeserializeFailed)?;
    Ok(parsed)
}

pub fn role_from_group_names<'a>(names: impl IntoIterator<Item = &'a str>) -> &'static str {
    if names.into_iter().any(|name| name == GROUP_ADMIN) {
        ROLE_ADMIN
    } else {
        ROLE_VIEWER
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::adapter::identity::password_hasher::Argon2PasswordHasher;
    use crate::adapter::persistence::Database;
    use crate::domain::identity::auth::{GROUP_ADMIN, GROUP_VIEWER, ROLE_ADMIN, ROLE_VIEWER};
    use crate::interface::identity::auth_repo::{UserGroupRepo, UserRepo};
    use crate::interface::identity::password_hasher::PasswordHasher;

    async fn user_service_fixture() -> (Arc<Database>, UserService) {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));
        let svc = UserService::new(
            db.clone() as Arc<dyn UserRepo>,
            db.clone() as Arc<dyn UserGroupRepo>,
            Arc::new(Argon2PasswordHasher),
        );
        (db, svc)
    }

    async fn create_viewer(db: &Database, username: &str, password: &str) -> i64 {
        let hasher = Argon2PasswordHasher;
        let hash = hasher.hash_password(password).expect("hash");
        let user_id = db
            .insert_user(username, &hash, ROLE_VIEWER, false)
            .await
            .expect("insert user");
        let viewer_group = db
            .list_user_groups()
            .await
            .expect("groups")
            .into_iter()
            .find(|g| g.name == GROUP_VIEWER)
            .expect("viewer group");
        db.set_user_groups(user_id, &[viewer_group.id])
            .await
            .expect("assign viewer group");
        user_id
    }

    #[tokio::test]
    async fn change_password_verifies_current_password_and_updates_hash() {
        let (db, svc) = user_service_fixture().await;
        let user_id = create_viewer(&db, "alice", "Correct Horse 123!").await;

        svc.change_password(user_id, "Correct Horse 123!", "New Password 456!")
            .await
            .expect("change password");

        let user = db.find_user("alice").await.expect("find user").expect("user exists");
        let hasher = Argon2PasswordHasher;
        assert!(
            !hasher
                .verify_password("Correct Horse 123!", &user.password_hash)
                .expect("verify old")
        );
        assert!(
            hasher
                .verify_password("New Password 456!", &user.password_hash)
                .expect("verify new")
        );
        assert!(!user.force_password_change);
    }

    #[tokio::test]
    async fn change_password_verifies_password_for_target_user_id() {
        let (db, svc) = user_service_fixture().await;
        let alice_id = create_viewer(&db, "alice", "Correct Horse 123!").await;
        create_viewer(&db, "bob", "Bob Password 123!").await;

        let err = svc
            .change_password(alice_id, "Bob Password 123!", "New Password 456!")
            .await
            .expect_err("another user's password must not authorize the change");

        assert!(matches!(err, UserError::Unauthorized));

        let alice = db.find_user("alice").await.expect("find user").expect("user exists");
        let hasher = Argon2PasswordHasher;
        assert!(
            hasher
                .verify_password("Correct Horse 123!", &alice.password_hash)
                .expect("verify alice password")
        );
    }

    #[tokio::test]
    async fn update_role_rejects_self_change_before_db_update() {
        let (db, svc) = user_service_fixture().await;
        let user_id = create_viewer(&db, "alice", "Correct Horse 123!").await;

        let err = svc
            .update_role(user_id, user_id, ROLE_ADMIN)
            .await
            .expect_err("self role change should be rejected");

        assert!(matches!(err, UserError::Validation { .. }));
    }

    #[tokio::test]
    async fn update_role_rejects_builtin_admin_role_change() {
        let (db, svc) = user_service_fixture().await;
        let hasher = Argon2PasswordHasher;
        let hash = hasher.hash_password("Default Admin 123!").expect("hash");
        let admin_id = db
            .insert_user(DEFAULT_ADMIN_USERNAME, &hash, ROLE_ADMIN, false)
            .await
            .expect("insert built-in admin");
        let admin_group = db
            .list_user_groups()
            .await
            .expect("groups")
            .into_iter()
            .find(|g| g.name == GROUP_ADMIN)
            .expect("admin group");
        db.set_user_groups(admin_id, &[admin_group.id])
            .await
            .expect("assign admin group");

        let err = svc
            .update_role(999, admin_id, ROLE_VIEWER)
            .await
            .expect_err("built-in admin role change should be rejected");

        assert!(matches!(err, UserError::Forbidden { .. }));
        let groups = db.list_groups_for_user(admin_id).await.expect("admin groups");
        assert!(groups.iter().any(|group| group.name == GROUP_ADMIN));
    }

    #[tokio::test]
    async fn reset_password_marks_force_password_change() {
        let (db, svc) = user_service_fixture().await;
        let user_id = create_viewer(&db, "alice", "Correct Horse 123!").await;

        svc.reset_password(user_id, "Reset Password 456!")
            .await
            .expect("reset password");

        let user = db.find_user("alice").await.expect("find user").expect("user exists");
        let hasher = Argon2PasswordHasher;
        assert!(
            hasher
                .verify_password("Reset Password 456!", &user.password_hash)
                .expect("verify reset")
        );
        assert!(user.force_password_change);
    }

    #[tokio::test]
    async fn set_user_groups_rejects_self_membership_change() {
        let (db, svc) = user_service_fixture().await;
        let user_id = create_viewer(&db, "alice", "Correct Horse 123!").await;

        let err = svc
            .set_user_groups(user_id, user_id, &[])
            .await
            .expect_err("self group change should be rejected");

        assert!(matches!(err, UserError::Validation { .. }));
        assert!(!db.list_groups_for_user(user_id).await.expect("groups").is_empty());
    }
}
