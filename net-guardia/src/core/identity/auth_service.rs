use std::sync::Arc;

use macros::log;
use serde::Serialize;

use crate::common::error::Error;
use crate::core::identity::user_service::role_from_group_names;
use crate::domain::identity::auth::{GROUP_ADMIN, GROUP_VIEWER, ROLE_ADMIN, ROLE_VIEWER};
use crate::domain::identity::error::{AuthError, LoginError, RegisterError};
use crate::domain::identity::validation::{validate_password, validate_username};
use crate::interface::identity::auth_repo::IdentityAuthRepo;
use crate::interface::identity::password_hasher::PasswordHasher;

pub const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$dW5rbm93bg$QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE";

pub struct AuthService {
    db: Arc<dyn IdentityAuthRepo>,
    password_hasher: Arc<dyn PasswordHasher>,
}

#[derive(Serialize)]
pub struct LoginResult {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub force_password_change: bool,
}

impl AuthService {
    pub fn new(db: Arc<dyn IdentityAuthRepo>, password_hasher: Arc<dyn PasswordHasher>) -> Self {
        Self { db, password_hasher }
    }

    pub async fn login(&self, username: &str, raw_password: &str) -> Result<LoginResult, LoginError> {
        match self.db.get_remaining_lock_secs(username).await {
            Ok(Some(remaining)) => {
                return Err(LoginError::Locked(remaining));
            }
            Ok(None) => {
                if let Err(e) = self.db.clear_expired_login_lock(username).await {
                    log!(AuthError::LoginLockoutLookupFailed(e));
                    return Err(LoginError::InternalError);
                }
            }
            Err(e) => {
                log!(AuthError::LoginLockoutLookupFailed(e));
                return Err(LoginError::InternalError);
            }
        }

        let user = match self.db.find_user(username).await {
            Ok(Some(u)) => u,
            _ => {
                let _ = self.password_hasher.verify_password(raw_password, DUMMY_HASH);
                if let Err(e) = self.db.record_login_failure(username).await {
                    log!(AuthError::LoginFailureTrackingError(e));
                }
                return Err(LoginError::InvalidCredentials);
            }
        };

        match self.password_hasher.verify_password(raw_password, &user.password_hash) {
            Ok(true) => {}
            _ => {
                if let Err(e) = self.db.record_login_failure(username).await {
                    log!(AuthError::LoginFailureTrackingError(e));
                }
                return Err(LoginError::InvalidCredentials);
            }
        }

        if let Err(e) = self.db.clear_login_failures(username).await {
            log!(AuthError::LoginClearError(e));
        }

        let mut permissions = self.db.list_user_permissions(user.id).await.map_err(|e| {
            log!(AuthError::PermissionLookupFailed(e));
            LoginError::InternalError
        })?;
        if user.force_password_change {
            permissions.clear();
        }
        let role = self.derive_role(user.id).await.map_err(|e| {
            log!(AuthError::GroupLookupFailed(e));
            LoginError::InternalError
        })?;

        Ok(LoginResult {
            user_id: user.id,
            username: user.username,
            role,
            permissions,
            force_password_change: user.force_password_change,
        })
    }

    pub async fn register(
        &self,
        username: &str,
        raw_password: &str,
        role: &str,
        caller_role: &str,
    ) -> Result<i64, RegisterError> {
        validate_username(username).map_err(RegisterError::Validation)?;
        validate_password(raw_password).map_err(RegisterError::Validation)?;

        if role != ROLE_ADMIN && role != ROLE_VIEWER {
            return Err(RegisterError::InvalidRole);
        }
        if role == ROLE_ADMIN && caller_role != ROLE_ADMIN {
            return Err(RegisterError::Forbidden);
        }

        let default_group = if role == ROLE_ADMIN { GROUP_ADMIN } else { GROUP_VIEWER };
        let default_group_id = self.default_group_id(default_group).await?;
        let hash = self
            .password_hasher
            .hash_password(raw_password)
            .map_err(|_| RegisterError::HashFailed)?;

        let new_id = self
            .db
            .insert_user(username, &hash, role, false)
            .await
            .map_err(RegisterError::Conflict)?;

        if let Err(e) = self.db.set_user_groups(new_id, &[default_group_id]).await {
            let message = e.to_string();
            log!(AuthError::GroupAssignmentFailed(e));
            if let Err(cleanup_err) = self.db.delete_user(new_id).await {
                log!(AuthError::GroupAssignmentFailed(cleanup_err));
            }
            return Err(RegisterError::Internal(message));
        }

        Ok(new_id)
    }

    async fn default_group_id(&self, group_name: &str) -> Result<i64, RegisterError> {
        let groups = self.db.list_user_groups().await.map_err(RegisterError::Internal)?;
        groups
            .into_iter()
            .find(|group| group.name == group_name)
            .map(|group| group.id)
            .ok_or_else(|| RegisterError::Internal(format!("Default group '{group_name}' is missing")))
    }

    async fn derive_role(&self, user_id: i64) -> Result<String, Error> {
        let groups = self.db.list_groups_for_user(user_id).await?;
        Ok(role_from_group_names(groups.iter().map(|group| group.name.as_str())).to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::*;
    use crate::adapter::identity::password_hasher::Argon2PasswordHasher;
    use crate::adapter::persistence::Database;
    use crate::common::error::Error;
    use crate::common::error::database::DatabaseError;
    use crate::domain::identity::auth::{GROUP_ADMIN, GROUP_VIEWER, ROLE_ADMIN, ROLE_VIEWER};
    use crate::domain::identity::user::{GroupMemberView, UserGroupView, UserView, UserWithGroupsView};
    use crate::interface::identity::auth_repo::{IdentityAuthRepo, LoginAttemptRepo, UserGroupRepo, UserRepo};
    use crate::interface::identity::password_hasher::PasswordHasher;

    struct FailingLockoutRepo;

    fn test_db_error() -> Error {
        DatabaseError::PersistedValueInvalid("login_attempts", "locked_until", "bad").into()
    }

    #[async_trait]
    impl UserRepo for FailingLockoutRepo {
        async fn find_user(&self, _username: &str) -> Result<Option<UserView>, Error> {
            Ok(None)
        }

        async fn find_user_by_id(&self, _user_id: i64) -> Result<Option<UserView>, Error> {
            Ok(None)
        }

        async fn list_users_with_groups(&self) -> Result<Vec<UserWithGroupsView>, Error> {
            Ok(Vec::new())
        }

        async fn insert_user(
            &self,
            _username: &str,
            _password_hash: &str,
            _role: &str,
            _force_password_change: bool,
        ) -> Result<i64, Error> {
            Err(test_db_error())
        }

        async fn update_user_password(&self, _user_id: i64, _password_hash: &str) -> Result<(), Error> {
            Err(test_db_error())
        }

        async fn update_user_role(&self, _user_id: i64, _role: &str) -> Result<(), Error> {
            Err(test_db_error())
        }

        async fn reset_user_password(&self, _user_id: i64, _password_hash: &str) -> Result<(), Error> {
            Err(test_db_error())
        }

        async fn delete_user(&self, _user_id: i64) -> Result<bool, Error> {
            Err(test_db_error())
        }
    }

    #[async_trait]
    impl UserGroupRepo for FailingLockoutRepo {
        async fn get_user_group(&self, _id: i64) -> Result<Option<UserGroupView>, Error> {
            Ok(None)
        }

        async fn list_user_groups(&self) -> Result<Vec<UserGroupView>, Error> {
            Ok(Vec::new())
        }

        async fn list_groups_for_user(&self, _user_id: i64) -> Result<Vec<UserGroupView>, Error> {
            Ok(Vec::new())
        }

        async fn list_user_permissions(&self, _user_id: i64) -> Result<Vec<String>, Error> {
            Ok(Vec::new())
        }

        async fn list_group_member_ids(&self, _group_id: i64) -> Result<Vec<i64>, Error> {
            Ok(Vec::new())
        }

        async fn list_group_members(&self, _group_id: i64) -> Result<Vec<GroupMemberView>, Error> {
            Ok(Vec::new())
        }

        async fn create_user_group(&self, _name: &str, _description: &str, _permissions: &str) -> Result<i64, Error> {
            Err(test_db_error())
        }

        async fn update_user_group(
            &self,
            _id: i64,
            _name: &str,
            _description: &str,
            _permissions: &str,
        ) -> Result<(), Error> {
            Err(test_db_error())
        }

        async fn set_user_groups(&self, _user_id: i64, _group_ids: &[i64]) -> Result<(), Error> {
            Err(test_db_error())
        }

        async fn delete_user_group(&self, _id: i64) -> Result<bool, Error> {
            Err(test_db_error())
        }
    }

    #[async_trait]
    impl LoginAttemptRepo for FailingLockoutRepo {
        async fn get_remaining_lock_secs(&self, _username: &str) -> Result<Option<u64>, Error> {
            Err(test_db_error())
        }

        async fn clear_expired_login_lock(&self, _username: &str) -> Result<(), Error> {
            Err(test_db_error())
        }

        async fn record_login_failure(&self, _username: &str) -> Result<(u32, Option<u64>), Error> {
            Err(test_db_error())
        }

        async fn clear_login_failures(&self, _username: &str) -> Result<(), Error> {
            Err(test_db_error())
        }
    }

    async fn auth_fixture() -> (Arc<Database>, AuthService) {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));
        let auth = AuthService::new(db.clone() as Arc<dyn IdentityAuthRepo>, Arc::new(Argon2PasswordHasher));
        (db, auth)
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
    async fn login_lockout_lookup_error_fails_closed() {
        let auth = AuthService::new(Arc::new(FailingLockoutRepo), Arc::new(Argon2PasswordHasher));

        let result = auth.login("alice", "Correct Horse 123!").await;

        assert!(matches!(result, Err(LoginError::InternalError)));
    }

    #[tokio::test]
    async fn force_password_change_login_has_no_admin_permissions() {
        let (db, auth) = auth_fixture().await;
        let hasher = Argon2PasswordHasher;
        let hash = hasher.hash_password("Default Admin 123!").expect("hash");
        let user_id = db
            .insert_user("setup_admin", &hash, ROLE_ADMIN, true)
            .await
            .expect("insert admin");
        let admin_group = db
            .list_user_groups()
            .await
            .expect("groups")
            .into_iter()
            .find(|g| g.name == GROUP_ADMIN)
            .expect("admin group");
        db.set_user_groups(user_id, &[admin_group.id])
            .await
            .expect("assign admin group");

        let login = auth.login("setup_admin", "Default Admin 123!").await.expect("login");

        assert!(login.force_password_change);
        assert!(login.permissions.is_empty());
    }

    #[tokio::test]
    async fn relogin_permissions_follow_role_promotion_and_demotion() {
        let (db, auth) = auth_fixture().await;
        let user_id = create_viewer(&db, "alice", "Correct Horse 123!").await;

        db.update_user_role(user_id, ROLE_ADMIN).await.expect("promote");
        let promoted = auth.login("alice", "Correct Horse 123!").await.expect("login");
        assert_eq!(promoted.role, ROLE_ADMIN);
        assert!(promoted.permissions.contains(&"users:admin".to_string()));

        db.update_user_role(user_id, ROLE_VIEWER).await.expect("demote");
        let demoted = auth.login("alice", "Correct Horse 123!").await.expect("login");
        assert_eq!(demoted.role, ROLE_VIEWER);
        assert!(!demoted.permissions.contains(&"users:admin".to_string()));
    }

    #[tokio::test]
    async fn register_assigns_default_group_before_returning_success() {
        let (db, auth) = auth_fixture().await;

        let user_id = auth
            .register("bob", "Correct Horse 123!", ROLE_ADMIN, ROLE_ADMIN)
            .await
            .expect("register admin");

        let groups = db.list_groups_for_user(user_id).await.expect("user groups");
        assert!(groups.iter().any(|group| group.name == GROUP_ADMIN));
    }

    #[tokio::test]
    async fn register_fails_without_creating_user_when_default_group_is_missing() {
        let (db, auth) = auth_fixture().await;
        let admin_group = db
            .list_user_groups()
            .await
            .expect("groups")
            .into_iter()
            .find(|group| group.name == GROUP_ADMIN)
            .expect("admin group");
        db.delete_user_group(admin_group.id).await.expect("delete admin group");

        let err = auth
            .register("carol", "Correct Horse 123!", ROLE_ADMIN, ROLE_ADMIN)
            .await
            .expect_err("missing default group should fail registration");

        assert!(matches!(err, RegisterError::Internal { .. }));
        assert!(db.find_user("carol").await.expect("find user").is_none());
    }
}
