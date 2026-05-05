use std::sync::Arc;

use macros::log;
use serde::Serialize;

use crate::domain::common::error::Error;
use crate::domain::identity::auth::{GROUP_ADMIN, GROUP_VIEWER, ROLE_ADMIN, ROLE_VIEWER};
use crate::domain::identity::error::AuthError;
use crate::domain::identity::password;
use crate::domain::identity::validation::{validate_password, validate_username};
use crate::interface::app_repo::AppRepo;
use crate::interface::token_minter::TokenMinter;

pub const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$dW5rbm93bg$QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE";

pub struct AuthService {
    db: Arc<dyn AppRepo>,
    jwt: Arc<dyn TokenMinter>,
}

#[derive(Serialize)]
pub struct LoginResult {
    pub token: String,
    pub role: String,
    pub force_password_change: bool,
}

#[derive(Serialize)]
pub struct UserProfile {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub groups: Vec<String>,
}

#[derive(Debug)]
pub enum LoginError {
    Locked { retry_after_secs: u64 },
    InvalidCredentials,
    InternalError,
}

pub enum RegisterError {
    Validation(&'static str),
    InvalidRole,
    Forbidden,
    HashFailed,
    Conflict(Error),
}

impl AuthService {
    pub fn new(db: Arc<dyn AppRepo>, jwt: Arc<dyn TokenMinter>) -> Self {
        Self { db, jwt }
    }

    pub async fn login(&self, username: &str, raw_password: &str) -> Result<LoginResult, LoginError> {
        if let Ok(Some(remaining)) = self.db.check_login_locked(username).await {
            return Err(LoginError::Locked {
                retry_after_secs: remaining,
            });
        }

        let user = match self.db.find_user(username).await {
            Ok(Some(u)) => u,
            _ => {
                let _ = password::verify_password(raw_password, DUMMY_HASH);
                if let Err(e) = self.db.record_login_failure(username).await {
                    log!(AuthError::LoginFailureTrackingError(e));
                }
                return Err(LoginError::InvalidCredentials);
            }
        };

        match password::verify_password(raw_password, &user.password_hash) {
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

        let permissions = self.db.list_user_permissions(user.id).await.unwrap_or_default();
        let role = self.derive_role(user.id).await;

        let token = self
            .jwt
            .create_token(user.id, &user.username, &role, permissions)
            .map_err(|_| LoginError::InternalError)?;

        Ok(LoginResult {
            token,
            role,
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

        let hash = password::hash_password(raw_password).map_err(|_| RegisterError::HashFailed)?;

        let new_id = self
            .db
            .insert_user(username, &hash, role, false)
            .await
            .map_err(RegisterError::Conflict)?;

        let default_group = if role == ROLE_ADMIN { GROUP_ADMIN } else { GROUP_VIEWER };
        if let Ok(groups) = self.db.list_user_groups().await
            && let Some(g) = groups.into_iter().find(|g| g.name == default_group)
            && let Err(e) = self.db.set_user_groups(new_id, &[g.id]).await
        {
            log!(AuthError::GroupAssignmentFailed(e));
        }

        Ok(new_id)
    }

    pub async fn user_profile(&self, user_id: i64, username: &str) -> UserProfile {
        let groups_raw = self.db.list_groups_for_user(user_id).await.unwrap_or_default();
        let group_names: Vec<String> = groups_raw.iter().map(|g| g.name.clone()).collect();
        let role = if group_names.iter().any(|n| n == GROUP_ADMIN) {
            ROLE_ADMIN.to_string()
        } else {
            ROLE_VIEWER.to_string()
        };
        let permissions = self.db.list_user_permissions(user_id).await.unwrap_or_default();

        UserProfile {
            id: user_id,
            username: username.to_string(),
            role,
            permissions,
            groups: group_names,
        }
    }

    pub async fn derive_role(&self, user_id: i64) -> String {
        let groups = self.db.list_groups_for_user(user_id).await.unwrap_or_default();
        if groups.iter().any(|g| g.name == GROUP_ADMIN) {
            ROLE_ADMIN.to_string()
        } else {
            ROLE_VIEWER.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::adapter::http::jwt::JwtService;
    use crate::adapter::persistence::Database;
    use crate::domain::identity::password;
    use crate::infrastructure::secret_store::SecretStore;
    use crate::interface::secret_store::SecretStorePort;

    async fn auth_fixture() -> (Arc<Database>, Arc<JwtService>, AuthService) {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));
        let secrets: Arc<dyn SecretStorePort> = Arc::new(SecretStore::new(db.clone()));
        let jwt = Arc::new(JwtService::new(&secrets, 24).expect("jwt"));
        let auth = AuthService::new(db.clone() as Arc<dyn AppRepo>, jwt.clone());
        (db, jwt, auth)
    }

    async fn create_viewer(db: &Database, username: &str, password: &str) -> i64 {
        let hash = password::hash_password(password).expect("hash");
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
    async fn relogin_token_permissions_follow_role_promotion_and_demotion() {
        let (db, jwt, auth) = auth_fixture().await;
        let user_id = create_viewer(&db, "alice", "Correct Horse 123!").await;

        db.update_user_role(user_id, ROLE_ADMIN).await.expect("promote");
        let promoted = auth.login("alice", "Correct Horse 123!").await.expect("login");
        let promoted_claims = jwt.validate_token(&promoted.token).expect("promoted token");
        assert_eq!(promoted.role, ROLE_ADMIN);
        assert_eq!(promoted_claims.role, ROLE_ADMIN);
        assert!(promoted_claims.permissions.contains(&"users:admin".to_string()));

        db.update_user_role(user_id, ROLE_VIEWER).await.expect("demote");
        let demoted = auth.login("alice", "Correct Horse 123!").await.expect("login");
        let demoted_claims = jwt.validate_token(&demoted.token).expect("demoted token");
        assert_eq!(demoted.role, ROLE_VIEWER);
        assert_eq!(demoted_claims.role, ROLE_VIEWER);
        assert!(!demoted_claims.permissions.contains(&"users:admin".to_string()));
    }
}
