use std::sync::Arc;
use std::sync::atomic::AtomicU8;

use crate::adapter::http::session::SessionCookieService;
use crate::adapter::identity::api_key_hasher::HmacApiKeyHasher;
use crate::adapter::identity::password_hasher::Argon2PasswordHasher;
use crate::common::error::Error;
use crate::core::common::enforce_mode_handler::{EnforceModeHandler, enforce_mode_to_u8};
use crate::core::identity::auth_service::AuthService;
use crate::core::identity::group_service::GroupService;
use crate::core::identity::session_service::SessionService;
use crate::core::identity::user_service::UserService;
use crate::infrastructure::startup::{FoundationRuntime, IdentityRuntime};
use crate::interface::identity::api_key_hasher::ApiKeyHasher;
use crate::interface::identity::auth_repo::{IdentityAuthRepo, UserGroupRepo, UserRepo};
use crate::interface::identity::password_hasher::PasswordHasher;
use crate::interface::system::audit::AuditRepo;
use crate::interface::system::config_repo::ConfigRepo;

pub fn build_identity(foundation: &FoundationRuntime, api_key_hmac: [u8; 32]) -> Result<IdentityRuntime, Error> {
    let session_service = Arc::new(SessionService::new(foundation.app_config.clone()));
    let session_cookie_service = Arc::new(SessionCookieService::new(foundation.app_config.clone()));
    let password_hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2PasswordHasher);
    let api_key_hasher: Arc<dyn ApiKeyHasher> = Arc::new(HmacApiKeyHasher::new(api_key_hmac));
    let auth_service = Arc::new(AuthService::new(
        foundation.database.clone() as Arc<dyn IdentityAuthRepo>,
        password_hasher.clone(),
    ));
    let user_service = Arc::new(UserService::new(
        foundation.database.clone() as Arc<dyn UserRepo>,
        foundation.database.clone() as Arc<dyn UserGroupRepo>,
        password_hasher,
    ));
    let group_service = Arc::new(GroupService::new(foundation.database.clone() as Arc<dyn UserGroupRepo>));
    let enforce_level_cache = Arc::new(AtomicU8::new({
        let mode = foundation.app_config.load().system.enforce_mode;
        enforce_mode_to_u8(mode)
    }));
    let enforce_handler = Arc::new(EnforceModeHandler::new(
        foundation.database.clone() as Arc<dyn ConfigRepo>,
        foundation.database.clone() as Arc<dyn AuditRepo>,
        foundation.app_config.clone(),
        enforce_level_cache.clone(),
    ));

    Ok(IdentityRuntime {
        session_service,
        session_cookie_service,
        auth_service,
        user_service,
        group_service,
        enforce_handler,
        enforce_level_cache,
        api_key_hasher,
    })
}
