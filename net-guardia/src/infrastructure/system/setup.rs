use std::sync::Arc;

use arc_swap::ArcSwap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use macros::log;
use rand::Rng;
use tokio::signal;

use crate::adapter::http::session::SessionCookieService;
use crate::adapter::http::setup::SetupToken;
use crate::adapter::identity::api_key_hasher::HmacApiKeyHasher;
use crate::adapter::identity::password_hasher::Argon2PasswordHasher;
use crate::adapter::persistence::Database;
use crate::adapter::secret_store::SecretStore;
use crate::common::error::Error;
use crate::common::error::system::SystemError;
use crate::common::log::system::SystemLog;
use crate::core::common::setup_service::SetupService;
use crate::core::identity::auth_service::AuthService;
use crate::core::identity::session_service::SessionService;
use crate::domain::common::config::AppConfig;
use crate::infrastructure::http_runtime::SetupCompleteFlag;
use crate::infrastructure::http_server::{self, SetupServerParams};
use crate::interface::identity::api_key_hasher::ApiKeyHasher;
use crate::interface::identity::auth_repo::IdentityAuthRepo;
use crate::interface::system::secret_store::SecretStorePort;
use crate::interface::system::setup::SetupRepo;
use crate::interface::system::system_state::SystemStateRepo;

pub async fn seed_initial_data(database: &Arc<Database>) -> Result<(), Error> {
    database.seed_default_playbooks().await?;
    Ok(())
}

pub async fn is_setup_complete(database: &Arc<Database>) -> Result<bool, Error> {
    let state_repo = database.as_ref() as &dyn SystemStateRepo;
    Ok(state_repo
        .get_system_state("setup_complete")
        .await?
        .map(|v| v == "true")
        .unwrap_or(false))
}

pub async fn run_setup_wizard(database: &Arc<Database>, api_key_hmac: [u8; 32]) -> Result<(), Error> {
    log!(SystemLog::SetupMode);

    let setup_complete_flag = SetupCompleteFlag::new(false);
    let setup_token_raw = random_setup_token();
    log!(SystemLog::SetupTokenGenerated(setup_token_raw.clone()));
    let database = database.clone();
    let secret_store = Arc::new(SecretStore::new(database.clone()));
    let setup_service = Arc::new(SetupService::new(
        database.clone() as Arc<dyn SetupRepo>,
        secret_store.clone() as Arc<dyn SecretStorePort>,
        Arc::new(Argon2PasswordHasher),
    ));
    let app_config = Arc::new(ArcSwap::from_pointee(AppConfig::defaults()));
    let session_service = Arc::new(SessionService::new(app_config.clone()));
    let session_cookie_service = Arc::new(SessionCookieService::new(app_config));
    let password_hasher = Arc::new(Argon2PasswordHasher);
    let auth_service = Arc::new(AuthService::new(
        database.clone() as Arc<dyn IdentityAuthRepo>,
        password_hasher,
    ));
    let api_key_hasher: Arc<dyn ApiKeyHasher> = Arc::new(HmacApiKeyHasher::new(api_key_hmac));
    let params = SetupServerParams {
        database,
        secret_store,
        setup_service,
        session_service,
        session_cookie_service,
        auth_service,
        api_key_hasher,
        setup_complete: setup_complete_flag.clone(),
        setup_token: SetupToken::new(setup_token_raw),
        port: 8080,
    };
    let handle = http_server::start_setup_server(params)?;

    tokio::select! {
        _ = setup_complete_flag.wait_complete() => {
            log!(SystemLog::SetupCompleted);
        }
        _ = signal::ctrl_c() => {
            log!(SystemLog::ShutdownDuringSetup);
            handle.stop(true).await;
            Err(SystemError::SetupInterrupted)?;
        }
    }

    handle.stop(true).await;
    log!(SystemLog::SetupServerStopped);
    Ok(())
}

fn random_setup_token() -> String {
    let mut token = [0_u8; 32];
    rand::rng().fill_bytes(&mut token);
    URL_SAFE_NO_PAD.encode(token)
}
