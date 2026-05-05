mod adapter;
mod core;
mod domain;
mod infrastructure;
mod interface;
mod utils;

use std::env;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Parser;
use macros::log;
use sd_notify::NotifyState;
use tokio::time::sleep;
use tokio::{signal, time};

use crate::adapter::http::jwt::JwtService;
use crate::adapter::persistence::Database;
use crate::core::identity::auth_service::AuthService;
use crate::domain::common::config::AppConfig;
use crate::domain::common::error::Error;
use crate::domain::common::error::system::SystemError;
use crate::domain::common::log::system::SystemLog;
use crate::domain::identity::auth::{DEFAULT_ADMIN_USERNAME, GROUP_ADMIN, ROLE_ADMIN};
use crate::domain::identity::password;
use crate::infrastructure::cli::{Cli, handle_subcommand};
use crate::infrastructure::http_server;
use crate::infrastructure::http_server::SetupServerParams;
use crate::infrastructure::logger::Logger;
use crate::infrastructure::secret_store::SecretStore;
use crate::infrastructure::system::{ShutdownMode, System};
use crate::interface::app_repo::AppRepo;
use crate::interface::secret_store::SecretStorePort;
use crate::interface::system_state::SystemStateRepo;
use crate::interface::token_minter::TokenMinter;

async fn seed_default_admin(database: &Arc<Database>) -> Result<(), Error> {
    if database.user_count().await.unwrap_or(0) != 0 {
        return Ok(());
    }
    let hash = password::hash_password(DEFAULT_ADMIN_USERNAME)?;
    let admin_user_id = database
        .insert_user(DEFAULT_ADMIN_USERNAME, &hash, ROLE_ADMIN, false)
        .await?;
    if let Ok(groups) = database.list_user_groups().await
        && let Some(g) = groups.into_iter().find(|g| g.name == GROUP_ADMIN)
        && let Err(err) = database.set_user_groups(admin_user_id, &[g.id]).await
    {
        log!(SystemError::SetUserGroupsFailed(err));
    }
    log!(SystemLog::DefaultAdminCreated);
    Ok(())
}

async fn is_setup_complete(database: &Arc<Database>) -> Result<bool, Error> {
    let state_repo = database.as_ref() as &dyn SystemStateRepo;
    Ok(state_repo
        .get_system_state("setup_complete")
        .await?
        .map(|v| v == "true")
        .unwrap_or(false))
}

async fn run_setup_wizard(database: &Arc<Database>) -> Result<(), Error> {
    log!(SystemLog::SetupMode);

    let setup_flag = Arc::new(AtomicBool::new(false));
    let setup_complete_flag = http_server::SetupCompleteFlag(setup_flag.clone());

    let database = database.clone();
    let secret_store = Arc::new(SecretStore::new(database.clone()));
    let secrets: Arc<dyn SecretStorePort> = secret_store.clone();
    let jwt_service = Arc::new(JwtService::new(&secrets, 24)?);
    let auth_service = Arc::new(AuthService::new(
        database.clone() as Arc<dyn AppRepo>,
        jwt_service.clone() as Arc<dyn TokenMinter>,
    ));
    let params = SetupServerParams {
        database,
        secret_store,
        jwt_service,
        auth_service,
        setup_complete: setup_complete_flag,
        port: 8080,
    };
    let handle = http_server::start_setup_server(params)?;

    let flag = setup_flag.clone();
    let setup_done = async move {
        loop {
            time::sleep(Duration::from_millis(500)).await;
            if flag.load(Ordering::SeqCst) {
                return;
            }
        }
    };

    tokio::select! {
        _ = setup_done => {
            log!(SystemLog::SetupCompleted);
        }
        _ = signal::ctrl_c() => {
            log!(SystemLog::ShutdownDuringSetup);
            handle.stop(true).await;
            return Ok(());
        }
    }

    handle.stop(true).await;
    log!(SystemLog::SetupServerStopped);
    Ok(())
}

async fn handle_shutdown(mode: ShutdownMode, system: System) -> Result<(), Error> {
    match mode {
        ShutdownMode::Restart => {
            log!(SystemLog::Restart);
            let _ = sd_notify::notify(false, &[NotifyState::Reloading]);
            drop(system);
            sleep(Duration::from_millis(500)).await;
            let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("net-guardia"));
            let err = process::Command::new(exe).args(env::args().skip(1)).exec();
            log!(SystemError::UnexpectedError(err));
            process::exit(1);
        }
        ShutdownMode::Shutdown => {
            log!(SystemLog::Shutdown);
            let _ = sd_notify::notify(false, &[NotifyState::Stopping]);
        }
    }
    Ok(())
}

#[actix_web::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    if cli.command.is_some() {
        Logger::initialize_cli()?;
        return handle_subcommand(&cli).await;
    }

    let database = Arc::new(Database::new(&cli.db_path).await?);
    let app_config = AppConfig::from_config_repo(database.as_ref()).await?;
    let (logger, log_buffer) = Logger::initialize(&app_config)?;
    let logger = Arc::new(logger);
    let log_buffer = Arc::new(log_buffer);

    seed_default_admin(&database).await?;

    if !is_setup_complete(&database).await? {
        run_setup_wizard(&database).await?;
    }

    let mut system = System::new(database).await?;
    let mode = system.run(logger, log_buffer).await?;
    system.terminate().await?;
    handle_shutdown(mode, system).await
}
