mod adapter;
mod core;
mod infrastructure;
mod interface;
mod model;
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

use crate::adapter::persistence::Database;
use crate::core::auth::jwt::JwtService;
use crate::core::auth::password;
use crate::infrastructure::cli::{Cli, handle_subcommand};
use crate::infrastructure::http_server;
use crate::infrastructure::secret_store::SecretStore;
use crate::infrastructure::system::{ShutdownMode, System};
use crate::interface::port::secret_store::SecretStorePort;
use crate::model::error::Error;
use crate::model::error::system::SystemError;
use crate::model::log::system::SystemLog;
use crate::utils::logging::Logging;

#[actix_web::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    if cli.command.is_some() {
        Logging::initialize_cli()?;
        return handle_subcommand(&cli);
    }

    Logging::initialize()?;
    let db = Arc::new(Database::new(&cli.db_path)?);
    if db.user_count().unwrap_or(0) == 0 {
        let hash = password::hash_password("admin")?;
        let admin_user_id = db.insert_user("admin", &hash, "admin", false)?;
        if let Ok(groups) = db.list_user_groups()
            && let Some((group_id, _, _, _, _)) = groups.into_iter().find(|(_, name, _, _, _)| name == "Administrator")
            && let Err(e) = db.set_user_groups(admin_user_id, &[group_id])
        {
            log!(SystemError::SetUserGroupsFailed(e));
        }
        log!(SystemLog::DefaultAdminCreated);
    }

    let setup_complete = db.get_setting("setup_complete")?.map(|v| v == "true").unwrap_or(false);
    if !setup_complete {
        log!(SystemLog::SetupMode);

        let secret_store = Arc::new(SecretStore::new(db.clone()));
        let secrets: Arc<dyn SecretStorePort> = secret_store.clone();
        let jwt_service = Arc::new(JwtService::new(&secrets, 24)?);
        let setup_flag = Arc::new(AtomicBool::new(false));

        let handle = http_server::start_setup_server(db.clone(), secret_store, jwt_service, setup_flag.clone(), 8080)?;

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
    }

    let mut system = System::new(db).await?;
    let mode = system.run().await?;
    system.terminate().await?;
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
