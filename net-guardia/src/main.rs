mod adapter;
mod core;
mod infrastructure;
mod interface;
mod model;
mod utils;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use macros::log;

use crate::adapter::persistence::Database;
use crate::core::auth::jwt::JwtService;
use crate::core::auth::password;
use crate::core::system::System;
use crate::model::error::Error;
use crate::model::error::system::SystemError;
use crate::model::log::system::SystemLog;
use crate::utils::logging::Logging;

/// Two-phase startup:
///
/// ```text
/// ┌────────────┐     ┌──────────────────┐     ┌──────────────────┐
/// │ Create DB  │────→│ Setup complete?  │─no─→│ Setup HTTP server│
/// │ (fast)     │     │                  │     │ (instant start)  │
/// └────────────┘     └────────┬─────────┘     └────────┬─────────┘
///                             │yes                      │done
///                             ▼                         ▼
///                    ┌──────────────────┐     ┌──────────────────┐
///                    │ Full build       │←────│ Stop setup server│
///                    │ (eBPF, ML, SOAR) │     │ + reload config  │
///                    └────────┬─────────┘     └──────────────────┘
///                             ▼
///                    ┌──────────────────┐
///                    │ Full HTTP server │
///                    └──────────────────┘
/// ```
#[actix_web::main]
async fn main() -> Result<(), Error> {
    Logging::initialize()?;

    // Phase 1: Create DB (fast — needed for setup check and setup server)
    let db_path = std::env::var("NETGUARDIA_DB_PATH")
        .unwrap_or_else(|_| "net-guardia.db".to_string());
    let db = Arc::new(Database::new(&db_path)?);

    // Seed default admin user if no users exist
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

    let setup_complete = db.get_setting("setup_complete")?
        .map(|v| v == "true")
        .unwrap_or(false);

    // Phase 2: If setup not complete, run lightweight setup server immediately
    if !setup_complete {
        log!(SystemLog::SetupMode);

        let jwt_service = Arc::new(JwtService::new(db.as_ref(), 24)?);
        let setup_flag = Arc::new(AtomicBool::new(false));

        // Start setup server — returns handle for graceful shutdown
        let handle = infrastructure::http_server::start_setup_server(
            db.clone(), jwt_service, setup_flag.clone(), 8080,
        )?;

        // Wait for setup completion or shutdown signal
        let flag = setup_flag.clone();
        let setup_done = async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if flag.load(Ordering::SeqCst) { return; }
            }
        };

        tokio::select! {
            _ = setup_done => {
                log!(SystemLog::SetupCompleted);
            }
            _ = tokio::signal::ctrl_c() => {
                log!(SystemLog::ShutdownDuringSetup);
                handle.stop(true).await;
                return Ok(());
            }
        }

        // Stop setup server to free the port for full server
        handle.stop(true).await;
        log!(SystemLog::SetupServerStopped);
    }

    // Phase 3: Full system build and run (setup is complete, DB has config)
    let mut system = System::new(db).await?;
    system.run().await?;
    system.terminate().await?;
    Ok(())
}
