mod adapter;
mod core;
mod infrastructure;
mod interface;
mod model;
mod utils;

use std::env;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use macros::log;
use sd_notify::NotifyState;
use tokio::{signal, time};

use crate::adapter::persistence::Database;
use crate::core::auth::jwt::JwtService;
use crate::core::auth::password;
use crate::infrastructure::http_server;
use crate::infrastructure::secret_store::SecretStore;
use crate::infrastructure::system::{ShutdownMode, System};
use crate::interface::port::secret_store::SecretStorePort;
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

    // Handle DB encrypt/decrypt subcommands before full startup
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 {
        let db_path = env::var("NETGUARDIA_DB_PATH").unwrap_or_else(|_| "net-guardia.db".to_string());
        match args[1].as_str() {
            "--decrypt-db" => {
                let key = match env::var("NETGUARDIA_DB_KEY") {
                    Ok(k) if !k.is_empty() => k,
                    _ => {
                        eprintln!("Error: NETGUARDIA_DB_KEY must be set for decrypt");
                        process::exit(1);
                    }
                };
                let dest = args.get(2).map(|s| s.as_str()).unwrap_or("net-guardia-decrypted.db");
                println!("Decrypting {} → {}", db_path, dest);
                Database::decrypt_to_file(&db_path, &key, dest)?;
                println!("Done. Decrypted database written to {}", dest);
                return Ok(());
            }
            "--encrypt-db" => {
                let key = match env::var("NETGUARDIA_DB_KEY") {
                    Ok(k) if !k.is_empty() => k,
                    _ => {
                        eprintln!("Error: NETGUARDIA_DB_KEY must be set for encrypt");
                        process::exit(1);
                    }
                };
                let dest = args.get(2).map(|s| s.as_str()).unwrap_or("net-guardia-encrypted.db");
                println!("Encrypting {} → {}", db_path, dest);
                Database::encrypt_to_file(&db_path, &key, dest)?;
                println!("Done. Encrypted database written to {}", dest);
                return Ok(());
            }
            "--verify-audit-log" => {
                println!("Verifying audit_log hash chain in {}", db_path);
                let db = Database::new(&db_path)?;
                match db.verify_audit_log_chain() {
                    Ok(count) => {
                        println!("OK: {} audit_log rows verified, chain intact.", count);
                        return Ok(());
                    }
                    Err(e) => {
                        eprintln!("FAIL: {}", e);
                        process::exit(2);
                    }
                }
            }
            _ => {}
        }
    }

    // Phase 1: Create DB (fast — needed for setup check and setup server)
    let db_path = env::var("NETGUARDIA_DB_PATH").unwrap_or_else(|_| "net-guardia.db".to_string());
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

    let setup_complete = db.get_setting("setup_complete")?.map(|v| v == "true").unwrap_or(false);

    // Phase 2: If setup not complete, run lightweight setup server immediately
    if !setup_complete {
        log!(SystemLog::SetupMode);

        let secret_store = Arc::new(SecretStore::new(db.clone()));
        let secrets: Arc<dyn SecretStorePort> = secret_store.clone();
        let jwt_service = Arc::new(JwtService::new(&secrets, 24)?);
        let setup_flag = Arc::new(AtomicBool::new(false));

        // Start setup server — returns handle for graceful shutdown
        let handle = http_server::start_setup_server(db.clone(), secret_store, jwt_service, setup_flag.clone(), 8080)?;

        // Wait for setup completion or shutdown signal
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

        // Stop setup server to free the port for full server
        handle.stop(true).await;
        log!(SystemLog::SetupServerStopped);
    }

    // Phase 3: Full system build and run (setup is complete, DB has config)
    let mut system = System::new(db).await?;
    let mode = system.run().await?;
    system.terminate().await?;

    match mode {
        ShutdownMode::Restart => {
            log!(SystemLog::ApiRestart);
            let _ = sd_notify::notify(false, &[NotifyState::Reloading]);
            // Drop System to detach eBPF XDP programs before re-exec
            drop(system);
            // Brief delay for kernel to release XDP/AF_XDP resources
            thread::sleep(Duration::from_millis(500));
            // Re-exec self — works with or without systemd
            use std::os::unix::process::CommandExt;
            let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("net-guardia"));
            let err = process::Command::new(exe).args(env::args().skip(1)).exec(); // replaces current process
            // If exec fails, fall through to exit
            log!(SystemError::UnexpectedError(err));
            process::exit(1);
        }
        ShutdownMode::Shutdown => {
            log!(SystemLog::ApiShutdown);
            let _ = sd_notify::notify(false, &[NotifyState::Stopping]);
        }
    }
    Ok(())
}
