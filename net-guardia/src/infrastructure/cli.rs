use std::env;
use std::process;

use clap::{Parser, Subcommand};
use macros::log;

use crate::adapter::persistence::Database;
use crate::domain::common::error::Error;
use crate::domain::common::log::cli::CliLog;

const EXIT_USAGE: i32 = 1;
const EXIT_OP_FAILED: i32 = 2;
const DEFAULT_DB_PATH: &str = "net-guardia.db";
const DEFAULT_DECRYPTED_DEST: &str = "net-guardia-decrypted.db";
const DEFAULT_ENCRYPTED_DEST: &str = "net-guardia-encrypted.db";

#[derive(Parser)]
#[command(name = "net-guardia", version, about = "network defense system")]
pub struct Cli {
    #[arg(long, global = true, env = "NETGUARDIA_DB_PATH", default_value = DEFAULT_DB_PATH)]
    pub db_path: String,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    DecryptDb {
        #[arg(default_value = DEFAULT_DECRYPTED_DEST)]
        dest: String,
    },
    EncryptDb {
        #[arg(default_value = DEFAULT_ENCRYPTED_DEST)]
        dest: String,
    },
    VerifyAuditLog,
}

pub async fn handle_subcommand(cli: &Cli) -> Result<(), Error> {
    let db_path = cli.db_path.as_str();
    match cli.command.as_ref() {
        Some(Command::DecryptDb { dest }) => run_decrypt(db_path, dest),
        Some(Command::EncryptDb { dest }) => run_encrypt(db_path, dest),
        Some(Command::VerifyAuditLog) => run_verify(db_path).await,
        None => Ok(()),
    }
}

fn require_db_key(op: &str) -> String {
    match env::var("NETGUARDIA_DB_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            log!(CliLog::MissingDbKey(op.to_string()));
            process::exit(EXIT_USAGE);
        }
    }
}

fn run_decrypt(db_path: &str, dest: &str) -> Result<(), Error> {
    let key = require_db_key("decrypt");
    log!(CliLog::DecryptStarted(db_path.to_string(), dest.to_string()));
    match Database::decrypt_to_file(db_path, &key, dest) {
        Ok(()) => {
            log!(CliLog::DecryptCompleted(dest.to_string()));
            Ok(())
        }
        Err(e) => {
            log!(CliLog::DecryptFailed(e.to_string()));
            process::exit(EXIT_OP_FAILED);
        }
    }
}

fn run_encrypt(db_path: &str, dest: &str) -> Result<(), Error> {
    let key = require_db_key("encrypt");
    log!(CliLog::EncryptStarted(db_path.to_string(), dest.to_string()));
    match Database::encrypt_to_file(db_path, &key, dest) {
        Ok(()) => {
            log!(CliLog::EncryptCompleted(dest.to_string()));
            Ok(())
        }
        Err(e) => {
            log!(CliLog::EncryptFailed(e.to_string()));
            process::exit(EXIT_OP_FAILED);
        }
    }
}

async fn run_verify(db_path: &str) -> Result<(), Error> {
    log!(CliLog::VerifyStarted(db_path.to_string()));
    let db = match Database::new(db_path).await {
        Ok(db) => db,
        Err(e) => {
            log!(CliLog::DbOpenFailed(db_path.to_string(), e.to_string()));
            process::exit(EXIT_OP_FAILED);
        }
    };
    match db.verify_audit_log_chain(0).await {
        Ok((count, _last_id)) => {
            log!(CliLog::VerifyOk(count));
            Ok(())
        }
        Err(e) => {
            log!(CliLog::VerifyFailed(e.to_string()));
            process::exit(EXIT_OP_FAILED);
        }
    }
}
