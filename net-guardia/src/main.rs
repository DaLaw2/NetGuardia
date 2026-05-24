mod adapter;
mod common;
mod core;
mod domain;
mod infrastructure;
mod interface;

use clap::Parser;

use crate::common::error::Error;
use crate::infrastructure::cli::{Cli, handle_subcommand};
use crate::infrastructure::logger::Logger;
use crate::infrastructure::system::System;

#[actix_web::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    if cli.command.is_some() {
        Logger::initialize_cli()?;
        return handle_subcommand(&cli).await;
    }

    let mut system = System::new(cli.db_path);
    system.setup().await?;
    let mode = system.run().await?;
    system.terminate().await?;
    system.handle_shutdown(mode).await
}
