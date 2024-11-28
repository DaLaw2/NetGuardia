mod core;
mod model;
mod utils;
mod web;

use crate::core::system::System;

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    System::initialize().await?;
    System::run().await?;
    System::terminate().await?;
    Ok(())
}
