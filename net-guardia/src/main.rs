mod core;
mod model;
mod utils;
mod web;

use crate::core::system::System;
use crate::model::error::Error;

#[actix_web::main]
async fn main() -> Result<(), Error> {
    System::initialize().await?;
    System::run().await?;
    System::terminate().await?;
    Ok(())
}
