mod core;
mod model;
mod utils;
mod web;
mod ml;

use crate::core::system::System;
use crate::model::error::Error;

#[actix_web::main]
async fn main() -> Result<(), Error> {
    let mut system = System::new().await?;
    system.run().await?;
    system.terminate().await?;
    Ok(())
}
