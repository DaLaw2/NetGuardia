use crate::core::control::access_control::AccessControl;
use crate::core::control::service::Service;
use crate::model::error::Error;

pub mod access_control;
pub mod service;

pub struct Control;

impl Control {
    pub async fn initialize() -> Result<(), Error> {
        AccessControl::initialize().await?;
        Service::initialize().await
    }
}
