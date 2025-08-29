use crate::core::control::access_control::AccessControl;
use crate::core::control::service::Service;

pub mod access_control;
pub mod service;

pub struct Control;

impl Control {
    pub async fn initialize() -> anyhow::Result<()> {
        AccessControl::initialize().await?;
        Service::initialize().await
    }
}
