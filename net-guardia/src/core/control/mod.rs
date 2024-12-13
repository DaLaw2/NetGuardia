use crate::core::control::access_control::AccessControl;
use crate::core::control::defence::Defence;
use crate::core::control::sampling::Sampling;
use crate::core::control::service::Service;

pub mod access_control;
pub mod defence;
pub mod service;
pub mod sampling;

pub struct Control;

impl Control {
    pub async fn initialize() -> anyhow::Result<()> {
        AccessControl::initialize().await?;
        Defence::initialize().await?;
        Sampling::initialize().await?;
        Service::initialize().await
    }
}
