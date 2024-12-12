use crate::core::control::access_list::AccessList;
use crate::core::control::defence::Defence;
use crate::core::control::sampling::Sampling;
use crate::core::control::service::Service;

pub mod access_list;
pub mod defence;
pub mod service;
pub mod sampling;

pub struct Control;

impl Control {
    pub async fn initialize() -> anyhow::Result<()> {
        AccessList::initialize().await?;
        Defence::initialize().await?;
        Sampling::initialize().await?;
        Service::initialize().await
    }
}
