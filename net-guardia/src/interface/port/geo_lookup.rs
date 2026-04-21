use std::net::IpAddr;

use async_trait::async_trait;

use crate::model::monitoring::geolocation::GeoLocation;

#[async_trait]
pub trait GeoLookup: Send + Sync {
    async fn lookup(&self, ip: IpAddr) -> Option<GeoLocation>;
}
