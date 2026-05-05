use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use maxminddb::{MaxMindDbError, Reader, geoip2};
use moka::sync::Cache;
use tokio::task;

use crate::domain::data_plane::geolocation::GeoLocation;
use crate::interface::geo_lookup::GeoLookup;
use crate::utils::ip_address;

pub struct GeoIpService {
    reader: Arc<Reader<Vec<u8>>>,
    cache: Cache<IpAddr, Option<GeoLocation>>,
}

impl GeoIpService {
    pub fn with_cache_size<P: AsRef<Path>>(db_path: P, cache_size: usize) -> Result<Self, MaxMindDbError> {
        let reader = Reader::open_readfile(db_path)?;
        let capacity = cache_size.max(1) as u64;

        Ok(Self {
            reader: Arc::new(reader),
            cache: Cache::new(capacity),
        })
    }

    fn lookup_from_db_blocking(reader: &Reader<Vec<u8>>, ip: IpAddr) -> Result<Option<GeoLocation>, MaxMindDbError> {
        let lookup_result = reader.lookup(ip)?;
        let city_option: Option<geoip2::City> = lookup_result.decode()?;

        Ok(city_option.map(|city| {
            let country_name = city.country.names.english.map(|s| s.to_string());

            let country_code = city.country.iso_code.map(|s| s.to_string());

            let city_name = city.city.names.english.map(|s| s.to_string());

            let latitude = city.location.latitude;
            let longitude = city.location.longitude;
            let timezone = city.location.time_zone.map(|s| s.to_string());

            GeoLocation {
                country: country_name,
                country_code,
                city: city_name,
                latitude,
                longitude,
                timezone,
            }
        }))
    }
}

#[async_trait]
impl GeoLookup for GeoIpService {
    async fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
        if ip_address::is_private_ip(&ip) {
            return Some(GeoLocation {
                country: Some("Local IP".into()),
                country_code: Some("Local".into()),
                city: None,
                latitude: None,
                longitude: None,
                timezone: None,
            });
        }

        if let Some(cached) = self.cache.get(&ip) {
            return cached;
        }

        let reader = self.reader.clone();
        let result = match task::spawn_blocking(move || Self::lookup_from_db_blocking(&reader, ip)).await {
            Ok(Ok(loc)) => loc,
            _ => None,
        };

        self.cache.insert(ip, result.clone());
        result
    }
}
