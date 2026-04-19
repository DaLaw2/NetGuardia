use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use maxminddb::{MaxMindDbError, Reader, geoip2};
use moka::sync::Cache;
use tokio::task;

use crate::model::monitoring::geolocation::GeoLocation;
use crate::utils::ip_address;

pub struct GeoIpService {
    reader: Arc<Reader<Vec<u8>>>,
    cache: Cache<IpAddr, Option<GeoLocation>>,
}

impl GeoIpService {
    pub fn new(db_name: &str) -> Result<Self, MaxMindDbError> {
        let db_path = PathBuf::from("net-guardia/static/geo").join(db_name);
        Self::with_cache_size(db_path, 10000)
    }

    pub fn with_cache_size<P: AsRef<Path>>(db_path: P, cache_size: usize) -> Result<Self, MaxMindDbError> {
        let reader = Reader::open_readfile(db_path)?;
        let capacity = if cache_size == 0 { 10_000 } else { cache_size } as u64;

        Ok(Self {
            reader: Arc::new(reader),
            cache: Cache::new(capacity),
        })
    }

    pub async fn lookup(&self, ip: IpAddr) -> Result<Option<GeoLocation>, MaxMindDbError> {
        if ip_address::is_private_ip(&ip) {
            return Ok(Some(GeoLocation {
                country: Some("Local IP".into()),
                country_code: Some("Local".into()),
                city: None,
                latitude: None,
                longitude: None,
                timezone: None,
            }));
        }

        if let Some(cached) = self.cache.get(&ip) {
            return Ok(cached);
        }

        let reader = self.reader.clone();
        let result = task::spawn_blocking(move || Self::lookup_from_db_blocking(&reader, ip))
            .await
            .map_err(|e| MaxMindDbError::InvalidDatabase {
                message: format!("Task join error: {}", e),
                offset: None,
            })??;

        self.cache.insert(ip, result.clone());

        Ok(result)
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
