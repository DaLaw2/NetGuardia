use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use maxminddb::{geoip2, MaxMindDbError, Reader};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use lru::LruCache;
use std::num::NonZeroUsize;
use tokio::task;
use crate::model::geo_stats::GeoLocation;


pub struct GeoIpService {
    reader: Arc<Reader<Vec<u8>>>,
    cache: Arc<RwLock<LruCache<IpAddr, Option<GeoLocation>>>>,
}

impl GeoIpService {
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self, MaxMindDbError> {
        Self::with_cache_size(db_path, 10000)
    }

    pub fn with_cache_size<P: AsRef<Path>>(
        db_path: P,
        cache_size: usize,
    ) -> Result<Self, MaxMindDbError> {
        let reader = Reader::open_readfile(db_path)?;
        let cache_capacity = NonZeroUsize::new(cache_size)
            .unwrap_or_else(|| NonZeroUsize::new(10000).unwrap());

        Ok(Self {
            reader: Arc::new(reader),
            cache: Arc::new(RwLock::new(LruCache::new(cache_capacity))),
        })
    }

    pub async fn lookup(&self, ip: IpAddr) -> Result<Option<GeoLocation>, MaxMindDbError> {
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.peek(&ip) {
                return Ok(cached.clone());
            }
        }

        let reader = self.reader.clone();
        let result = task::spawn_blocking(move || {
            Self::lookup_from_db_blocking(&reader, ip)
        })
            .await
            .map_err(|e| MaxMindDbError::InvalidDatabase(format!("Task join error: {}", e)))??;

        {
            let mut cache = self.cache.write().await;
            cache.put(ip, result.clone());
        }

        Ok(result)
    }

    fn lookup_from_db_blocking(
        reader: &Reader<Vec<u8>>,
        ip: IpAddr,
    ) -> Result<Option<GeoLocation>, MaxMindDbError> {
        let city_option: Option<geoip2::City> = reader.lookup(ip)?;

        Ok(city_option.map(|city| {
            let country_name = city
                .country
                .as_ref()
                .and_then(|c| c.names.as_ref())
                .and_then(|n| n.get("en"))
                .map(|s| s.to_string());

            let country_code = city
                .country
                .as_ref()
                .and_then(|c| c.iso_code)
                .map(|s| s.to_string());

            let city_name = city
                .city
                .as_ref()
                .and_then(|c| c.names.as_ref())
                .and_then(|n| n.get("en"))
                .map(|s| s.to_string());

            let latitude = city.location.as_ref().and_then(|l| l.latitude);

            let longitude = city.location.as_ref().and_then(|l| l.longitude);

            let timezone = city
                .location
                .as_ref()
                .and_then(|l| l.time_zone)
                .map(|s| s.to_string());

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

    pub async fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read().await;
        (cache.len(), cache.cap().get())
    }
}