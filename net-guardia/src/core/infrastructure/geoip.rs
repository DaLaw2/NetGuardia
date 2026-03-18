use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use maxminddb::{geoip2, MaxMindDbError, Reader};
use tokio::sync::RwLock;
use lru::LruCache;
use std::num::NonZeroUsize;
use tokio::task;

use crate::model::geo_stats::GeoLocation;
use crate::utils::ip_address;

pub struct GeoIpService {
    reader: Arc<Reader<Vec<u8>>>,
    cache: Arc<RwLock<LruCache<IpAddr, Option<GeoLocation>>>>,
}

impl GeoIpService {
    pub fn new(db_name: &str) -> Result<Self, MaxMindDbError> {
        let db_path = PathBuf::from("net-guardia/static/geo").join(db_name);
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
            .map_err(|e| MaxMindDbError::InvalidDatabase {
                message: format!("Task join error: {}", e),
                offset: None,
            })??;

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
        let lookup_result = reader.lookup(ip)?;
        let city_option: Option<geoip2::City> = lookup_result.decode()?;

        Ok(city_option.map(|city| {
            let country_name = city.country.names.english
                .map(|s| s.to_string());

            let country_code = city.country.iso_code
                .map(|s| s.to_string());

            let city_name = city.city.names.english
                .map(|s| s.to_string());

            let latitude = city.location.latitude.or(Some(0.0));
            let longitude = city.location.longitude.or(Some(0.0));
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

    pub async fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read().await;
        (cache.len(), cache.cap().get())
    }
}