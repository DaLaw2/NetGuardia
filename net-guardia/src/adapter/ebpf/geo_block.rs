use std::collections::{HashMap as StdHashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use aya::Ebpf;
use aya::maps::MapData;
use aya::maps::lpm_trie::{Key, LpmTrie};
use ipnetwork::IpNetwork;
use maxminddb::Reader;
use parking_lot::RwLock;
use serde::Deserialize;

use crate::common::error::Error;
use crate::common::error::io::IOError;
use crate::domain::common::config::AppConfig;
use crate::domain::data_plane::error::EbpfError;
use crate::interface::data_plane::geo_block_api::GeoBlockPort;

struct GeoIndex {
    v4: StdHashMap<String, Vec<(u32, u32)>>,
    v6: StdHashMap<String, Vec<(u128, u32)>>,
}

#[derive(Default, Deserialize)]
struct GeoCountryRecord<'a> {
    #[serde(borrow, default)]
    country: GeoCountry<'a>,
}

#[derive(Default, Deserialize)]
struct GeoCountry<'a> {
    iso_code: Option<&'a str>,
}

pub struct GeoBlock {
    geo_block_v4: RwLock<Option<LpmTrie<MapData, u32, u8>>>,
    geo_block_v6: RwLock<Option<LpmTrie<MapData, u128, u8>>>,
    blocked_countries: ArcSwap<HashSet<String>>,
    db_path: String,
    index: RwLock<Option<Arc<GeoIndex>>>,
}

impl GeoBlock {
    pub fn new(ebpf: &mut Ebpf, app_config: Arc<ArcSwap<AppConfig>>) -> Result<Self, Error> {
        let v4_map = ebpf.take_map("GEO_BLOCK_V4").ok_or(EbpfError::MapNotFound)?;
        let v4_trie = LpmTrie::try_from(v4_map).map_err(EbpfError::MapOperationError)?;

        let v6_map = ebpf.take_map("GEO_BLOCK_V6").ok_or(EbpfError::MapNotFound)?;
        let v6_trie = LpmTrie::try_from(v6_map).map_err(EbpfError::MapOperationError)?;

        let db_path = app_config.load().acl.geoip_db_path.clone();
        let _ = Reader::open_readfile(&db_path).map_err(|e| IOError::OpenFileFailed(db_path.clone(), e))?;

        Ok(Self {
            geo_block_v4: RwLock::new(Some(v4_trie)),
            geo_block_v6: RwLock::new(Some(v6_trie)),
            blocked_countries: ArcSwap::from_pointee(HashSet::new()),
            db_path,
            index: RwLock::new(None),
        })
    }

    pub fn unavailable(app_config: Arc<ArcSwap<AppConfig>>) -> Self {
        let db_path = app_config.load().acl.geoip_db_path.clone();
        Self {
            geo_block_v4: RwLock::new(None),
            geo_block_v6: RwLock::new(None),
            blocked_countries: ArcSwap::from_pointee(HashSet::new()),
            db_path,
            index: RwLock::new(None),
        }
    }

    fn index(&self) -> Result<Arc<GeoIndex>, Error> {
        if let Some(index) = self.index.read().as_ref() {
            return Ok(index.clone());
        }

        let mut guard = self.index.write();
        if let Some(index) = guard.as_ref() {
            return Ok(index.clone());
        }

        let reader =
            Reader::open_readfile(&self.db_path).map_err(|e| IOError::OpenFileFailed(self.db_path.clone(), e))?;
        let index = Arc::new(Self::build_index(&reader)?);
        *guard = Some(index.clone());
        Ok(index)
    }

    fn build_index(reader: &Reader<Vec<u8>>) -> Result<GeoIndex, Error> {
        let mut v4: StdHashMap<String, Vec<(u32, u32)>> = StdHashMap::new();
        let mut v6: StdHashMap<String, Vec<(u128, u32)>> = StdHashMap::new();

        let ipv4_all = parse_geoip_network("0.0.0.0/0")?;
        if let Ok(iter) = reader.within(ipv4_all, Default::default()) {
            for result in iter {
                let Ok(lookup) = result else { continue };
                let Ok(network) = lookup.network() else { continue };
                let Ok(Some(record)) = lookup.decode::<GeoCountryRecord>() else {
                    continue;
                };
                let Some(code) = record.country.iso_code else {
                    continue;
                };
                let code = code.to_uppercase();

                if let IpNetwork::V4(v4_net) = network {
                    let ip_be = u32::from(v4_net.ip()).to_be();
                    v4.entry(code).or_default().push((ip_be, v4_net.prefix() as u32));
                }
            }
        }

        let ipv6_all = parse_geoip_network("::/0")?;
        if let Ok(iter) = reader.within(ipv6_all, Default::default()) {
            for result in iter {
                let Ok(lookup) = result else { continue };
                let Ok(network) = lookup.network() else { continue };
                let Ok(Some(record)) = lookup.decode::<GeoCountryRecord>() else {
                    continue;
                };
                let Some(code) = record.country.iso_code else {
                    continue;
                };
                let code = code.to_uppercase();

                if let IpNetwork::V6(v6_net) = network {
                    let ip_be = u128::from(v6_net.ip()).to_be();
                    v6.entry(code).or_default().push((ip_be, v6_net.prefix() as u32));
                }
            }
        }

        Ok(GeoIndex { v4, v6 })
    }

    pub fn get_blocked_countries(&self) -> Vec<String> {
        self.blocked_countries.load().iter().cloned().collect()
    }

    pub fn block_countries(&self, country_codes: &[String]) -> Result<u64, Error> {
        let mut next: HashSet<String> = self.blocked_countries.load().as_ref().clone();
        for code in country_codes {
            let upper = code.trim().to_uppercase();
            if upper.len() == 2 && upper.chars().all(|c| c.is_ascii_alphabetic()) {
                next.insert(upper);
            }
        }
        let count = self.rebuild_tries_for(&next)?;
        self.blocked_countries.store(Arc::new(next));
        Ok(count)
    }

    pub fn unblock_countries(&self, country_codes: &[String]) -> Result<u64, Error> {
        let mut next: HashSet<String> = self.blocked_countries.load().as_ref().clone();
        for code in country_codes {
            next.remove(&code.trim().to_uppercase());
        }
        let count = self.rebuild_tries_for(&next)?;
        self.blocked_countries.store(Arc::new(next));
        Ok(count)
    }

    fn rebuild_tries_for(&self, countries: &HashSet<String>) -> Result<u64, Error> {
        {
            let v4_guard = self.geo_block_v4.read();
            let v6_guard = self.geo_block_v6.read();
            if v4_guard.is_none() || v6_guard.is_none() {
                Err(EbpfError::NotLoaded)?;
            }
        }

        let mut v4_entries: HashSet<(u32, u32)> = HashSet::new();
        let mut v6_entries: HashSet<(u128, u32)> = HashSet::new();

        if !countries.is_empty() {
            let index = self.index()?;
            for code in countries {
                if let Some(prefixes) = index.v4.get(code) {
                    for &entry in prefixes {
                        v4_entries.insert(entry);
                    }
                }
                if let Some(prefixes) = index.v6.get(code) {
                    for &entry in prefixes {
                        v6_entries.insert(entry);
                    }
                }
            }
        }

        let mut v4_guard = self.geo_block_v4.write();
        let mut v6_guard = self.geo_block_v6.write();
        let (v4_trie, v6_trie) = match (v4_guard.as_mut(), v6_guard.as_mut()) {
            (Some(v4), Some(v6)) => (v4, v6),
            _ => Err(EbpfError::NotLoaded)?,
        };

        let mut count = 0u64;
        for &(ip_be, prefix_len) in &v4_entries {
            let key = Key::new(prefix_len, ip_be);
            if v4_trie.insert(&key, 1u8, 0).is_ok() {
                count += 1;
            }
        }
        for &(ip_be, prefix_len) in &v6_entries {
            let key = Key::new(prefix_len, ip_be);
            if v6_trie.insert(&key, 1u8, 0).is_ok() {
                count += 1;
            }
        }

        Self::remove_stale_v4(v4_trie, &v4_entries);
        Self::remove_stale_v6(v6_trie, &v6_entries);

        Ok(count)
    }

    fn remove_stale_v4(trie: &mut LpmTrie<MapData, u32, u8>, desired: &HashSet<(u32, u32)>) {
        let stale: Vec<Key<u32>> = trie
            .iter()
            .filter_map(|entry| entry.ok())
            .map(|(key, _)| key)
            .filter(|key| !desired.contains(&(key.data(), key.prefix_len())))
            .collect();
        for key in stale {
            let _ = trie.remove(&key);
        }
    }

    fn remove_stale_v6(trie: &mut LpmTrie<MapData, u128, u8>, desired: &HashSet<(u128, u32)>) {
        let stale: Vec<Key<u128>> = trie
            .iter()
            .filter_map(|entry| entry.ok())
            .map(|(key, _)| key)
            .filter(|key| !desired.contains(&(key.data(), key.prefix_len())))
            .collect();
        for key in stale {
            let _ = trie.remove(&key);
        }
    }
}

fn parse_geoip_network(cidr: &str) -> Result<IpNetwork, Error> {
    let network = cidr
        .parse::<IpNetwork>()
        .map_err(|err| EbpfError::InvalidGeoIpCidr(cidr, err))?;
    Ok(network)
}

impl GeoBlockPort for GeoBlock {
    fn list_blocked(&self) -> Vec<String> {
        self.get_blocked_countries()
    }

    fn block_countries(&self, codes: &[String]) -> Result<u64, Error> {
        self.block_countries(codes)
    }

    fn unblock_countries(&self, codes: &[String]) -> Result<u64, Error> {
        self.unblock_countries(codes)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arc_swap::ArcSwap;

    use super::*;

    fn unavailable_geo_block() -> GeoBlock {
        GeoBlock::unavailable(Arc::new(ArcSwap::from_pointee(AppConfig::defaults())))
    }

    #[test]
    fn block_does_not_publish_state_when_rebuild_fails() {
        let geo_block = unavailable_geo_block();

        let result = geo_block.block_countries(&["US".to_string()]);

        assert!(result.is_err());
        assert!(geo_block.get_blocked_countries().is_empty());
    }

    #[test]
    fn unblock_does_not_publish_state_when_rebuild_fails() {
        let geo_block = unavailable_geo_block();
        geo_block
            .blocked_countries
            .store(Arc::new(HashSet::from(["US".to_string()])));

        let result = geo_block.unblock_countries(&["US".to_string()]);

        assert!(result.is_err());
        assert_eq!(geo_block.get_blocked_countries(), vec!["US".to_string()]);
    }
}
