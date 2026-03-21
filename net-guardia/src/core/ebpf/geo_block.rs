use std::collections::{HashMap as StdHashMap, HashSet};
use std::sync::Arc;

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::MapData;
use aya::Ebpf;
use ipnetwork::IpNetwork;
use macros::log;
use maxminddb::{geoip2, Reader};
use parking_lot::RwLock;

use crate::core::infrastructure::app_config::AppConfig;
use crate::model::error::ebpf::EbpfError;
use crate::model::error::misc::MiscError;
use crate::model::error::Error;
use crate::model::log::system::SystemLog;

/// Pre-indexed GeoIP prefix table, built once at startup.
struct GeoIndex {
    v4: StdHashMap<String, Vec<(u32, u32)>>,  // country -> [(ip_be, prefix_len)]
    v6: StdHashMap<String, Vec<(u128, u32)>>,
}

pub struct GeoBlock {
    geo_block_v4: RwLock<LpmTrie<MapData, u32, u8>>,
    geo_block_v6: RwLock<LpmTrie<MapData, u128, u8>>,
    blocked_countries: RwLock<HashSet<String>>,
    index: Arc<GeoIndex>,
}

impl GeoBlock {
    pub fn new(ebpf: &mut Ebpf, app_config: &AppConfig) -> Result<Self, Error> {
        let v4_map = ebpf.take_map("GEO_BLOCK_V4").ok_or(EbpfError::MapNotFound)?;
        let v4_trie = LpmTrie::try_from(v4_map).map_err(EbpfError::MapOperationError)?;

        let v6_map = ebpf.take_map("GEO_BLOCK_V6").ok_or(EbpfError::MapNotFound)?;
        let v6_trie = LpmTrie::try_from(v6_map).map_err(EbpfError::MapOperationError)?;

        let db_path = &app_config.misc.geoip_db_name;
        let reader = Reader::open_readfile(db_path)
            .map_err(|e| MiscError::GeoIPDatabaseError {
                path: db_path.clone(),
                reason: e.to_string(),
            })?;

        let index = Self::build_index(&reader)?;

        Ok(Self {
            geo_block_v4: RwLock::new(v4_trie),
            geo_block_v6: RwLock::new(v6_trie),
            blocked_countries: RwLock::new(HashSet::new()),
            index: Arc::new(index),
        })
    }

    /// Build index from MaxMind DB at startup. One-time cost.
    fn build_index(reader: &Reader<Vec<u8>>) -> Result<GeoIndex, Error> {
        let mut v4: StdHashMap<String, Vec<(u32, u32)>> = StdHashMap::new();
        let mut v6: StdHashMap<String, Vec<(u128, u32)>> = StdHashMap::new();

        let ipv4_all: IpNetwork = "0.0.0.0/0".parse().unwrap();
        if let Ok(iter) = reader.within(ipv4_all, Default::default()) {
            for result in iter {
                let Ok(lookup) = result else { continue };
                let Ok(network) = lookup.network() else { continue };
                let Ok(Some(city)) = lookup.decode::<geoip2::City>() else { continue };
                let Some(code) = city.country.iso_code else { continue };
                let code = code.to_uppercase();

                if let IpNetwork::V4(v4_net) = network {
                    let ip_be = u32::from(v4_net.ip()).to_be();
                    v4.entry(code).or_default().push((ip_be, v4_net.prefix() as u32));
                }
            }
        }

        let ipv6_all: IpNetwork = "::/0".parse().unwrap();
        if let Ok(iter) = reader.within(ipv6_all, Default::default()) {
            for result in iter {
                let Ok(lookup) = result else { continue };
                let Ok(network) = lookup.network() else { continue };
                let Ok(Some(city)) = lookup.decode::<geoip2::City>() else { continue };
                let Some(code) = city.country.iso_code else { continue };
                let code = code.to_uppercase();

                if let IpNetwork::V6(v6_net) = network {
                    let ip_be = u128::from(v6_net.ip()).to_be();
                    v6.entry(code).or_default().push((ip_be, v6_net.prefix() as u32));
                }
            }
        }

        Ok(GeoIndex { v4, v6 })
    }

    /// Block multiple countries at once, rebuilding tries only once.
    pub fn block_countries(&self, country_codes: &[String]) -> Result<u64, Error> {
        {
            let mut countries = self.blocked_countries.write();
            for code in country_codes {
                let upper = code.trim().to_uppercase();
                if upper.len() == 2 && upper.chars().all(|c| c.is_ascii_alphabetic()) {
                    countries.insert(upper);
                }
            }
        }
        self.rebuild_tries()
    }

    /// Unblock multiple countries at once, rebuilding tries only once.
    pub fn unblock_countries(&self, country_codes: &[String]) -> Result<u64, Error> {
        {
            let mut countries = self.blocked_countries.write();
            for code in country_codes {
                countries.remove(&code.trim().to_uppercase());
            }
        }
        self.rebuild_tries()
    }

    pub fn get_blocked_countries(&self) -> Vec<String> {
        self.blocked_countries.read().iter().cloned().collect()
    }

    /// Rebuild LPM tries from pre-indexed data. Fast — no DB scan.
    fn rebuild_tries(&self) -> Result<u64, Error> {
        let countries = self.blocked_countries.read().clone();

        // Collect entries from index (no DB scan)
        let mut v4_entries: Vec<(Key<u32>, u8)> = Vec::new();
        let mut v6_entries: Vec<(Key<u128>, u8)> = Vec::new();

        for code in &countries {
            if let Some(prefixes) = self.index.v4.get(code) {
                for &(ip_be, prefix_len) in prefixes {
                    v4_entries.push((Key::new(prefix_len, ip_be), 1u8));
                }
            }
            if let Some(prefixes) = self.index.v6.get(code) {
                for &(ip_be, prefix_len) in prefixes {
                    v6_entries.push((Key::new(prefix_len, ip_be), 1u8));
                }
            }
        }

        // Lock, clear, insert
        let mut v4_trie = self.geo_block_v4.write();
        let mut v6_trie = self.geo_block_v6.write();
        Self::clear_trie_v4(&mut v4_trie);
        Self::clear_trie_v6(&mut v6_trie);

        let mut count = 0u64;
        for (key, val) in &v4_entries {
            if v4_trie.insert(key, *val, 0).is_ok() {
                count += 1;
            }
        }
        for (key, val) in &v6_entries {
            if v6_trie.insert(key, *val, 0).is_ok() {
                count += 1;
            }
        }

        Ok(count)
    }

    fn clear_trie_v4(trie: &mut LpmTrie<MapData, u32, u8>) {
        let keys: Vec<Key<u32>> = trie.iter()
            .filter_map(|r| r.ok())
            .map(|(k, _)| k)
            .collect();
        for key in keys {
            let _ = trie.remove(&key);
        }
    }

    fn clear_trie_v6(trie: &mut LpmTrie<MapData, u128, u8>) {
        let keys: Vec<Key<u128>> = trie.iter()
            .filter_map(|r| r.ok())
            .map(|(k, _)| k)
            .collect();
        for key in keys {
            let _ = trie.remove(&key);
        }
    }
}
