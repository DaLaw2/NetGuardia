use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::MapData;
use aya::Ebpf;
use ipnetwork::IpNetwork;
use maxminddb::{geoip2, Reader};
use parking_lot::RwLock;

use crate::model::error::ebpf::EbpfError;
use crate::model::error::misc::MiscError;
use crate::model::error::Error;

pub struct GeoBlock {
    geo_block_v4: RwLock<LpmTrie<MapData, u32, u8>>,
    geo_block_v6: RwLock<LpmTrie<MapData, u128, u8>>,
    blocked_countries: RwLock<HashSet<String>>,
    reader: Arc<Reader<Vec<u8>>>,
}

impl GeoBlock {
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, Error> {
        let v4_map = ebpf.take_map("GEO_BLOCK_V4").ok_or(EbpfError::MapNotFound)?;
        let v4_trie = LpmTrie::try_from(v4_map).map_err(EbpfError::MapOperationError)?;

        let v6_map = ebpf.take_map("GEO_BLOCK_V6").ok_or(EbpfError::MapNotFound)?;
        let v6_trie = LpmTrie::try_from(v6_map).map_err(EbpfError::MapOperationError)?;

        let db_path = PathBuf::from("net-guardia/static/geo/GeoLite2-City.mmdb");
        let reader = Reader::open_readfile(&db_path)
            .map_err(MiscError::InvalidGeoIPConfiguration)?;

        Ok(Self {
            geo_block_v4: RwLock::new(v4_trie),
            geo_block_v6: RwLock::new(v6_trie),
            blocked_countries: RwLock::new(HashSet::new()),
            reader: Arc::new(reader),
        })
    }

    pub fn block_country(&self, country_code: &str) -> Result<u64, Error> {
        {
            let mut countries = self.blocked_countries.write();
            countries.insert(country_code.to_uppercase());
        }
        self.rebuild_tries()
    }

    pub fn unblock_country(&self, country_code: &str) -> Result<u64, Error> {
        {
            let mut countries = self.blocked_countries.write();
            countries.remove(&country_code.to_uppercase());
        }
        self.rebuild_tries()
    }

    pub fn get_blocked_countries(&self) -> Vec<String> {
        let countries = self.blocked_countries.read();
        countries.iter().cloned().collect()
    }

    /// Rebuild both LPM tries from scratch based on the current set of blocked countries.
    /// Returns the total number of prefixes inserted.
    fn rebuild_tries(&self) -> Result<u64, Error> {
        let countries = self.blocked_countries.read().clone();
        let mut v4_trie = self.geo_block_v4.write();
        let mut v6_trie = self.geo_block_v6.write();

        // Clear existing entries by iterating and removing
        // For LpmTrie, we need to iterate keys and remove them
        // Since aya LpmTrie doesn't have a clear method, we remove entries one by one
        Self::clear_v4_trie(&mut v4_trie);
        Self::clear_v6_trie(&mut v6_trie);

        if countries.is_empty() {
            return Ok(0);
        }

        let mut count = 0u64;

        // Iterate all IPv4 networks
        let ipv4_all: IpNetwork = "0.0.0.0/0".parse().unwrap();
        if let Ok(iter) = self.reader.within(ipv4_all, Default::default()) {
            for result in iter {
                let Ok(lookup) = result else { continue };
                let Ok(network) = lookup.network() else { continue };
                let Ok(city_opt) = lookup.decode::<geoip2::City>() else { continue };
                let Some(city) = city_opt else { continue };

                let iso_code = city.country.iso_code.map(|s| s.to_uppercase());
                if let Some(ref code) = iso_code {
                    if !countries.contains(code) {
                        continue;
                    }
                } else {
                    continue;
                }

                if let IpNetwork::V4(v4_net) = network {
                    let ip_be = u32::from(v4_net.ip()).to_be();
                    let key = Key::new(v4_net.prefix() as u32, ip_be);
                    if v4_trie.insert(&key, 1u8, 0).is_ok() {
                        count += 1;
                    }
                }
            }
        }

        // Iterate all IPv6 networks
        let ipv6_all: IpNetwork = "::/0".parse().unwrap();
        if let Ok(iter) = self.reader.within(ipv6_all, Default::default()) {
            for result in iter {
                let Ok(lookup) = result else { continue };
                let Ok(network) = lookup.network() else { continue };
                let Ok(city_opt) = lookup.decode::<geoip2::City>() else { continue };
                let Some(city) = city_opt else { continue };

                let iso_code = city.country.iso_code.map(|s| s.to_uppercase());
                if let Some(ref code) = iso_code {
                    if !countries.contains(code) {
                        continue;
                    }
                } else {
                    continue;
                }

                if let IpNetwork::V6(v6_net) = network {
                    let ip_be = u128::from(v6_net.ip()).to_be();
                    let key = Key::new(v6_net.prefix() as u32, ip_be);
                    if v6_trie.insert(&key, 1u8, 0).is_ok() {
                        count += 1;
                    }
                }
            }
        }

        Ok(count)
    }

    fn clear_v4_trie(trie: &mut LpmTrie<MapData, u32, u8>) {
        // Collect keys to remove
        let keys: Vec<Key<u32>> = trie.iter()
            .filter_map(|r| r.ok())
            .map(|(k, _)| k)
            .collect();
        for key in keys {
            let _ = trie.remove(&key);
        }
    }

    fn clear_v6_trie(trie: &mut LpmTrie<MapData, u128, u8>) {
        let keys: Vec<Key<u128>> = trie.iter()
            .filter_map(|r| r.ok())
            .map(|(k, _)| k)
            .collect();
        for key in keys {
            let _ = trie.remove(&key);
        }
    }
}
