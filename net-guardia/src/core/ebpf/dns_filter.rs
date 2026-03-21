use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::Ebpf;
use common::model::dns_name::DnsName;
use common::model::placeholder::PlaceHolder;
use tokio::sync::RwLock;

use crate::model::error::ebpf::EbpfError;
use crate::model::error::misc::MiscError;
use crate::model::error::Error;

pub struct DnsFilter {
    blacklist: RwLock<AyaHashMap<MapData, DnsName, PlaceHolder>>,
}

impl DnsFilter {
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, Error> {
        let map = ebpf.take_map("DNS_BLACKLIST").ok_or(EbpfError::MapNotFound)?;
        let map = AyaHashMap::try_from(map).map_err(EbpfError::MapOperationError)?;
        Ok(Self {
            blacklist: RwLock::new(map),
        })
    }

    pub async fn add_domain(&self, domain: &str) -> Result<(), Error> {
        let name = domain_to_wire_format(domain)?;
        self.blacklist
            .write()
            .await
            .insert(name, 0u8, 0)
            .map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    pub async fn remove_domain(&self, domain: &str) -> Result<(), Error> {
        let name = domain_to_wire_format(domain)?;
        self.blacklist
            .write()
            .await
            .remove(&name)
            .map_err(EbpfError::MapOperationError)?;
        Ok(())
    }

    pub async fn list_domains(&self) -> Vec<String> {
        let map = self.blacklist.read().await;
        map.keys()
            .filter_map(Result::ok)
            .filter_map(|key| wire_format_to_domain(&key))
            .collect()
    }
}

/// Convert a human-readable domain name (e.g., "example.com") to DNS wire format.
/// The result is a DnsName with lowercase, length-prefixed labels, zero-terminated and zero-padded.
fn domain_to_wire_format(domain: &str) -> Result<DnsName, Error> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    let mut name = DnsName::zeroed();
    let mut pos: usize = 0;

    for label in domain.split('.') {
        let label_bytes = label.as_bytes();
        let label_len = label_bytes.len();
        if label_len == 0 || label_len >= 64 {
            return Err(MiscError::InvalidDnsName {
                reason: format!("invalid label length: {}", label_len),
            }.into());
        }
        if pos + 1 + label_len >= 128 {
            return Err(MiscError::InvalidDnsName {
                reason: format!("domain name too long: {}", domain),
            }.into());
        }
        name.data[pos] = label_len as u8;
        pos += 1;
        name.data[pos..pos + label_len].copy_from_slice(label_bytes);
        pos += label_len;
    }

    // Terminating zero byte
    if pos < 128 {
        name.data[pos] = 0;
    }

    Ok(name)
}

/// Convert DNS wire format back to a human-readable domain name.
fn wire_format_to_domain(name: &DnsName) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos: usize = 0;

    loop {
        if pos >= 128 {
            break;
        }
        let label_len = name.data[pos] as usize;
        if label_len == 0 {
            break;
        }
        if label_len >= 64 || pos + 1 + label_len > 128 {
            return None;
        }
        pos += 1;
        let label = core::str::from_utf8(&name.data[pos..pos + label_len]).ok()?;
        labels.push(label.to_string());
        pos += label_len;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}
