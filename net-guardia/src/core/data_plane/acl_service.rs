use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use macros::log;

use crate::common::error::Error;
use crate::common::log::data_plane::DataPlaneLog;
use crate::domain::data_plane::direction::FlowDirection;
use crate::domain::data_plane::error::EbpfError;
use crate::domain::data_plane::ip_version::IpVersion;
use crate::domain::data_plane::list_type::ListType;
use crate::interface::data_plane::access_control_admin::AccessControlAdminPort;
use crate::interface::data_plane::acl::AclRepo;
use crate::interface::data_plane::enforcement::GeoEnforcementPort;
use crate::interface::data_plane::geo_block_api::GeoBlockPort;

pub struct AclService {
    acl_repo: Arc<dyn AclRepo>,
    enforcement_repo: Arc<dyn GeoEnforcementPort>,
    access_control: Arc<dyn AccessControlAdminPort>,
    geo_block: Arc<dyn GeoBlockPort>,
}

impl AclService {
    pub fn new(
        acl_repo: Arc<dyn AclRepo>,
        enforcement_repo: Arc<dyn GeoEnforcementPort>,
        access_control: Arc<dyn AccessControlAdminPort>,
        geo_block: Arc<dyn GeoBlockPort>,
    ) -> Self {
        Self {
            acl_repo,
            enforcement_repo,
            access_control,
            geo_block,
        }
    }

    pub async fn restore(&self) {
        self.restore_geo_countries().await;
        self.restore_acl_rules().await;
    }

    async fn restore_geo_countries(&self) {
        let countries = match self.enforcement_repo.load_geo_countries().await {
            Ok(c) if !c.is_empty() => c,
            _ => return,
        };
        match self.geo_block.block_countries(&countries) {
            Ok(_) => log!(DataPlaneLog::GeoCountriesRestored(countries.len())),
            Err(e) => log!(DataPlaneLog::GeoRestoreFailed(e.to_string())),
        }
    }

    async fn restore_acl_rules(&self) {
        let rules = match self.acl_repo.list_acl_rules().await {
            Ok(r) => r,
            Err(_) => return,
        };
        let mut restored = 0u32;
        for rule in &rules {
            let result = match rule.ip_version {
                IpVersion::V4 => match rule.ip_address.parse::<Ipv4Addr>() {
                    Ok(addr) => self.access_control.add_ipv4_list(
                        rule.direction,
                        rule.list_type,
                        SocketAddrV4::new(addr, rule.port),
                    ),
                    Err(e) => {
                        log!(DataPlaneLog::AclIpv4ParseFailed(rule.ip_address.clone(), e.to_string()));
                        continue;
                    }
                },
                IpVersion::V6 => match rule.ip_address.parse::<Ipv6Addr>() {
                    Ok(addr) => self.access_control.add_ipv6_list(
                        rule.direction,
                        rule.list_type,
                        SocketAddrV6::new(addr, rule.port, 0, 0),
                    ),
                    Err(e) => {
                        log!(DataPlaneLog::AclIpv6ParseFailed(rule.ip_address.clone(), e.to_string()));
                        continue;
                    }
                },
            };
            if let Err(e) = result {
                log!(DataPlaneLog::AclRuleRestoreFailed(
                    rule.direction.as_str().to_string(),
                    rule.list_type.as_str().to_string(),
                    rule.ip_address.clone(),
                    rule.port,
                    e.to_string()
                ));
            } else {
                restored += 1;
            }
        }
        if restored > 0 {
            log!(DataPlaneLog::AclRulesRestored(restored as usize));
        }
    }

    pub async fn add_ipv4(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV4,
    ) -> Result<(), Error> {
        self.access_control.add_ipv4_list(direction, list_type, address)?;
        if let Err(e) = self
            .acl_repo
            .insert_acl_rule(
                IpVersion::V4,
                direction,
                list_type,
                &address.ip().to_string(),
                address.port(),
                should_preserve_active_soar_blocks(direction, list_type),
            )
            .await
        {
            if let Err(rollback_err) = self.access_control.remove_ipv4_list(direction, list_type, address) {
                log!(EbpfError::RollbackFailed(rollback_err));
            }
            return Err(e);
        }
        Ok(())
    }

    pub async fn add_ipv6(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV6,
    ) -> Result<(), Error> {
        self.access_control.add_ipv6_list(direction, list_type, address)?;
        if let Err(e) = self
            .acl_repo
            .insert_acl_rule(
                IpVersion::V6,
                direction,
                list_type,
                &address.ip().to_string(),
                address.port(),
                should_preserve_active_soar_blocks(direction, list_type),
            )
            .await
        {
            if let Err(rollback_err) = self.access_control.remove_ipv6_list(direction, list_type, address) {
                log!(EbpfError::RollbackFailed(rollback_err));
            }
            return Err(e);
        }
        Ok(())
    }

    pub async fn remove_ipv4(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV4,
    ) -> Result<(), Error> {
        self.access_control.remove_ipv4_list(direction, list_type, address)?;
        if let Err(e) = self
            .acl_repo
            .delete_acl_rule(
                IpVersion::V4,
                direction,
                list_type,
                &address.ip().to_string(),
                address.port(),
            )
            .await
        {
            if let Err(rollback_err) = self.access_control.add_ipv4_list(direction, list_type, address) {
                log!(EbpfError::RollbackFailed(rollback_err));
            }
            return Err(e);
        }
        Ok(())
    }

    pub async fn remove_ipv6(
        &self,
        direction: FlowDirection,
        list_type: ListType,
        address: SocketAddrV6,
    ) -> Result<(), Error> {
        self.access_control.remove_ipv6_list(direction, list_type, address)?;
        if let Err(e) = self
            .acl_repo
            .delete_acl_rule(
                IpVersion::V6,
                direction,
                list_type,
                &address.ip().to_string(),
                address.port(),
            )
            .await
        {
            if let Err(rollback_err) = self.access_control.add_ipv6_list(direction, list_type, address) {
                log!(EbpfError::RollbackFailed(rollback_err));
            }
            return Err(e);
        }
        Ok(())
    }

    pub async fn block_geo_countries(&self, codes: &[String]) -> Result<u64, Error> {
        let codes = normalize_geo_codes(codes)?;
        let current = current_geo_set(self.geo_block.as_ref());
        let delta: Vec<String> = codes.iter().filter(|code| !current.contains(*code)).cloned().collect();
        let total = self.geo_block.block_countries(&codes)?;
        if let Err(e) = self.enforcement_repo.insert_geo_countries(&codes).await {
            if let Err(rollback_err) = self.geo_block.unblock_countries(&delta) {
                log!(EbpfError::RollbackFailed(rollback_err));
            }
            return Err(e);
        }
        Ok(total)
    }

    pub async fn unblock_geo_countries(&self, codes: &[String]) -> Result<u64, Error> {
        let codes = normalize_geo_codes(codes)?;
        let current = current_geo_set(self.geo_block.as_ref());
        let delta: Vec<String> = codes.iter().filter(|code| current.contains(*code)).cloned().collect();
        let total = self.geo_block.unblock_countries(&codes)?;
        if let Err(e) = self.enforcement_repo.delete_geo_countries(&codes).await {
            if let Err(rollback_err) = self.geo_block.block_countries(&delta) {
                log!(EbpfError::RollbackFailed(rollback_err));
            }
            return Err(e);
        }
        Ok(total)
    }

    pub fn get_blocked_countries(&self) -> Vec<String> {
        self.geo_block.list_blocked()
    }

    pub fn access_control(&self) -> &dyn AccessControlAdminPort {
        self.access_control.as_ref()
    }
}

fn current_geo_set(geo_block: &dyn GeoBlockPort) -> HashSet<String> {
    geo_block
        .list_blocked()
        .into_iter()
        .map(|code| code.trim().to_uppercase())
        .collect()
}

fn should_preserve_active_soar_blocks(direction: FlowDirection, list_type: ListType) -> bool {
    direction == FlowDirection::Source && list_type == ListType::Black
}

fn normalize_geo_codes(codes: &[String]) -> Result<Vec<String>, Error> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();
    for code in codes {
        let upper = code.trim().to_uppercase();
        if upper.len() != 2 || !upper.chars().all(|c| c.is_ascii_alphabetic()) {
            Err(EbpfError::InvalidCountryCode(code.clone()))?;
        }
        if seen.insert(upper.clone()) {
            normalized.push(upper);
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_geo_codes_uppercases_trims_and_deduplicates() {
        let codes = vec![" us ".to_string(), "US".to_string(), "jp".to_string()];

        let normalized = normalize_geo_codes(&codes).expect("valid country codes");

        assert_eq!(normalized, vec!["US".to_string(), "JP".to_string()]);
    }

    #[test]
    fn normalize_geo_codes_rejects_invalid_values() {
        let codes = vec!["usa".to_string(), "1p".to_string()];

        let result = normalize_geo_codes(&codes);

        assert!(result.is_err());
    }
}
