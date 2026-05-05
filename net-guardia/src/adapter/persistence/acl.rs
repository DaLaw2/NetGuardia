use async_trait::async_trait;
use rusqlite::params;

use super::Database;
use crate::domain::common::error::Error;
use crate::domain::data_plane::acl_rule::AclRuleView;
use crate::interface::acl::AclRepo;

impl Database {
    pub async fn insert_acl_rule(
        &self,
        ip_version: u8,
        direction: &str,
        list_type: &str,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error> {
        let direction = direction.to_string();
        let list_type = list_type.to_string();
        let ip_address = ip_address.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT OR IGNORE INTO acl_rules (ip_version, direction, list_type, ip_address, port) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![ip_version, direction, list_type, ip_address, port as i64],
                )?;
                if direction == "source" && list_type == "blacklist" {
                    conn.execute(
                        "UPDATE soar_block_rules
                         SET preserve_acl_on_unblock = 1
                         WHERE source_ip = ?1 AND unblocked_at IS NULL",
                        params![ip_address],
                    )?;
                }
                Ok(())
            })
            .await
    }

    pub async fn delete_acl_rule(
        &self,
        ip_version: u8,
        direction: &str,
        list_type: &str,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error> {
        let direction = direction.to_string();
        let list_type = list_type.to_string();
        let ip_address = ip_address.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "DELETE FROM acl_rules WHERE ip_version = ?1 AND direction = ?2 AND list_type = ?3 AND ip_address = ?4 AND port = ?5",
                    params![ip_version, direction, list_type, ip_address, port as i64],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn list_acl_rules(&self) -> Result<Vec<AclRuleView>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT ip_version, direction, list_type, ip_address, port FROM acl_rules")?;
                let rows = stmt.query_map([], |row| {
                    Ok(AclRuleView {
                        ip_version: row.get(0)?,
                        direction: row.get(1)?,
                        list_type: row.get(2)?,
                        ip_address: row.get(3)?,
                        port: row.get::<_, i64>(4)? as u16,
                    })
                })?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            })
            .await
    }

    pub async fn has_manual_acl_rule(&self, ip_address: &str) -> Result<bool, Error> {
        let ip_address = ip_address.to_string();
        self.pool
            .conn_and_then(move |conn| {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM acl_rules
                     WHERE ip_address = ?1 AND list_type = 'blacklist'
                       AND EXISTS (
                           SELECT 1 FROM soar_block_rules
                           WHERE soar_block_rules.source_ip = acl_rules.ip_address
                             AND soar_block_rules.unblocked_at IS NULL
                             AND (
                                 soar_block_rules.preserve_acl_on_unblock = 1
                                 OR soar_block_rules.created_acl_rule = 0
                             )
                       )",
                    params![ip_address],
                    |row| row.get(0),
                )?;
                Ok(count > 0)
            })
            .await
    }

    pub async fn list_admin_whitelist(&self) -> Result<Vec<String>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare("SELECT ip FROM admin_whitelist")?;
                let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
                let mut result = Vec::new();
                for row in rows {
                    result.push(row?);
                }
                Ok(result)
            })
            .await
    }

    pub async fn insert_admin_whitelist(&self, ip: &str) -> Result<(), Error> {
        let ip = ip.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute("INSERT OR IGNORE INTO admin_whitelist (ip) VALUES (?1)", params![ip])?;
                Ok(())
            })
            .await
    }

    pub async fn delete_admin_whitelist(&self, ip: &str) -> Result<(), Error> {
        let ip = ip.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute("DELETE FROM admin_whitelist WHERE ip = ?1", params![ip])?;
                Ok(())
            })
            .await
    }
}

#[async_trait]
impl AclRepo for Database {
    async fn insert_acl_rule(
        &self,
        ip_version: u8,
        direction: &str,
        list_type: &str,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error> {
        self.insert_acl_rule(ip_version, direction, list_type, ip_address, port)
            .await
    }

    async fn delete_acl_rule(
        &self,
        ip_version: u8,
        direction: &str,
        list_type: &str,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error> {
        self.delete_acl_rule(ip_version, direction, list_type, ip_address, port)
            .await
    }

    async fn has_manual_acl_rule(&self, ip_address: &str) -> Result<bool, Error> {
        self.has_manual_acl_rule(ip_address).await
    }

    async fn list_admin_whitelist(&self) -> Result<Vec<String>, Error> {
        self.list_admin_whitelist().await
    }

    async fn insert_admin_whitelist(&self, ip: &str) -> Result<(), Error> {
        self.insert_admin_whitelist(ip).await
    }

    async fn delete_admin_whitelist(&self, ip: &str) -> Result<(), Error> {
        self.delete_admin_whitelist(ip).await
    }
}
