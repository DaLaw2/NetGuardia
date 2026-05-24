use async_trait::async_trait;
use rusqlite::Error as RusqliteError;
use rusqlite::params;
use rusqlite::types::Type;

use super::Database;
use crate::common::error::Error;
use crate::common::error::database::DatabaseError;
use crate::domain::data_plane::acl_rule::AclRuleView;
use crate::domain::data_plane::direction::FlowDirection;
use crate::domain::data_plane::ip_version::IpVersion;
use crate::domain::data_plane::list_type::ListType;
use crate::interface::data_plane::acl::AclRepo;

impl Database {
    pub async fn insert_acl_rule(
        &self,
        ip_version: IpVersion,
        direction: FlowDirection,
        list_type: ListType,
        ip_address: &str,
        port: u16,
        preserve_active_soar_blocks: bool,
    ) -> Result<(), Error> {
        let ip_version = ip_version.as_u8();
        let direction = direction.as_str().to_string();
        let list_type = list_type.as_str().to_string();
        let ip_address = ip_address.to_string();
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                tx.execute(
                    "INSERT OR IGNORE INTO acl_rules (ip_version, direction, list_type, ip_address, port) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![ip_version, direction, list_type, ip_address, port as i64],
                )?;
                if preserve_active_soar_blocks {
                    tx.execute(
                        "UPDATE soar_block_rules
                         SET preserve_acl_on_unblock = 1
                         WHERE source_ip = ?1 AND unblocked_at IS NULL",
                        params![ip_address],
                    )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
    }

    pub async fn delete_acl_rule(
        &self,
        ip_version: IpVersion,
        direction: FlowDirection,
        list_type: ListType,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error> {
        let ip_version = ip_version.as_u8();
        let direction = direction.as_str().to_string();
        let list_type = list_type.as_str().to_string();
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
                    let raw_ip_version = row.get::<_, u8>(0)?;
                    Ok(AclRuleView {
                        ip_version: IpVersion::try_from(raw_ip_version).map_err(|_| {
                            RusqliteError::FromSqlConversionFailure(
                                0,
                                Type::Integer,
                                Box::new(DatabaseError::PersistedValueInvalid(
                                    "acl_rules",
                                    "ip_version",
                                    raw_ip_version.to_string(),
                                )),
                            )
                        })?,
                        direction: decode_acl_direction(row.get::<_, String>(1)?)?,
                        list_type: decode_acl_list_type(row.get::<_, String>(2)?)?,
                        ip_address: row.get(3)?,
                        port: decode_acl_port(row.get::<_, i64>(4)?)?,
                    })
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await
    }

    pub async fn has_manual_acl_rule(&self, ip_address: &str) -> Result<bool, Error> {
        let ip_address = ip_address.to_string();
        self.pool
            .conn_and_then(move |conn| {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM acl_rules
                     WHERE ip_address = ?1 AND direction = 'source' AND list_type = 'blacklist'
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
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
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

fn decode_acl_port(raw_port: i64) -> Result<u16, RusqliteError> {
    u16::try_from(raw_port).map_err(|_| {
        RusqliteError::FromSqlConversionFailure(
            4,
            Type::Integer,
            Box::new(DatabaseError::PersistedValueInvalid(
                "acl_rules",
                "port",
                raw_port.to_string(),
            )),
        )
    })
}

fn decode_acl_direction(raw_direction: String) -> Result<FlowDirection, RusqliteError> {
    raw_direction.parse::<FlowDirection>().map_err(|_| {
        RusqliteError::FromSqlConversionFailure(
            1,
            Type::Text,
            Box::new(DatabaseError::PersistedValueInvalid(
                "acl_rules",
                "direction",
                raw_direction,
            )),
        )
    })
}

fn decode_acl_list_type(raw_list_type: String) -> Result<ListType, RusqliteError> {
    raw_list_type.parse::<ListType>().map_err(|_| {
        RusqliteError::FromSqlConversionFailure(
            2,
            Type::Text,
            Box::new(DatabaseError::PersistedValueInvalid(
                "acl_rules",
                "list_type",
                raw_list_type,
            )),
        )
    })
}

#[async_trait]
impl AclRepo for Database {
    async fn list_acl_rules(&self) -> Result<Vec<AclRuleView>, Error> {
        self.list_acl_rules().await
    }

    async fn has_manual_acl_rule(&self, ip_address: &str) -> Result<bool, Error> {
        self.has_manual_acl_rule(ip_address).await
    }

    async fn list_admin_whitelist(&self) -> Result<Vec<String>, Error> {
        self.list_admin_whitelist().await
    }

    async fn insert_acl_rule(
        &self,
        ip_version: IpVersion,
        direction: FlowDirection,
        list_type: ListType,
        ip_address: &str,
        port: u16,
        preserve_active_soar_blocks: bool,
    ) -> Result<(), Error> {
        self.insert_acl_rule(
            ip_version,
            direction,
            list_type,
            ip_address,
            port,
            preserve_active_soar_blocks,
        )
        .await
    }

    async fn insert_admin_whitelist(&self, ip: &str) -> Result<(), Error> {
        self.insert_admin_whitelist(ip).await
    }

    async fn delete_acl_rule(
        &self,
        ip_version: IpVersion,
        direction: FlowDirection,
        list_type: ListType,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error> {
        self.delete_acl_rule(ip_version, direction, list_type, ip_address, port)
            .await
    }

    async fn delete_admin_whitelist(&self, ip: &str) -> Result<(), Error> {
        self.delete_admin_whitelist(ip).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_IP: &str = "198.51.100.42";
    const ACTIVE_UNTIL: &str = "2999-01-01 00:00:00";

    #[test]
    fn decode_acl_port_rejects_out_of_range_values() {
        assert!(decode_acl_port(-1).is_err());
        assert!(decode_acl_port(65_536).is_err());
    }

    #[test]
    fn decode_acl_port_accepts_valid_bounds() {
        assert_eq!(decode_acl_port(0).unwrap(), 0);
        assert_eq!(decode_acl_port(65_535).unwrap(), u16::MAX);
    }

    #[tokio::test]
    async fn destination_blacklist_does_not_preserve_soar_source_block() {
        let db = Database::new(":memory:").await.expect("database");
        db.commit_soar_block_to_db(SOURCE_IP, IpVersion::V4, 1, ACTIVE_UNTIL)
            .await
            .expect("soar block");
        db.insert_acl_rule(
            IpVersion::V4,
            FlowDirection::Source,
            ListType::Black,
            SOURCE_IP,
            0,
            true,
        )
        .await
        .expect("manual source acl");
        db.delete_acl_rule(IpVersion::V4, FlowDirection::Source, ListType::Black, SOURCE_IP, 0)
            .await
            .expect("remove manual source acl");
        db.insert_acl_rule(
            IpVersion::V4,
            FlowDirection::Destination,
            ListType::Black,
            SOURCE_IP,
            0,
            false,
        )
        .await
        .expect("manual destination acl");

        assert!(
            !db.has_manual_acl_rule(SOURCE_IP).await.expect("manual acl check"),
            "destination ACL ownership must not preserve a SOAR source block"
        );
    }
}
