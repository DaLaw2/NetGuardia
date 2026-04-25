use rusqlite::params;

use super::Database;
use crate::domain::common::error::Error;
use crate::domain::data_plane::acl_rule::AclRuleView;
use crate::interface::acl::AclRepo;

impl Database {
    pub fn insert_acl_rule(
        &self,
        ip_version: u8,
        direction: &str,
        list_type: &str,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO acl_rules (ip_version, direction, list_type, ip_address, port) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ip_version, direction, list_type, ip_address, port as i64],
        )?;
        Ok(())
    }

    pub fn delete_acl_rule(
        &self,
        ip_version: u8,
        direction: &str,
        list_type: &str,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM acl_rules WHERE ip_version = ?1 AND direction = ?2 AND list_type = ?3 AND ip_address = ?4 AND port = ?5",
            params![ip_version, direction, list_type, ip_address, port as i64],
        )?;
        Ok(())
    }

    pub fn list_acl_rules(&self) -> Result<Vec<AclRuleView>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT ip_version, direction, list_type, ip_address, port FROM acl_rules")?;
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
    }

    pub fn has_manual_acl_rule(&self, ip_address: &str) -> Result<bool, Error> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM acl_rules
             WHERE ip_address = ?1 AND list_type = 'blacklist'
               AND NOT EXISTS (
                   SELECT 1 FROM soar_block_rules
                   WHERE soar_block_rules.source_ip = acl_rules.ip_address
                     AND soar_block_rules.unblocked_at IS NULL
               )",
            params![ip_address],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn list_admin_whitelist(&self) -> Result<Vec<String>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT ip FROM admin_whitelist")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn insert_admin_whitelist(&self, ip: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute("INSERT OR IGNORE INTO admin_whitelist (ip) VALUES (?1)", params![ip])?;
        Ok(())
    }

    pub fn delete_admin_whitelist(&self, ip: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM admin_whitelist WHERE ip = ?1", params![ip])?;
        Ok(())
    }
}

impl AclRepo for Database {
    fn insert_acl_rule(
        &self,
        ip_version: u8,
        direction: &str,
        list_type: &str,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error> {
        self.insert_acl_rule(ip_version, direction, list_type, ip_address, port)
    }

    fn delete_acl_rule(
        &self,
        ip_version: u8,
        direction: &str,
        list_type: &str,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error> {
        self.delete_acl_rule(ip_version, direction, list_type, ip_address, port)
    }

    fn has_manual_acl_rule(&self, ip_address: &str) -> Result<bool, Error> {
        self.has_manual_acl_rule(ip_address)
    }

    fn list_admin_whitelist(&self) -> Result<Vec<String>, Error> {
        self.list_admin_whitelist()
    }

    fn insert_admin_whitelist(&self, ip: &str) -> Result<(), Error> {
        self.insert_admin_whitelist(ip)
    }

    fn delete_admin_whitelist(&self, ip: &str) -> Result<(), Error> {
        self.delete_admin_whitelist(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_db;

    #[test]
    fn test_acl_crud() {
        let db = test_db();
        db.insert_acl_rule(4, "source", "blacklist", "192.168.1.1", 80).unwrap();
        let rules = db.list_acl_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].ip_version, 4);
        assert_eq!(rules[0].direction, "source");
        assert_eq!(rules[0].list_type, "blacklist");
        assert_eq!(rules[0].ip_address, "192.168.1.1");
        assert_eq!(rules[0].port, 80);

        db.delete_acl_rule(4, "source", "blacklist", "192.168.1.1", 80).unwrap();
        let rules = db.list_acl_rules().unwrap();
        assert!(rules.is_empty());
    }
}
