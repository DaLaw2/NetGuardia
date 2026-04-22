use rusqlite::params;

use super::Database;
use crate::domain::common::error::Error;
use crate::interface::port::enforcement::EnforcementRepo;

impl Database {
    pub fn set_rate_limit(&self, key: &str, value: u64) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO rate_limit_config (key, value) VALUES (?1, ?2)",
            params![key, value as i64],
        )?;
        Ok(())
    }

    pub fn load_rate_limit_config(&self) -> Result<Vec<(String, u64)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT key, value FROM rate_limit_config")?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64)))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn insert_dns_domain(&self, domain: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO dns_blacklist (domain) VALUES (?1)",
            params![domain],
        )?;
        Ok(())
    }

    pub fn delete_dns_domain(&self, domain: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM dns_blacklist WHERE domain = ?1", params![domain])?;
        Ok(())
    }

    pub fn load_dns_domains(&self) -> Result<Vec<String>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT domain FROM dns_blacklist")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn insert_geo_country(&self, code: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO geo_blocked_countries (country_code) VALUES (?1)",
            params![code],
        )?;
        Ok(())
    }

    pub fn delete_geo_country(&self, code: &str) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM geo_blocked_countries WHERE country_code = ?1",
            params![code],
        )?;
        Ok(())
    }

    pub fn load_geo_countries(&self) -> Result<Vec<String>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT country_code FROM geo_blocked_countries")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }
}

impl EnforcementRepo for Database {
    fn set_rate_limit(&self, key: &str, value: u64) -> Result<(), Error> {
        self.set_rate_limit(key, value)
    }

    fn insert_dns_domain(&self, domain: &str) -> Result<(), Error> {
        self.insert_dns_domain(domain)
    }

    fn delete_dns_domain(&self, domain: &str) -> Result<(), Error> {
        self.delete_dns_domain(domain)
    }

    fn insert_geo_country(&self, code: &str) -> Result<(), Error> {
        self.insert_geo_country(code)
    }

    fn delete_geo_country(&self, code: &str) -> Result<(), Error> {
        self.delete_geo_country(code)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_db;

    #[test]
    fn test_dns_crud() {
        let db = test_db();
        db.insert_dns_domain("evil.com").unwrap();
        let domains = db.load_dns_domains().unwrap();
        assert_eq!(domains, vec!["evil.com"]);

        db.delete_dns_domain("evil.com").unwrap();
        assert!(db.load_dns_domains().unwrap().is_empty());
    }

    #[test]
    fn test_geo_crud() {
        let db = test_db();
        db.insert_geo_country("CN").unwrap();
        let countries = db.load_geo_countries().unwrap();
        assert_eq!(countries, vec!["CN"]);

        db.delete_geo_country("CN").unwrap();
        assert!(db.load_geo_countries().unwrap().is_empty());
    }

    #[test]
    fn test_rate_limit_crud() {
        let db = test_db();
        db.set_rate_limit("packet_rate", 1000).unwrap();
        let configs = db.load_rate_limit_config().unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0], ("packet_rate".to_string(), 1000));
    }
}
