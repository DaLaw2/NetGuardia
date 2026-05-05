use async_trait::async_trait;
use rusqlite::params;

use super::Database;
use crate::domain::common::error::Error;
use crate::interface::enforcement::EnforcementRepo;

impl Database {
    pub async fn set_rate_limit(&self, key: &str, value: u64) -> Result<(), Error> {
        let key = key.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO rate_limit_config (key, value) VALUES (?1, ?2)",
                    params![key, value as i64],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn load_rate_limit_config(&self) -> Result<Vec<(String, u64)>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare("SELECT key, value FROM rate_limit_config")?;
                let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64)))?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            })
            .await
    }

    pub async fn insert_dns_domains(&self, domains: &[String]) -> Result<(), Error> {
        let domains = domains.to_vec();
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                for domain in domains {
                    tx.execute(
                        "INSERT OR IGNORE INTO dns_blacklist (domain) VALUES (?1)",
                        params![domain],
                    )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
    }

    pub async fn delete_dns_domains(&self, domains: &[String]) -> Result<(), Error> {
        let domains = domains.to_vec();
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                for domain in domains {
                    tx.execute("DELETE FROM dns_blacklist WHERE domain = ?1", params![domain])?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
    }

    pub async fn load_dns_domains(&self) -> Result<Vec<String>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare("SELECT domain FROM dns_blacklist")?;
                let rows = stmt.query_map([], |row| row.get(0))?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            })
            .await
    }

    pub async fn insert_geo_country(&self, code: &str) -> Result<(), Error> {
        let code = code.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT OR IGNORE INTO geo_blocked_countries (country_code) VALUES (?1)",
                    params![code],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn delete_geo_country(&self, code: &str) -> Result<(), Error> {
        let code = code.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "DELETE FROM geo_blocked_countries WHERE country_code = ?1",
                    params![code],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn load_geo_countries(&self) -> Result<Vec<String>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare("SELECT country_code FROM geo_blocked_countries")?;
                let rows = stmt.query_map([], |row| row.get(0))?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            })
            .await
    }
}

#[async_trait]
impl EnforcementRepo for Database {
    async fn set_rate_limit(&self, key: &str, value: u64) -> Result<(), Error> {
        self.set_rate_limit(key, value).await
    }

    async fn insert_dns_domains(&self, domains: &[String]) -> Result<(), Error> {
        self.insert_dns_domains(domains).await
    }

    async fn delete_dns_domains(&self, domains: &[String]) -> Result<(), Error> {
        self.delete_dns_domains(domains).await
    }

    async fn insert_geo_country(&self, code: &str) -> Result<(), Error> {
        self.insert_geo_country(code).await
    }

    async fn delete_geo_country(&self, code: &str) -> Result<(), Error> {
        self.delete_geo_country(code).await
    }
}
