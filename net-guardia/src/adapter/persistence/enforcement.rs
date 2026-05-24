use async_trait::async_trait;
use rusqlite::Error as RusqliteError;
use rusqlite::params;
use rusqlite::types::Type;

use super::Database;
use crate::common::error::Error;
use crate::common::error::database::DatabaseError;
use crate::interface::data_plane::enforcement::DnsEnforcementPort;
use crate::interface::data_plane::enforcement::GeoEnforcementPort;
use crate::interface::data_plane::enforcement::RateLimitWritePort;

impl Database {
    pub async fn set_rate_limits(&self, values: &[(String, u64)]) -> Result<(), Error> {
        let values: Vec<(String, i64)> = values
            .iter()
            .map(|(key, value)| Ok((key.clone(), encode_rate_limit_value(*value)?)))
            .collect::<Result<_, Error>>()?;
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                for (key, value) in values {
                    tx.execute(
                        "INSERT OR REPLACE INTO rate_limit_config (key, value) VALUES (?1, ?2)",
                        params![key, value],
                    )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
    }

    pub async fn load_rate_limit_config(&self) -> Result<Vec<(String, u64)>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare("SELECT key, value FROM rate_limit_config")?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        decode_rate_limit_value(row.get::<_, i64>(1)?)?,
                    ))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
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
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await
    }

    pub async fn insert_geo_countries(&self, codes: &[String]) -> Result<(), Error> {
        let codes = codes.to_vec();
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                for code in codes {
                    tx.execute(
                        "INSERT OR IGNORE INTO geo_blocked_countries (country_code) VALUES (?1)",
                        params![code],
                    )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
    }

    pub async fn delete_geo_countries(&self, codes: &[String]) -> Result<(), Error> {
        let codes = codes.to_vec();
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                for code in codes {
                    tx.execute(
                        "DELETE FROM geo_blocked_countries WHERE country_code = ?1",
                        params![code],
                    )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
    }

    pub async fn load_geo_countries(&self) -> Result<Vec<String>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare("SELECT country_code FROM geo_blocked_countries")?;
                let rows = stmt.query_map([], |row| row.get(0))?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await
    }
}

fn encode_rate_limit_value(value: u64) -> Result<i64, Error> {
    i64::try_from(value)
        .map_err(|_| DatabaseError::PersistedValueInvalid("rate_limit_config", "value", value.to_string()).into())
}

fn decode_rate_limit_value(raw_value: i64) -> Result<u64, RusqliteError> {
    u64::try_from(raw_value).map_err(|_| {
        RusqliteError::FromSqlConversionFailure(
            1,
            Type::Integer,
            Box::new(DatabaseError::PersistedValueInvalid(
                "rate_limit_config",
                "value",
                raw_value.to_string(),
            )),
        )
    })
}

#[async_trait]
impl RateLimitWritePort for Database {
    async fn load_rate_limit_config(&self) -> Result<Vec<(String, u64)>, Error> {
        self.load_rate_limit_config().await
    }

    async fn set_rate_limits(&self, values: &[(String, u64)]) -> Result<(), Error> {
        self.set_rate_limits(values).await
    }
}

#[async_trait]
impl DnsEnforcementPort for Database {
    async fn load_dns_domains(&self) -> Result<Vec<String>, Error> {
        self.load_dns_domains().await
    }

    async fn insert_dns_domains(&self, domains: &[String]) -> Result<(), Error> {
        self.insert_dns_domains(domains).await
    }

    async fn delete_dns_domains(&self, domains: &[String]) -> Result<(), Error> {
        self.delete_dns_domains(domains).await
    }
}

#[async_trait]
impl GeoEnforcementPort for Database {
    async fn load_geo_countries(&self) -> Result<Vec<String>, Error> {
        self.load_geo_countries().await
    }

    async fn insert_geo_countries(&self, codes: &[String]) -> Result<(), Error> {
        self.insert_geo_countries(codes).await
    }

    async fn delete_geo_countries(&self, codes: &[String]) -> Result<(), Error> {
        self.delete_geo_countries(codes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_rate_limit_value_rejects_negative_values() {
        assert!(decode_rate_limit_value(-1).is_err());
    }

    #[test]
    fn encode_rate_limit_value_rejects_values_above_sqlite_integer_range() {
        assert!(encode_rate_limit_value(i64::MAX as u64 + 1).is_err());
    }

    #[test]
    fn rate_limit_value_codec_accepts_valid_bounds() {
        assert_eq!(encode_rate_limit_value(0).unwrap(), 0);
        assert_eq!(decode_rate_limit_value(0).unwrap(), 0);
        assert_eq!(encode_rate_limit_value(i64::MAX as u64).unwrap(), i64::MAX);
        assert_eq!(decode_rate_limit_value(i64::MAX).unwrap(), i64::MAX as u64);
    }
}
