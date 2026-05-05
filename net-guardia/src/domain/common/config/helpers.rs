use std::str::FromStr;

use crate::domain::common::error::Error;
use crate::interface::config_repo::ConfigRepo;

pub(in crate::domain) async fn override_parsed<T: FromStr>(
    target: &mut T,
    repo: &dyn ConfigRepo,
    key: &str,
) -> Result<(), Error> {
    if let Some(v) = repo.get_config_value(key).await?
        && let Ok(parsed) = v.parse()
    {
        *target = parsed;
    }
    Ok(())
}

pub(in crate::domain) async fn override_bool(target: &mut bool, repo: &dyn ConfigRepo, key: &str) -> Result<(), Error> {
    if let Some(v) = repo.get_config_value(key).await? {
        *target = v == "true" || v == "1";
    }
    Ok(())
}

pub(in crate::domain) async fn override_string_nonempty(
    target: &mut String,
    repo: &dyn ConfigRepo,
    key: &str,
) -> Result<(), Error> {
    if let Some(v) = repo.get_config_value(key).await?
        && !v.is_empty()
    {
        *target = v;
    }
    Ok(())
}

pub(in crate::domain) async fn override_csv(
    target: &mut Vec<String>,
    repo: &dyn ConfigRepo,
    key: &str,
) -> Result<(), Error> {
    if let Some(v) = repo.get_config_value(key).await? {
        *target = if v.is_empty() {
            Vec::new()
        } else {
            v.split(',').map(|s| s.trim().to_string()).collect()
        };
    }
    Ok(())
}

pub(in crate::domain) async fn seed_key(repo: &dyn ConfigRepo, key: &str, value: &str) -> Result<(), Error> {
    if repo.get_config_value(key).await?.is_none() {
        repo.set_config_value(key, value).await?;
    }
    Ok(())
}
