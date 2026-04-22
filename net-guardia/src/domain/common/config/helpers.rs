use std::str::FromStr;

use crate::domain::common::error::Error;
use crate::interface::port::setting::SettingRepo;

pub(in crate::domain) fn override_parsed<T: FromStr>(
    target: &mut T,
    repo: &dyn SettingRepo,
    key: &str,
) -> Result<(), Error> {
    if let Some(v) = repo.get_setting(key)?
        && let Ok(parsed) = v.parse()
    {
        *target = parsed;
    }
    Ok(())
}

pub(in crate::domain) fn override_bool(target: &mut bool, repo: &dyn SettingRepo, key: &str) -> Result<(), Error> {
    if let Some(v) = repo.get_setting(key)? {
        *target = v == "true" || v == "1";
    }
    Ok(())
}

pub(in crate::domain) fn override_string(target: &mut String, repo: &dyn SettingRepo, key: &str) -> Result<(), Error> {
    if let Some(v) = repo.get_setting(key)? {
        *target = v;
    }
    Ok(())
}

pub(in crate::domain) fn override_string_nonempty(
    target: &mut String,
    repo: &dyn SettingRepo,
    key: &str,
) -> Result<(), Error> {
    if let Some(v) = repo.get_setting(key)?
        && !v.is_empty()
    {
        *target = v;
    }
    Ok(())
}

pub(in crate::domain) fn override_csv(
    target: &mut Vec<String>,
    repo: &dyn SettingRepo,
    key: &str,
) -> Result<(), Error> {
    if let Some(v) = repo.get_setting(key)? {
        *target = if v.is_empty() {
            Vec::new()
        } else {
            v.split(',').map(|s| s.trim().to_string()).collect()
        };
    }
    Ok(())
}

pub(in crate::domain) fn seed_key(repo: &dyn SettingRepo, key: &str, value: &str) -> Result<(), Error> {
    if repo.get_setting(key)?.is_none() {
        repo.set_setting(key, value)?;
    }
    Ok(())
}
