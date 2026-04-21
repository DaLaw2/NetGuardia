use crate::model::error::Error;

pub trait SettingRepo {
    fn get_setting(&self, key: &str) -> Result<Option<String>, Error>;
    fn set_setting(&self, key: &str, value: &str) -> Result<(), Error>;
    fn get_app_secret(&self, key: &str) -> Result<Option<String>, Error>;
    fn set_app_secret(&self, key: &str, plaintext: &str) -> Result<(), Error>;
    fn get_notification_config(&self, channel: &str) -> Result<Option<String>, Error>;
    fn set_notification_config(&self, channel: &str, config_json: &str) -> Result<(), Error>;
    fn transaction(&self, f: &mut dyn FnMut(&dyn SettingRepo) -> Result<(), Error>) -> Result<(), Error>;
}
