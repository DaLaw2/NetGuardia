use crate::domain::common::error::Error;

pub trait TokenMinter: Send + Sync {
    fn create_token(&self, user_id: i64, username: &str, role: &str, permissions: Vec<String>)
    -> Result<String, Error>;
}
