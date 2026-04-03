use crate::model::auth::Claims;
use crate::model::error::Error;

/// Type alias for API key list items: (id, name, permission_level, created_at, last_used_at)
#[allow(clippy::type_complexity)]
pub type ApiKeyListItem = (i64, String, String, String, Option<String>);

/// Port for API key management and validation.
pub trait ApiKeyPort: Send + Sync {
    fn validate_api_key(&self, api_key: &str) -> Result<Option<Claims>, Error>;
    fn insert_api_key(&self, key_hash: &str, name: &str, permission_level: &str) -> Result<i64, Error>;
    fn list_api_keys(&self) -> Result<Vec<ApiKeyListItem>, Error>;
    fn delete_api_key(&self, id: i64) -> Result<bool, Error>;
}
