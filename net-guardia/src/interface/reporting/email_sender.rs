use crate::common::error::Error;
use crate::domain::common::config::notification::SmtpConfig;
use crate::interface::system::secret_store::SecretStorePort;

pub trait EmailSender: Send + Sync {
    fn send(&self, to: &str, subject: &str, html_body: &str) -> Result<(), Error>;
}

#[async_trait::async_trait]
pub trait EmailSenderFactory: Send + Sync {
    async fn build_smtp_sender(
        &self,
        cfg: &SmtpConfig,
        secrets: Option<&dyn SecretStorePort>,
    ) -> Result<Option<Box<dyn EmailSender>>, Error>;
}
