use std::sync::Arc;

use crate::common::error::Error;
use crate::common::error::system::SystemError;
use crate::domain::identity::auth::DEFAULT_ADMIN_USERNAME;
use crate::domain::identity::validation::validate_password;
use crate::interface::identity::password_hasher::PasswordHasher;
use crate::interface::system::secret_store::SecretStorePort;
use crate::interface::system::setup::SetupRepo;

#[derive(Debug, Clone)]
pub struct CompleteSetupInput {
    pub ingress_interface: String,
    pub egress_interface: String,
    pub admin_password: String,
    pub http_port: Option<u16>,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub smtp_recipient: Option<String>,
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
}

pub struct SetupService {
    repo: Arc<dyn SetupRepo>,
    secrets: Arc<dyn SecretStorePort>,
    password_hasher: Arc<dyn PasswordHasher>,
}

impl SetupService {
    pub fn new(
        repo: Arc<dyn SetupRepo>,
        secrets: Arc<dyn SecretStorePort>,
        password_hasher: Arc<dyn PasswordHasher>,
    ) -> Self {
        Self {
            repo,
            secrets,
            password_hasher,
        }
    }

    pub async fn complete_setup(&self, input: CompleteSetupInput) -> Result<(), Error> {
        validate_setup_input(&input)?;
        let password_hash = self.password_hasher.hash_password(&input.admin_password)?;
        let state = prepare_setup_state(&input, self.secrets.as_ref())?;

        self.repo
            .complete_setup_atomically(
                state.config_values,
                state.secret_values,
                state.notification_configs,
                DEFAULT_ADMIN_USERNAME,
                &password_hash,
            )
            .await
    }
}

struct SetupState {
    config_values: Vec<(String, String)>,
    secret_values: Vec<(String, String)>,
    notification_configs: Vec<(String, String)>,
}

fn validate_setup_input(input: &CompleteSetupInput) -> Result<(), Error> {
    for iface in [&input.ingress_interface, &input.egress_interface] {
        if !is_valid_interface_name(iface) {
            Err(SystemError::InvalidSetupInput(format!(
                "Invalid interface name '{}': only alphanumeric, dots, underscores, hyphens allowed (max 16 chars, not dot names)",
                iface
            )))?;
        }
    }

    if input.ingress_interface == input.egress_interface {
        Err(SystemError::InvalidSetupInput(
            "Ingress and egress interfaces must be different".to_string(),
        ))?;
    }

    if let Err(message) = validate_password(&input.admin_password) {
        Err(SystemError::InvalidSetupInput(message.to_string()))?;
    }

    if input.http_port == Some(0) {
        Err(SystemError::InvalidSetupInput(
            "HTTP port must be greater than 0".to_string(),
        ))?;
    }

    if input.smtp_port == Some(0) {
        Err(SystemError::InvalidSetupInput(
            "SMTP port must be greater than 0".to_string(),
        ))?;
    }

    let telegram_token_present = has_text(&input.telegram_bot_token);
    let telegram_chat_present = has_text(&input.telegram_chat_id);
    if telegram_token_present != telegram_chat_present {
        Err(SystemError::InvalidSetupInput(
            "Telegram setup requires both bot token and chat ID".to_string(),
        ))?;
    }

    let required_smtp_fields = [
        ("smtp_host", &input.smtp_host),
        ("smtp_username", &input.smtp_username),
        ("smtp_password", &input.smtp_password),
        ("smtp_recipient", &input.smtp_recipient),
    ];
    let smtp_requested = input.smtp_port.is_some() || required_smtp_fields.iter().any(|(_, value)| has_text(value));
    if smtp_requested {
        for (field, value) in required_smtp_fields {
            if !has_text(value) {
                Err(SystemError::InvalidSetupInput(format!("SMTP setup requires {field}")))?;
            }
        }
    }

    Ok(())
}

pub fn is_valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 16
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn prepare_setup_state(input: &CompleteSetupInput, secrets: &dyn SecretStorePort) -> Result<SetupState, Error> {
    let mut config_values = vec![
        ("ingress_interface".to_string(), input.ingress_interface.clone()),
        ("egress_interface".to_string(), input.egress_interface.clone()),
    ];
    let mut secret_values = Vec::new();
    let mut notification_configs = Vec::new();

    if let Some(port) = input.http_port {
        config_values.push(("http_port".to_string(), port.to_string()));
    }

    if let Some(host) = trimmed_text_value(&input.smtp_host) {
        config_values.push(("smtp_host".to_string(), host));
    }
    if let Some(port) = input.smtp_port {
        config_values.push(("smtp_port".to_string(), port.to_string()));
    }
    if let Some(user) = trimmed_text_value(&input.smtp_username) {
        config_values.push(("smtp_username".to_string(), user));
    }
    if let Some(pass) = input.smtp_password.as_deref().filter(|value| !value.trim().is_empty()) {
        secret_values.push(("smtp_password".to_string(), secrets.encrypt_envelope(pass)?));
        config_values.push(("smtp_password".to_string(), "__encrypted__".to_string()));
    }
    if let Some(recipient) = trimmed_text_value(&input.smtp_recipient) {
        config_values.push(("smtp_recipient".to_string(), recipient));
    }

    if let (Some(token), Some(chat_id)) = (
        trimmed_text_value(&input.telegram_bot_token),
        trimmed_text_value(&input.telegram_chat_id),
    ) {
        secret_values.push(("telegram_bot_token".to_string(), secrets.encrypt_envelope(&token)?));
        let config_json = serde_json::json!({
            "bot_token": "__encrypted__",
            "chat_id": chat_id,
        })
        .to_string();
        notification_configs.push(("telegram".to_string(), config_json));
    }

    Ok(SetupState {
        config_values,
        secret_values,
        notification_configs,
    })
}

fn has_text(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|value| !value.trim().is_empty())
}

fn trimmed_text_value(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use parking_lot::Mutex;

    use super::*;

    #[derive(Default)]
    struct MockSetupRepo {
        commits: Mutex<Vec<Commit>>,
    }

    struct Commit {
        config_values: Vec<(String, String)>,
        secret_values: Vec<(String, String)>,
        notification_configs: Vec<(String, String)>,
        admin_username: String,
        password_hash: String,
    }

    #[async_trait]
    impl SetupRepo for MockSetupRepo {
        async fn complete_setup_atomically(
            &self,
            config_values: Vec<(String, String)>,
            secrets: Vec<(String, String)>,
            notification_configs: Vec<(String, String)>,
            admin_username: &str,
            password_hash: &str,
        ) -> Result<(), Error> {
            self.commits.lock().push(Commit {
                config_values,
                secret_values: secrets,
                notification_configs,
                admin_username: admin_username.to_string(),
                password_hash: password_hash.to_string(),
            });
            Ok(())
        }
    }

    struct MockSecretStore;

    #[async_trait]
    impl SecretStorePort for MockSecretStore {
        async fn get_secret(&self, _key: &str) -> Result<Option<String>, Error> {
            Ok(None)
        }

        async fn set_secret(&self, _key: &str, _plaintext: &str) -> Result<(), Error> {
            Ok(())
        }

        fn encrypt_envelope(&self, plaintext: &str) -> Result<String, Error> {
            Ok(format!("encrypted:{plaintext}"))
        }
    }

    struct MockPasswordHasher;

    impl PasswordHasher for MockPasswordHasher {
        fn hash_password(&self, password: &str) -> Result<String, Error> {
            Ok(format!("hashed:{password}"))
        }

        fn verify_password(&self, _password: &str, _hash: &str) -> Result<bool, Error> {
            Ok(false)
        }
    }

    fn valid_input() -> CompleteSetupInput {
        CompleteSetupInput {
            ingress_interface: "eth0".to_string(),
            egress_interface: "eth1".to_string(),
            admin_password: "Password1!".to_string(),
            http_port: Some(8443),
            smtp_host: Some("smtp.example.test".to_string()),
            smtp_port: Some(587),
            smtp_username: Some("mailer".to_string()),
            smtp_password: Some("smtp-secret".to_string()),
            smtp_recipient: Some("sec@example.test".to_string()),
            telegram_bot_token: Some("token".to_string()),
            telegram_chat_id: Some("chat".to_string()),
        }
    }

    #[tokio::test]
    async fn complete_setup_prepares_atomic_commit_state() {
        let repo = Arc::new(MockSetupRepo::default());
        let service = SetupService::new(repo.clone(), Arc::new(MockSecretStore), Arc::new(MockPasswordHasher));

        service.complete_setup(valid_input()).await.expect("complete setup");

        let commits = repo.commits.lock();
        assert_eq!(commits.len(), 1);
        let commit = &commits[0];
        assert_eq!(commit.admin_username, DEFAULT_ADMIN_USERNAME);
        assert_eq!(commit.password_hash, "hashed:Password1!");
        assert!(
            commit
                .config_values
                .contains(&("ingress_interface".to_string(), "eth0".to_string()))
        );
        assert!(
            commit
                .config_values
                .contains(&("smtp_password".to_string(), "__encrypted__".to_string()))
        );
        assert!(
            commit
                .secret_values
                .contains(&("smtp_password".to_string(), "encrypted:smtp-secret".to_string()))
        );
        assert!(
            commit
                .secret_values
                .contains(&("telegram_bot_token".to_string(), "encrypted:token".to_string()))
        );
        assert_eq!(commit.notification_configs.len(), 1);
    }

    #[tokio::test]
    async fn complete_setup_trims_text_config_values_before_commit() {
        let repo = Arc::new(MockSetupRepo::default());
        let service = SetupService::new(repo.clone(), Arc::new(MockSecretStore), Arc::new(MockPasswordHasher));
        let mut input = valid_input();
        input.smtp_host = Some(" smtp.example.test ".to_string());
        input.smtp_username = Some(" mailer ".to_string());
        input.smtp_password = Some(" smtp-secret ".to_string());
        input.smtp_recipient = Some(" sec@example.test ".to_string());
        input.telegram_bot_token = Some(" token ".to_string());
        input.telegram_chat_id = Some(" chat ".to_string());

        service.complete_setup(input).await.expect("complete setup");

        let commits = repo.commits.lock();
        let commit = &commits[0];
        assert!(
            commit
                .config_values
                .contains(&("smtp_host".to_string(), "smtp.example.test".to_string()))
        );
        assert!(
            commit
                .config_values
                .contains(&("smtp_username".to_string(), "mailer".to_string()))
        );
        assert!(
            commit
                .config_values
                .contains(&("smtp_recipient".to_string(), "sec@example.test".to_string()))
        );
        assert!(
            commit
                .secret_values
                .contains(&("smtp_password".to_string(), "encrypted: smtp-secret ".to_string()))
        );
        assert!(
            commit
                .secret_values
                .contains(&("telegram_bot_token".to_string(), "encrypted:token".to_string()))
        );
        let telegram_config: serde_json::Value =
            serde_json::from_str(&commit.notification_configs[0].1).expect("telegram config json");
        assert_eq!(telegram_config.get("chat_id").and_then(|v| v.as_str()), Some("chat"));
    }

    #[tokio::test]
    async fn complete_setup_rejects_invalid_input_before_commit() {
        let repo = Arc::new(MockSetupRepo::default());
        let service = SetupService::new(repo.clone(), Arc::new(MockSecretStore), Arc::new(MockPasswordHasher));
        let mut input = valid_input();
        input.egress_interface = input.ingress_interface.clone();

        let result = service.complete_setup(input).await;

        assert!(result.is_err());
        assert!(repo.commits.lock().is_empty());
    }

    #[tokio::test]
    async fn complete_setup_rejects_partial_telegram_before_commit() {
        let repo = Arc::new(MockSetupRepo::default());
        let service = SetupService::new(repo.clone(), Arc::new(MockSecretStore), Arc::new(MockPasswordHasher));
        let mut input = valid_input();
        input.telegram_chat_id = None;

        let result = service.complete_setup(input).await;

        assert!(result.is_err());
        assert!(repo.commits.lock().is_empty());
    }

    #[tokio::test]
    async fn complete_setup_rejects_partial_smtp_before_commit() {
        let repo = Arc::new(MockSetupRepo::default());
        let service = SetupService::new(repo.clone(), Arc::new(MockSecretStore), Arc::new(MockPasswordHasher));
        let mut input = valid_input();
        input.smtp_password = Some("   ".to_string());

        let result = service.complete_setup(input).await;

        assert!(result.is_err());
        assert!(repo.commits.lock().is_empty());
    }

    fn set_http_port_zero(input: &mut CompleteSetupInput) {
        input.http_port = Some(0);
    }

    fn set_smtp_port_zero(input: &mut CompleteSetupInput) {
        input.smtp_port = Some(0);
    }

    #[tokio::test]
    async fn complete_setup_rejects_zero_ports_before_commit() {
        for mutate in [set_http_port_zero as fn(&mut CompleteSetupInput), set_smtp_port_zero] {
            let repo = Arc::new(MockSetupRepo::default());
            let service = SetupService::new(repo.clone(), Arc::new(MockSecretStore), Arc::new(MockPasswordHasher));
            let mut input = valid_input();
            mutate(&mut input);

            let result = service.complete_setup(input).await;

            assert!(result.is_err());
            assert!(repo.commits.lock().is_empty());
        }
    }
}
