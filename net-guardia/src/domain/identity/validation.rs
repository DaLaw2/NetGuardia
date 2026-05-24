pub fn validate_username(username: &str) -> Result<(), &'static str> {
    if username.is_empty() || username.len() > 32 {
        return Err("Username must be 1-32 characters");
    }
    if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("Username must contain only alphanumeric characters and underscores");
    }
    Ok(())
}

pub fn validate_api_key_name(name: &str) -> Result<(), &'static str> {
    let len = name.chars().count();
    if len == 0 || len > 64 {
        return Err("API key name must be 1-64 characters");
    }
    if name.chars().any(char::is_control) {
        return Err("API key name must not contain control characters");
    }
    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), &'static str> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters");
    }
    let has_letter = password.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());
    if !has_letter || !has_digit || !has_symbol {
        return Err("Password must contain at least one letter, one digit, and one symbol");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_usernames() {
        assert!(validate_username("admin").is_ok());
        assert!(validate_username("user_123").is_ok());
        assert!(validate_username("a").is_ok());
    }

    #[test]
    fn valid_api_key_names() {
        assert!(validate_api_key_name("automation").is_ok());
        assert!(validate_api_key_name("CI deploy key").is_ok());
    }

    #[test]
    fn api_key_name_must_not_be_empty() {
        assert!(validate_api_key_name("").is_err());
    }

    #[test]
    fn api_key_name_has_length_cap() {
        let long = "a".repeat(65);
        assert!(validate_api_key_name(&long).is_err());
    }

    #[test]
    fn api_key_name_must_not_contain_control_characters() {
        assert!(validate_api_key_name("prod\nkey").is_err());
        assert!(validate_api_key_name("prod\tkey").is_err());
        assert!(validate_api_key_name("prod key").is_ok());
    }

    #[test]
    fn empty_username() {
        assert!(validate_username("").is_err());
    }

    #[test]
    fn too_long_username() {
        let long = "a".repeat(33);
        assert!(validate_username(&long).is_err());
    }

    #[test]
    fn special_chars_blocked() {
        assert!(validate_username("admin@host").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("user-name").is_err());
    }

    #[test]
    fn valid_passwords() {
        assert!(validate_password("Password1!").is_ok());
        assert!(validate_password("a very long password1!").is_ok());
    }

    #[test]
    fn too_short_password() {
        assert!(validate_password("").is_err());
        assert!(validate_password("Abc123!").is_err());
    }

    #[test]
    fn weak_passwords_are_rejected() {
        assert!(validate_password("12345678").is_err());
        assert!(validate_password("password").is_err());
        assert!(validate_password("Password1").is_err());
    }
}
