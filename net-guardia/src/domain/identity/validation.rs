pub fn validate_username(username: &str) -> Result<(), &'static str> {
    if username.is_empty() || username.len() > 32 {
        return Err("Username must be 1-32 characters");
    }
    if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("Username must contain only alphanumeric characters and underscores");
    }
    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), &'static str> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters");
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
        assert!(validate_password("12345678").is_ok());
        assert!(validate_password("a very long password").is_ok());
    }

    #[test]
    fn too_short_password() {
        assert!(validate_password("").is_err());
        assert!(validate_password("1234567").is_err());
    }
}
