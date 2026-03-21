use macros::traceable;

traceable! {
    AuthError {
        #[error("Invalid credentials")]
        InvalidCredentials => tracing::Level::WARN,

        #[error("Token expired")]
        TokenExpired => tracing::Level::WARN,

        #[error("Invalid token")]
        InvalidToken => tracing::Level::WARN,

        #[error("Insufficient permissions")]
        InsufficientPermissions => tracing::Level::WARN,

        #[error("Missing authorization header")]
        MissingAuthHeader => tracing::Level::WARN,
    }
}
