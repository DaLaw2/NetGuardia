use macros::traceable;

traceable! {
    AuthError {
        #[no_source]
        #[error("Invalid credentials")]
        InvalidCredentials => tracing::Level::WARN,

        #[no_source]
        #[error("Token expired")]
        TokenExpired => tracing::Level::WARN,

        #[no_source]
        #[error("Invalid token")]
        InvalidToken => tracing::Level::WARN,

        #[no_source]
        #[error("Insufficient permissions")]
        InsufficientPermissions => tracing::Level::WARN,

        #[no_source]
        #[error("Missing authorization header")]
        MissingAuthHeader => tracing::Level::WARN,
    }
}
