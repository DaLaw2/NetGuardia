use macros::traceable;

traceable! {
    DatabaseError {
        #[no_source]
        #[error("Database error: {reason}")]
        QueryFailed { reason: String } => tracing::Level::ERROR,

        #[error("Database connection failed")]
        ConnectionFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("User '{username}' already exists")]
        UserAlreadyExists { username: String } => tracing::Level::WARN,
    }
}
