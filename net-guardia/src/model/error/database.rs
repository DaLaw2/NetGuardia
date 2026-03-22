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

impl From<rusqlite::Error> for DatabaseError {
    fn from(e: rusqlite::Error) -> Self {
        DatabaseError::QueryFailed { reason: e.to_string() }
    }
}

impl From<rusqlite::Error> for super::Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(DatabaseError::from(e))
    }
}
