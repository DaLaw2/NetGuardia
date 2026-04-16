use macros::traceable;

traceable! {
    DatabaseError {
        #[error("Database error: {err}")]
        QueryFailed => tracing::Level::ERROR,

        #[error("Database connection failed")]
        ConnectionFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("User '{username}' already exists")]
        UserAlreadyExists { username: String } => tracing::Level::WARN,

        #[no_source]
        #[error("User group '{name}' already exists")]
        GroupAlreadyExists { name: String } => tracing::Level::WARN,

        #[no_source]
        #[error("Database encryption key is incorrect or database is corrupted")]
        EncryptionKeyInvalid => tracing::Level::ERROR,

        #[no_source]
        #[error("Cannot read database with provided key — wrong key or not encrypted")]
        DatabaseNotReadable => tracing::Level::ERROR,

        #[no_source]
        #[error("Cannot read source database — may already be encrypted")]
        SourceDatabaseNotReadable => tracing::Level::ERROR,

        #[no_source]
        #[error("Audit log prev_hash mismatch at id {id}: expected {expected}, found {found}")]
        AuditPrevHashMismatch { id: i64, expected: String, found: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Audit log row_hash mismatch at id {id}: computed {computed}, stored {stored}")]
        AuditRowHashMismatch { id: i64, computed: String, stored: String } => tracing::Level::ERROR,
    }
}

impl From<rusqlite::Error> for DatabaseError {
    fn from(e: rusqlite::Error) -> Self {
        DatabaseError::QueryFailed(e)
    }
}

impl From<rusqlite::Error> for super::Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(DatabaseError::from(e))
    }
}
