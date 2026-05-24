use macros::traceable;

traceable! {
    DatabaseError {
        #[error("Database error: {err}")]
        QueryFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("User '{username}' already exists")]
        UserAlreadyExists { username: String } => tracing::Level::WARN,

        #[no_source]
        #[error("User id {id} was not found")]
        UserNotFound { id: i64 } => tracing::Level::WARN,

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

        #[no_source]
        #[error("Audit log checkpoint id {id} was not found")]
        AuditCheckpointMissing { id: i64 } => tracing::Level::ERROR,

        #[error("Invalid JSON in database column '{column}' for row {id}: {err}")]
        PersistedJsonInvalid { id: i64, column: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Invalid value '{value}' in database column '{table}.{column}'")]
        PersistedValueInvalid { table: String, column: String, value: String } => tracing::Level::ERROR,
    }
}
