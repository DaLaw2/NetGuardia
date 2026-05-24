use macros::{fallible, traceable};

fallible! {
    LoginError {
        #[no_source]
        #[error("Account locked, retry after {retry_after_secs}s")]
        Locked { retry_after_secs: u64 },

        #[no_source]
        #[error("Invalid credentials")]
        InvalidCredentials,

        #[no_source]
        #[error("Internal authentication error")]
        InternalError,
    }
}

fallible! {
    RegisterError {
        #[no_source]
        #[error("Validation failed: {reason}")]
        Validation { reason: String },

        #[no_source]
        #[error("Invalid role")]
        InvalidRole,

        #[no_source]
        #[error("Insufficient permissions")]
        Forbidden,

        #[no_source]
        #[error("Password hashing failed")]
        HashFailed,

        #[error("User already exists: {err}")]
        Conflict,

        #[error("Internal error: {err}")]
        Internal,
    }
}

fallible! {
    UserError {
        #[no_source]
        #[error("Validation failed: {reason}")]
        Validation { reason: String },

        #[no_source]
        #[error("Current password is incorrect")]
        Unauthorized,

        #[no_source]
        #[error("Forbidden: {reason}")]
        Forbidden { reason: String },

        #[no_source]
        #[error("Not found: {entity}")]
        NotFound { entity: String },

        #[no_source]
        #[error("Password hashing failed")]
        HashFailed,

        #[error("Conflict: {err}")]
        Conflict,

        #[error("Internal error: {err}")]
        Internal,
    }
}

fallible! {
    GroupError {
        #[no_source]
        #[error("Validation failed: {reason}")]
        Validation { reason: String },

        #[no_source]
        #[error("Forbidden: {reason}")]
        Forbidden { reason: String },

        #[no_source]
        #[error("Not found: {entity}")]
        NotFound { entity: String },

        #[error("Conflict: {err}")]
        Conflict,

        #[error("Internal error: {err}")]
        Internal,
    }
}

traceable! {
    AuthError {
        #[no_source]
        #[error("Invalid credentials")]
        InvalidCredentials => tracing::Level::WARN,

        #[error("Failed to record login failure: {err}")]
        LoginFailureTrackingError => tracing::Level::ERROR,

        #[error("Failed to check login lockout state: {err}")]
        LoginLockoutLookupFailed => tracing::Level::ERROR,

        #[error("Failed to clear login failures: {err}")]
        LoginClearError => tracing::Level::ERROR,

        #[error("Failed to assign user to group: {err}")]
        GroupAssignmentFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("Default user group '{group_name}' is missing")]
        DefaultGroupMissing { group_name: String } => tracing::Level::ERROR,

        #[error("Failed to look up user permissions: {err}")]
        PermissionLookupFailed => tracing::Level::ERROR,

        #[error("Failed to look up user groups: {err}")]
        GroupLookupFailed => tracing::Level::ERROR,
    }
}
