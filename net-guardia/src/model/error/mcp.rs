use macros::traceable;

traceable! {
    McpError {
        #[no_source]
        #[error("MCP tool not found: {tool_name}")]
        ToolNotFound { tool_name: String } => tracing::Level::WARN,

        #[no_source]
        #[error("MCP parameter validation failed: {reason}")]
        InvalidParams { reason: String } => tracing::Level::WARN,

        #[no_source]
        #[error("MCP permission denied: key has '{key_level}' but tool requires '{required_level}'")]
        PermissionDenied { key_level: String, required_level: String } => tracing::Level::WARN,

        #[no_source]
        #[error("MCP API key invalid or revoked")]
        InvalidApiKey => tracing::Level::WARN,

        #[no_source]
        #[error("MCP proxy error: {reason}")]
        ProxyError { reason: String } => tracing::Level::ERROR,
    }
}
