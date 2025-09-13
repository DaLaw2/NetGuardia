use macros::traceable;

traceable! {
    HttpError {
        #[error("Bind port error")]
        BindPortError => tracing::Level::ERROR,

        #[error("Http Server panic")]
        ServerPanic => tracing::Level::ERROR,

        #[error("WebSocket error")]
        WebSocketError => tracing::Level::ERROR,
    }
}
