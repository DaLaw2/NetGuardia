use macros::traceable;

traceable! {
    CodecError {
        #[error("Failed to serialize data")]
        SerializeFailed => tracing::Level::ERROR,

        #[error("Failed to deserialize data")]
        DeserializeFailed => tracing::Level::ERROR,
    }
}
