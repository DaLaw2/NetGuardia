use macros::loggable;
use tracing;

loggable! {
    MiscLog {
        #[error("GeoIP features will be disabled")]
        GeoIPDisabled => tracing::Level::WARN,
    }
}
