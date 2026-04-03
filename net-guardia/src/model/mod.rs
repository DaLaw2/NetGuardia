// Bounded Context subdirectories
pub mod access_control;
pub mod config;
pub mod detection;
pub mod error;
pub mod event;
pub mod identity;
pub mod log;
pub mod monitoring;
pub mod report;
pub mod soar;
pub mod system;

// Backward-compatible re-exports (existing imports continue to work)
pub use access_control::ip_address;
pub use access_control::list_type;
pub use detection::ml_detection;
pub use identity::auth;
pub use monitoring::direction;
pub use monitoring::drop_event;
pub use monitoring::flow_stats;
pub use monitoring::user_packet;
pub use system::health;
