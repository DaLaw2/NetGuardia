//! Centralized constants for the NetGuardia application.
//!
//! Only **true constants** live here — values that are either part of a
//! stable wire/FS contract or derived from an external spec. Anything
//! runtime-tunable has moved into the corresponding `model/config/*.rs`
//! subsystem config (Q-10, 2026-04-22).

// ── ML Model Directory ─────────────────────────────────────────────
/// Directory name (relative to working directory) where promoted models land.
/// Stable filesystem contract shared with the model watcher and upload path.
pub const MODELS_DIR: &str = "models";
/// Filename the model watcher listens for as the "commit marker" of a new
/// model promotion. Paired with upload's atomic rename order.
pub const MANIFEST_FILENAME: &str = "manifest.yaml";
/// Hidden subdirectory inside `MODELS_DIR` used for in-progress uploads.
/// The watcher filters events inside this path so partial uploads don't
/// trigger reloads. Stable contract with the multipart upload handler.
pub const STAGING_SUBDIR: &str = ".staging";

// ── HTTP Server ────────────────────────────────────────────────────
/// Fallback port used when `http_port` is unset / unparseable. Matches
/// the `defaults()` of `HttpServerConfig` and the setup-wizard default.
pub const HTTP_FALLBACK_PORT: u16 = 8080;
