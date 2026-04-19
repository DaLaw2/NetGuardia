//! Classifier for eBPF bring-up failures.
//!
//! Takes a raw error plus interface/stage context and produces an
//! `EbpfHealth::Unavailable { stage, category, reason }` suitable for the
//! frontend status display.
//!
//! Classification is best-effort: we inspect `std::io::ErrorKind` where we
//! have one, then fall back to substring matching on the rendered error
//! string. The produced `reason` always includes the interface name,
//! host kernel release, and the NIC driver where those are obtainable,
//! so the operator can diagnose directly from the UI without shelling in.

use std::fs;

use crate::model::error::Error;
use crate::model::system::health::{EbpfFailCategory, EbpfFailStage, EbpfHealth};

/// Read the running kernel release from `/proc/sys/kernel/osrelease`.
/// Returns the trimmed value, or `"unknown"` if the file cannot be read.
pub fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Look up the driver name bound to a network interface via
/// `/sys/class/net/<ifname>/device/driver`. Returns the basename of
/// the symlink target, or `"unknown"` if the interface has no driver
/// (e.g., virtual or renamed) or the path is not readable.
pub fn interface_driver(ifname: &str) -> String {
    let link = format!("/sys/class/net/{}/device/driver", ifname);
    match fs::read_link(&link) {
        Ok(target) => target
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        Err(_) => "unknown".to_string(),
    }
}

/// Build an `EbpfHealth::Unavailable` from an error and stage context.
///
/// `ifname` is optional because some stages (Load, LoggerInit, PipelineSetup)
/// fail before any interface is involved.
pub fn classify(stage: EbpfFailStage, err: &Error, ifname: Option<&str>) -> EbpfHealth {
    let raw = err.to_string();
    let category = categorize(&raw);
    let kernel = kernel_release();
    let driver = ifname.map(interface_driver);

    let mut reason = format!("stage={:?}: {}", stage, raw);
    reason.push_str(&format!(" (kernel {}", kernel));
    if let Some(iface) = ifname {
        reason.push_str(&format!(", interface {}", iface));
        if let Some(drv) = driver.as_deref() {
            reason.push_str(&format!(", driver {}", drv));
        }
    }
    reason.push(')');

    // For the igb-before-6.17 case, augment the reason with a targeted hint.
    if matches!(category, EbpfFailCategory::AfXdpUnsupported)
        && driver.as_deref() == Some("igb")
        && !kernel_meets_igb_af_xdp(&kernel)
    {
        reason.push_str(". The igb driver supports AF_XDP only on kernel 6.17 or newer.");
    }

    EbpfHealth::Unavailable {
        stage,
        category,
        reason,
    }
}

/// Heuristic categorization based on the rendered error string.
/// Kept intentionally shallow — aya does not currently expose structured
/// enums for all kernel errno paths, so substring matching is the realistic
/// fallback.
fn categorize(raw: &str) -> EbpfFailCategory {
    let lower = raw.to_lowercase();

    if lower.contains("permission denied") || lower.contains("operation not permitted") || lower.contains("eperm") {
        return EbpfFailCategory::Permission;
    }
    if lower.contains("no such device")
        || lower.contains("enodev")
        || lower.contains("no such file or directory")
            && (lower.contains("/sys/class/net") || lower.contains("interface"))
    {
        return EbpfFailCategory::InterfaceNotFound;
    }
    if lower.contains("operation not supported") || lower.contains("eopnotsupp") || lower.contains("enotsup") {
        // The same errno covers both "driver does not support XDP" and
        // "driver does not support AF_XDP". Disambiguate by XDP vs XSK/AF_XDP
        // mention in the message when possible.
        if lower.contains("xsk") || lower.contains("af_xdp") || lower.contains("afxdp") || lower.contains("bind") {
            return EbpfFailCategory::AfXdpUnsupported;
        }
        return EbpfFailCategory::XdpUnsupported;
    }
    if lower.contains("cannot allocate memory") || lower.contains("enomem") || lower.contains("rlimit") {
        return EbpfFailCategory::MemlockExhausted;
    }
    if lower.contains("invalid argument")
        && (lower.contains("verifier") || lower.contains("bpf_prog_load") || lower.contains("program load"))
    {
        return EbpfFailCategory::VerifierRejected;
    }
    if lower.contains("no such file")
        && (lower.contains("net-guardia-ingress") || lower.contains("net-guardia-egress") || lower.contains(".o"))
    {
        return EbpfFailCategory::ObjectNotFound;
    }

    EbpfFailCategory::Unknown
}

/// Parse a kernel release string like "6.17.4-generic" and return true
/// if it is >= 6.17. We only care about the first two numeric components.
fn kernel_meets_igb_af_xdp(release: &str) -> bool {
    // Pull leading "MAJOR.MINOR" out of strings like "6.12.0-124.45.1.el10_1.x86_64".
    let mut parts = release.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty());
    let Some(major_str) = parts.next() else {
        return false;
    };
    let Some(minor_str) = parts.next() else {
        return false;
    };
    let Ok(major): Result<u32, _> = major_str.parse() else {
        return false;
    };
    let Ok(minor): Result<u32, _> = minor_str.parse() else {
        return false;
    };
    major > 6 || (major == 6 && minor >= 17)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_version_matrix() {
        assert!(kernel_meets_igb_af_xdp("6.17.0-generic"));
        assert!(kernel_meets_igb_af_xdp("6.18.1"));
        assert!(kernel_meets_igb_af_xdp("7.0.0"));
        assert!(!kernel_meets_igb_af_xdp("6.16.9-generic"));
        assert!(!kernel_meets_igb_af_xdp("6.12.0-124.45.1.el10_1.x86_64"));
        assert!(!kernel_meets_igb_af_xdp("5.15.0"));
        assert!(!kernel_meets_igb_af_xdp("nonsense"));
    }

    #[test]
    fn categorizes_permission_errors() {
        assert!(matches!(
            categorize("Permission denied (os error 13)"),
            EbpfFailCategory::Permission
        ));
        assert!(matches!(
            categorize("Operation not permitted"),
            EbpfFailCategory::Permission
        ));
    }

    #[test]
    fn categorizes_af_xdp_vs_xdp() {
        assert!(matches!(
            categorize("bind failed: Operation not supported (os error 95)"),
            EbpfFailCategory::AfXdpUnsupported
        ));
        assert!(matches!(
            categorize("xdp attach: Operation not supported"),
            EbpfFailCategory::XdpUnsupported
        ));
    }
}
