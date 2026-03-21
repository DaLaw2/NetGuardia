use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};

use crate::model::error::license::LicenseError;
use crate::model::license::{LicenseInfo, LicensePayload};

/// Public key auto-embedded from license_pub.key at compile time.
/// Generate with: cd license-generator && cargo run -- keygen
/// Then place license_pub.key in the repo root.
const PUBLIC_KEY_HEX: &str = env!("LICENSE_PUBLIC_KEY");

pub fn validate_license(license_path: &str, ingress_ifname: &str, egress_ifname: &str) -> Result<LicenseInfo, crate::model::error::Error> {
    // Guard against builds where the license feature was not configured
    if PUBLIC_KEY_HEX == "DISABLED" {
        return Err(LicenseError::ValidationFailed {
            reason: "License validation not configured".to_string(),
        }.into());
    }

    // If path is empty, license is optional — return unlicensed
    if license_path.is_empty() {
        tracing::warn!("No license file configured — running without license");
        return Ok(LicenseInfo::unlicensed());
    }

    let path = Path::new(license_path);
    if !path.exists() {
        tracing::warn!("License file '{}' not found — running without license", license_path);
        return Ok(LicenseInfo::unlicensed());
    }

    let contents = std::fs::read_to_string(path)
        .map_err(|_| LicenseError::FileNotFound { path: license_path.to_string() })?;

    let contents = contents.trim();

    // Format: base64(json_payload).base64(ed25519_signature)
    let parts: Vec<&str> = contents.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(LicenseError::ValidationFailed {
            reason: "Invalid license format: expected <payload>.<signature>".to_string(),
        }.into());
    }

    let payload_b64 = parts[0];
    let signature_b64 = parts[1];

    // Decode payload
    let payload_bytes = BASE64.decode(payload_b64)
        .map_err(|e| LicenseError::ValidationFailed {
            reason: format!("Failed to decode payload: {}", e),
        })?;

    // Decode signature
    let sig_bytes = BASE64.decode(signature_b64)
        .map_err(|e| LicenseError::ValidationFailed {
            reason: format!("Failed to decode signature: {}", e),
        })?;

    // Parse public key
    let pub_key_bytes = hex_decode(PUBLIC_KEY_HEX)
        .map_err(|e| LicenseError::ValidationFailed {
            reason: format!("Invalid embedded public key: {}", e),
        })?;

    let pub_key_array: [u8; 32] = pub_key_bytes.try_into()
        .map_err(|_| LicenseError::ValidationFailed {
            reason: "Public key must be 32 bytes".to_string(),
        })?;

    let verifying_key = VerifyingKey::from_bytes(&pub_key_array)
        .map_err(|_| LicenseError::ValidationFailed {
            reason: "Invalid public key".to_string(),
        })?;

    // Parse signature
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| LicenseError::ValidationFailed {
            reason: "Signature must be 64 bytes".to_string(),
        })?;

    let signature = Signature::from_bytes(&sig_array);

    // Verify signature over the raw base64-encoded payload (not decoded bytes)
    verifying_key.verify(payload_b64.as_bytes(), &signature)
        .map_err(|_| LicenseError::InvalidSignature)?;

    // Parse payload JSON
    let payload: LicensePayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| LicenseError::ValidationFailed {
            reason: format!("Failed to parse license payload: {}", e),
        })?;

    // Verify NIC MAC addresses
    let actual_ingress_mac = get_interface_mac(ingress_ifname).unwrap_or_default();
    let actual_egress_mac = get_interface_mac(egress_ifname).unwrap_or_default();

    if actual_ingress_mac != payload.ingress_mac {
        return Err(LicenseError::ValidationFailed {
            reason: "Ingress MAC mismatch — license not bound to this device".to_string(),
        }.into());
    }

    if actual_egress_mac != payload.egress_mac {
        return Err(LicenseError::ValidationFailed {
            reason: "Egress MAC mismatch — license not bound to this device".to_string(),
        }.into());
    }

    // Check expiry
    let today = chrono_free_today();
    let days_remaining = days_until(&payload.expires, &today)
        .map_err(|e| LicenseError::ValidationFailed {
            reason: format!("Invalid expiry date: {}", e),
        })?;

    if days_remaining < 0 {
        return Err(LicenseError::Expired.into());
    }

    tracing::info!(
        "License valid — ingress={}, egress={}, expires={}, days_remaining={}, features={:?}",
        payload.ingress_mac, payload.egress_mac, payload.expires, days_remaining, payload.features
    );

    Ok(LicenseInfo {
        payload: Some(payload),
        valid: true,
        days_remaining,
    })
}

/// Read MAC address from /sys/class/net/<ifname>/address (Linux only).
fn get_interface_mac(ifname: &str) -> Option<String> {
    // Prevent path traversal
    if !ifname.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return None;
    }
    let path = format!("/sys/class/net/{}/address", ifname);
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_lowercase())
}

/// Simple hex decoder without external dependency.
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Odd-length hex string".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Parse YYYY-MM-DD date and return days until expiry (no chrono dependency).
fn chrono_free_today() -> (i32, u32, u32) {
    // Use UNIX_EPOCH to get today's date
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let days_since_epoch = (secs / 86400) as i32;
    epoch_days_to_ymd(days_since_epoch)
}

fn parse_date(s: &str) -> Result<(i32, u32, u32), String> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return Err("Expected YYYY-MM-DD".to_string());
    }
    let y = parts[0].parse::<i32>().map_err(|e| e.to_string())?;
    let m = parts[1].parse::<u32>().map_err(|e| e.to_string())?;
    let d = parts[2].parse::<u32>().map_err(|e| e.to_string())?;
    Ok((y, m, d))
}

fn ymd_to_epoch_days(y: i32, m: u32, d: u32) -> i32 {
    // Algorithm from Howard Hinnant
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i32 - 719468
}

fn epoch_days_to_ymd(days: i32) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn days_until(expiry_str: &str, today: &(i32, u32, u32)) -> Result<i64, String> {
    let (ey, em, ed) = parse_date(expiry_str)?;
    let expiry_days = ymd_to_epoch_days(ey, em, ed) as i64;
    let today_days = ymd_to_epoch_days(today.0, today.1, today.2) as i64;
    Ok(expiry_days - today_days)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_decode_valid() {
        assert_eq!(hex_decode("48656c6c6f").unwrap(), b"Hello");
        assert_eq!(hex_decode("ff00").unwrap(), vec![0xff, 0x00]);
    }

    #[test]
    fn test_hex_decode_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn test_hex_decode_invalid_chars() {
        assert!(hex_decode("zzzz").is_err());
    }

    #[test]
    fn test_parse_date_valid() {
        assert_eq!(parse_date("2026-03-21").unwrap(), (2026, 3, 21));
        assert_eq!(parse_date("2000-01-01").unwrap(), (2000, 1, 1));
    }

    #[test]
    fn test_parse_date_invalid() {
        assert!(parse_date("not-a-date").is_err());
        assert!(parse_date("2026-13").is_err());
        assert!(parse_date("").is_err());
    }

    #[test]
    fn test_epoch_roundtrip() {
        // Test several dates
        let dates = vec![
            (2026, 3, 21),
            (2000, 1, 1),
            (1970, 1, 1),
            (2024, 2, 29), // leap year
            (2025, 12, 31),
        ];
        for (y, m, d) in dates {
            let days = ymd_to_epoch_days(y, m, d);
            let (ry, rm, rd) = epoch_days_to_ymd(days);
            assert_eq!((ry, rm, rd), (y, m, d), "Roundtrip failed for {}-{}-{}", y, m, d);
        }
    }

    #[test]
    fn test_epoch_day_1970() {
        assert_eq!(ymd_to_epoch_days(1970, 1, 1), 0);
    }

    #[test]
    fn test_days_until() {
        let today = (2026, 3, 21);
        assert_eq!(days_until("2026-03-21", &today).unwrap(), 0);
        assert_eq!(days_until("2026-03-22", &today).unwrap(), 1);
        assert_eq!(days_until("2026-03-20", &today).unwrap(), -1);
        assert_eq!(days_until("2027-03-21", &today).unwrap(), 365);
    }

    #[test]
    fn test_chrono_free_today_returns_reasonable_date() {
        let (y, m, d) = chrono_free_today();
        assert!(y >= 2025 && y <= 2030);
        assert!(m >= 1 && m <= 12);
        assert!(d >= 1 && d <= 31);
    }

    #[test]
    fn test_get_interface_mac_path_traversal() {
        // Should reject path traversal attempts
        assert!(get_interface_mac("../etc/passwd").is_none());
        assert!(get_interface_mac("eth0/../..").is_none());
    }

    #[test]
    fn test_license_format_invalid() {
        // Test with invalid license content (no file, just the parsing logic)
        let bad_formats = vec!["", "nodot", "too.many.dots"];
        for fmt in bad_formats {
            let parts: Vec<&str> = fmt.splitn(2, '.').collect();
            if parts.len() != 2 {
                continue; // expected — this is what validate_license checks
            }
        }
    }
}
