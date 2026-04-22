//! Canonical attack-type dictionary and cross-source translator.
//!
//! Fusion v1 requires that Suricata / ML / CV (Beaconing) / Graph (Correlation)
//! use a shared vocabulary — otherwise the orchestrator's dedup key
//! `(source_ip, attack_type)` never collides across sources, and the
//! cross-source "sources agreed" fusion signal is impossible.
//!
//! The 13 canonical types below are the v1 seed set. Each source ships a
//! translation table from its own raw labels (Suricata classtype, ML class
//! name, Beaconing tag, Correlation sub-type) into the canonical vocabulary.
//! Unknown labels land in `Unknown` — a valid dedup bucket that still
//! participates in fusion.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::domain::common::event::DetectionSource;

/// The v1 seed dictionary — 13 canonical attack types every detection source
/// maps into. New types may be added without breaking change; renaming or
/// removing one IS a breaking change (dedup keys drift).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalAttackType {
    BruteForce,
    PortScan,
    C2Beacon,
    DnsTunnel,
    SqlInjection,
    Xss,
    Exploit,
    LateralMovement,
    Reconnaissance,
    Cryptomining,
    DosDdos,
    BotActivity,
    /// Fallback bucket. Still a valid dedup key — two sources firing
    /// `Unknown` on the same src_ip within the fusion window DO fuse.
    Unknown,
}

impl CanonicalAttackType {
    /// Stable wire-format string. Must match `DedupKey.attack_type` exactly
    /// across releases — renaming breaks dedup on in-flight alerts.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BruteForce => "brute_force",
            Self::PortScan => "port_scan",
            Self::C2Beacon => "c2_beacon",
            Self::DnsTunnel => "dns_tunnel",
            Self::SqlInjection => "sql_injection",
            Self::Xss => "xss",
            Self::Exploit => "exploit",
            Self::LateralMovement => "lateral_movement",
            Self::Reconnaissance => "reconnaissance",
            Self::Cryptomining => "cryptomining",
            Self::DosDdos => "dos_ddos",
            Self::BotActivity => "bot_activity",
            Self::Unknown => "unknown",
        }
    }

    /// All 13 canonical values, in declaration order. Used by BYO-contract
    /// docs + CI consistency check.
    pub const ALL: &'static [Self] = &[
        Self::BruteForce,
        Self::PortScan,
        Self::C2Beacon,
        Self::DnsTunnel,
        Self::SqlInjection,
        Self::Xss,
        Self::Exploit,
        Self::LateralMovement,
        Self::Reconnaissance,
        Self::Cryptomining,
        Self::DosDdos,
        Self::BotActivity,
        Self::Unknown,
    ];
}

impl fmt::Display for CanonicalAttackType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reverse lookup: canonical wire string → enum. Returns `None` when the
/// input isn't one of the 13 seeds (caller typically treats this as an
/// upstream bug, not an `Unknown` bucket).
pub fn canonical_from_str(s: &str) -> Option<CanonicalAttackType> {
    CanonicalAttackType::ALL.iter().copied().find(|c| c.as_str() == s)
}

/// Translate a source-specific raw label into the canonical dictionary.
///
/// Never fails — unknown labels map to `CanonicalAttackType::Unknown` so
/// the event still lands in a valid dedup bucket. The `raw_label`
/// comparison is case-insensitive and trims whitespace; callers that pass
/// user-visible labels verbatim don't need to pre-normalize.
pub fn translate(source: DetectionSource, raw_label: &str) -> CanonicalAttackType {
    let normalized = raw_label.trim().to_ascii_lowercase();
    match source {
        DetectionSource::ML => translate_ml(&normalized),
        DetectionSource::Beaconing => translate_beaconing(&normalized),
        DetectionSource::Correlation => translate_correlation(&normalized),
        DetectionSource::Suricata => translate_suricata(&normalized),
    }
}

/// Map ML classifier class names into the canonical dictionary. Case-insensitive;
/// covers the baseline class vocabulary.
fn translate_ml(label: &str) -> CanonicalAttackType {
    match label {
        "brute force" | "brute_force" | "bruteforce" => CanonicalAttackType::BruteForce,
        // `port_scan` / `portscan` map to the specific `PortScan` bucket so
        // ML agreement with Correlation's `scan` / `port_scan` collapses onto
        // the same dedup key — the precondition for cross-source fusion.
        // Generic recon labels stay on `Reconnaissance`.
        "port_scan" | "portscan" => CanonicalAttackType::PortScan,
        "reconnaissance" | "recon" => CanonicalAttackType::Reconnaissance,
        "c2 communication" | "c2" | "c2_beacon" | "command_and_control" => CanonicalAttackType::C2Beacon,
        "dns tunneling" | "dns_tunnel" | "dns tunnel" => CanonicalAttackType::DnsTunnel,
        "sql injection" | "sql_injection" | "sqli" => CanonicalAttackType::SqlInjection,
        "xss" | "cross_site_scripting" => CanonicalAttackType::Xss,
        "web attack" | "web_attack" => CanonicalAttackType::Exploit,
        "exploitation" | "exploit" => CanonicalAttackType::Exploit,
        "dos/ddos" | "dos_ddos" | "ddos" | "dos" => CanonicalAttackType::DosDdos,
        "cryptomining" | "cryptocurrency_mining" | "mining" => CanonicalAttackType::Cryptomining,
        "bot" | "bot_activity" | "botnet" | "malware" => CanonicalAttackType::BotActivity,
        "lateral movement" | "lateral_movement" => CanonicalAttackType::LateralMovement,
        // "Normal" is not a threat — translators should not see it, but if they do,
        // fall through to Unknown rather than panicking.
        _ => CanonicalAttackType::Unknown,
    }
}

/// Beaconing (Layer 2 CV) only produces C2-style temporal beacons in v1.
/// Sub-tags (e.g. "c2_beacon", "heartbeat") all collapse here.
fn translate_beaconing(_label: &str) -> CanonicalAttackType {
    CanonicalAttackType::C2Beacon
}

/// Correlation (Layer 3 graph) splits across scan / lateral / botnet.
///
/// Note: Correlation's scan detector looks for fanout on the port dimension,
/// so every scan-flavored sub-tag maps to `PortScan`. ML's own `port_scan`
/// label uses the same bucket so the dedup orchestrator fuses agreement
/// from both sources onto one `(src_ip, port_scan)` key.
fn translate_correlation(label: &str) -> CanonicalAttackType {
    match label {
        "scan" | "port_scan" | "reconnaissance" => CanonicalAttackType::PortScan,
        "lateral" | "lateral_movement" => CanonicalAttackType::LateralMovement,
        "botnet" | "bot" | "bot_activity" => CanonicalAttackType::BotActivity,
        _ => CanonicalAttackType::Unknown,
    }
}

/// Map Suricata classtypes (`eve.json.alert.category`, not sid) into the
/// canonical dictionary. We match on classtype because sid numbering isn't
/// stable across rule packs; classtype is part of the rule DSL and stable
/// across ET Open / Talos releases.
fn translate_suricata(label: &str) -> CanonicalAttackType {
    // classtype strings come lowercase+trimmed from `translate`
    match label {
        // Port scan specifically — must match ML `port_scan` + Correlation
        // `scan` on the same canonical key so cross-source fusion fires.
        "network-scan" => CanonicalAttackType::PortScan,
        // Broader recon (non-port-scan host discovery, protocol probing)
        "attempted-recon" | "misc-activity" => CanonicalAttackType::Reconnaissance,
        // Exploits / admin compromise
        "attempted-admin" | "successful-admin" | "attempted-user" | "successful-user" | "shellcode-detect"
        | "attempted-exploit" => CanonicalAttackType::Exploit,
        // Web-application attacks
        "web-application-attack" => CanonicalAttackType::Exploit,
        "web-application-activity" => CanonicalAttackType::Exploit,
        // SQL injection is usually emitted as web-application-attack, but some
        // rule packs use "sql-injection" directly.
        "sql-injection" => CanonicalAttackType::SqlInjection,
        // XSS — same note as SQLi
        "xss" | "cross-site-scripting" => CanonicalAttackType::Xss,
        // DoS / DDoS
        "attempted-dos" | "successful-dos" | "denial-of-service" => CanonicalAttackType::DosDdos,
        // Trojan / malware / C2
        "trojan-activity" | "malware-cnc" | "command-and-control" => CanonicalAttackType::C2Beacon,
        // Credential attacks
        "suspicious-login" | "unsuccessful-user" | "brute-force" => CanonicalAttackType::BruteForce,
        // Policy / Crypto miner
        "coin-mining" | "policy-violation" => CanonicalAttackType::Cryptomining,
        // DNS tunneling detections emitted by some ET Open rules
        "dns-tunnel" | "protocol-command-decode" => CanonicalAttackType::DnsTunnel,
        _ => CanonicalAttackType::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_roundtrip() {
        for canonical in CanonicalAttackType::ALL {
            let wire = canonical.as_str();
            let round = canonical_from_str(wire).expect("wire format must round-trip");
            assert_eq!(*canonical, round, "roundtrip mismatch for {wire}");
        }
    }

    #[test]
    fn unknown_wire_string_returns_none() {
        assert!(canonical_from_str("this_attack_does_not_exist").is_none());
        assert!(canonical_from_str("").is_none());
    }

    #[test]
    fn ml_v10_class_names_translate() {
        // v10 ships 10 classes — every non-"Normal" class must hit a canonical entry.
        // "Normal" is a legitimate benign class and IS expected to return Unknown
        // because translators should not be called on benign flows in the first place.
        let cases = [
            ("Brute Force", CanonicalAttackType::BruteForce),
            ("Reconnaissance", CanonicalAttackType::Reconnaissance),
            ("C2 Communication", CanonicalAttackType::C2Beacon),
            ("DoS/DDoS", CanonicalAttackType::DosDdos),
            ("Exploitation", CanonicalAttackType::Exploit),
            ("Web Attack", CanonicalAttackType::Exploit),
            ("Bot", CanonicalAttackType::BotActivity),
            ("Malware", CanonicalAttackType::BotActivity),
            ("Cryptomining", CanonicalAttackType::Cryptomining),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                translate(DetectionSource::ML, raw),
                expected,
                "ML class {raw:?} must translate to {expected:?}",
            );
        }
    }

    #[test]
    fn beaconing_always_c2() {
        assert_eq!(
            translate(DetectionSource::Beaconing, "anything"),
            CanonicalAttackType::C2Beacon
        );
        assert_eq!(
            translate(DetectionSource::Beaconing, "c2_beacon"),
            CanonicalAttackType::C2Beacon
        );
    }

    #[test]
    fn correlation_subtypes_split() {
        assert_eq!(
            translate(DetectionSource::Correlation, "scan"),
            CanonicalAttackType::PortScan
        );
        assert_eq!(
            translate(DetectionSource::Correlation, "lateral"),
            CanonicalAttackType::LateralMovement
        );
        assert_eq!(
            translate(DetectionSource::Correlation, "botnet"),
            CanonicalAttackType::BotActivity
        );
    }

    #[test]
    fn suricata_classtype_mapping() {
        let cases = [
            ("attempted-admin", CanonicalAttackType::Exploit),
            ("web-application-attack", CanonicalAttackType::Exploit),
            ("trojan-activity", CanonicalAttackType::C2Beacon),
            ("attempted-recon", CanonicalAttackType::Reconnaissance),
            ("attempted-dos", CanonicalAttackType::DosDdos),
            ("coin-mining", CanonicalAttackType::Cryptomining),
            ("brute-force", CanonicalAttackType::BruteForce),
            ("sql-injection", CanonicalAttackType::SqlInjection),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                translate(DetectionSource::Suricata, raw),
                expected,
                "Suricata classtype {raw:?} must translate to {expected:?}",
            );
        }
    }

    #[test]
    fn unknown_label_lands_in_unknown_bucket() {
        // Unknown is the fallback — MUST NOT panic, MUST be dedup-safe.
        for source in [
            DetectionSource::ML,
            DetectionSource::Correlation,
            DetectionSource::Suricata,
        ] {
            assert_eq!(
                translate(source, "this_is_not_a_real_label"),
                CanonicalAttackType::Unknown,
            );
        }
    }

    #[test]
    fn case_insensitive_and_whitespace_tolerant() {
        assert_eq!(
            translate(DetectionSource::ML, "  BRUTE FORCE  "),
            CanonicalAttackType::BruteForce,
        );
        assert_eq!(
            translate(DetectionSource::Suricata, "Attempted-Admin"),
            CanonicalAttackType::Exploit,
        );
    }

    #[test]
    fn dedup_key_non_collision_across_sources() {
        // The central invariant: two sources hitting the SAME attack on the
        // SAME src_ip produce the SAME canonical wire string, so dedup collides.
        let pairs = [
            // ML vs Suricata: brute force
            (
                translate(DetectionSource::ML, "Brute Force"),
                translate(DetectionSource::Suricata, "brute-force"),
            ),
            // ML vs Correlation: port scan — historically mapped to two
            // different canonicals (Reconnaissance vs PortScan) until
            // 2026-04-19. Kept as a regression guard.
            (
                translate(DetectionSource::ML, "port_scan"),
                translate(DetectionSource::Correlation, "scan"),
            ),
            // Suricata network-scan vs Correlation scan — both land on
            // `PortScan` so a Suricata scan alert fuses with Correlation's
            // graph-based scan detection on the same src_ip.
            (
                translate(DetectionSource::Suricata, "network-scan"),
                translate(DetectionSource::Correlation, "scan"),
            ),
            // ML vs Suricata: C2
            (
                translate(DetectionSource::ML, "C2 Communication"),
                translate(DetectionSource::Suricata, "trojan-activity"),
            ),
        ];
        for (a, b) in pairs {
            assert_eq!(
                a.as_str(),
                b.as_str(),
                "cross-source dedup key MUST match for the same canonical attack ({a:?} vs {b:?})",
            );
        }
    }

    #[test]
    fn all_canonical_have_unique_wire_strings() {
        use std::collections::HashSet;
        let strings: HashSet<&str> = CanonicalAttackType::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            strings.len(),
            CanonicalAttackType::ALL.len(),
            "duplicate wire string in CanonicalAttackType::ALL",
        );
    }
}
