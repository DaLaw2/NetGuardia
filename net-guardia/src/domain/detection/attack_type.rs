use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::domain::common::event::DetectionSource;

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
    Unknown,
}

impl CanonicalAttackType {
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

impl FromStr for CanonicalAttackType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL.iter().copied().find(|c| c.as_str() == s).ok_or(())
    }
}

pub fn canonical_from_str(s: &str) -> Option<CanonicalAttackType> {
    s.parse().ok()
}

pub fn translate(source: DetectionSource, raw_label: &str) -> CanonicalAttackType {
    let normalized = raw_label.trim().to_ascii_lowercase();
    match source {
        DetectionSource::ML => translate_ml(&normalized),
        DetectionSource::Beaconing => translate_beaconing(&normalized),
        DetectionSource::Correlation => translate_correlation(&normalized),
        DetectionSource::Suricata => translate_suricata(&normalized),
    }
}

fn translate_ml(label: &str) -> CanonicalAttackType {
    match label {
        "brute force" | "brute_force" | "bruteforce" => CanonicalAttackType::BruteForce,
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
        _ => CanonicalAttackType::Unknown,
    }
}

fn translate_beaconing(_label: &str) -> CanonicalAttackType {
    CanonicalAttackType::C2Beacon
}

fn translate_correlation(label: &str) -> CanonicalAttackType {
    match label {
        "scan" | "port_scan" | "reconnaissance" => CanonicalAttackType::PortScan,
        "lateral" | "lateral_movement" => CanonicalAttackType::LateralMovement,
        "botnet" | "bot" | "bot_activity" => CanonicalAttackType::BotActivity,
        _ => CanonicalAttackType::Unknown,
    }
}

fn translate_suricata(label: &str) -> CanonicalAttackType {
    match label {
        "network-scan" => CanonicalAttackType::PortScan,
        "attempted-recon" | "misc-activity" => CanonicalAttackType::Reconnaissance,
        "attempted-admin" | "successful-admin" | "attempted-user" | "successful-user" | "shellcode-detect"
        | "attempted-exploit" => CanonicalAttackType::Exploit,
        "web-application-attack" => CanonicalAttackType::Exploit,
        "web-application-activity" => CanonicalAttackType::Exploit,
        "sql-injection" => CanonicalAttackType::SqlInjection,
        "xss" | "cross-site-scripting" => CanonicalAttackType::Xss,
        "attempted-dos" | "successful-dos" | "denial-of-service" => CanonicalAttackType::DosDdos,
        "trojan-activity" | "malware-cnc" | "command-and-control" => CanonicalAttackType::C2Beacon,
        "suspicious-login" | "unsuccessful-user" | "brute-force" => CanonicalAttackType::BruteForce,
        "coin-mining" | "policy-violation" => CanonicalAttackType::Cryptomining,
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
        let pairs = [
            (
                translate(DetectionSource::ML, "Brute Force"),
                translate(DetectionSource::Suricata, "brute-force"),
            ),
            (
                translate(DetectionSource::ML, "port_scan"),
                translate(DetectionSource::Correlation, "scan"),
            ),
            (
                translate(DetectionSource::Suricata, "network-scan"),
                translate(DetectionSource::Correlation, "scan"),
            ),
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
