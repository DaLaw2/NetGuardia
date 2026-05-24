use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::domain::common::event::{DetectionSource, ThreatDetectedEvent};
use crate::domain::response::error::SoarError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionType {
    Threshold,
    SourceCountry,
    IpPattern,
    RepeatOffender,
    Frequency,
    MultiSourceMin,
    SingleSourceHigh,
    FusedConfidenceAbove,
}

impl fmt::Display for ConditionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Threshold => write!(f, "threshold"),
            Self::SourceCountry => write!(f, "source_country"),
            Self::IpPattern => write!(f, "ip_pattern"),
            Self::RepeatOffender => write!(f, "repeat_offender"),
            Self::Frequency => write!(f, "frequency"),
            Self::MultiSourceMin => write!(f, "multi_source_min"),
            Self::SingleSourceHigh => write!(f, "single_source_high"),
            Self::FusedConfidenceAbove => write!(f, "fused_confidence_above"),
        }
    }
}

impl FromStr for ConditionType {
    type Err = SoarError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "threshold" => Ok(Self::Threshold),
            "source_country" => Ok(Self::SourceCountry),
            "ip_pattern" => Ok(Self::IpPattern),
            "repeat_offender" => Ok(Self::RepeatOffender),
            "frequency" => Ok(Self::Frequency),
            "multi_source_min" => Ok(Self::MultiSourceMin),
            "single_source_high" => Ok(Self::SingleSourceHigh),
            "fused_confidence_above" => Ok(Self::FusedConfidenceAbove),
            other => Err(SoarError::UnknownConditionType(other)),
        }
    }
}

impl ConditionType {
    pub fn default_operator(&self) -> &'static str {
        match self {
            Self::Threshold
            | Self::Frequency
            | Self::MultiSourceMin
            | Self::SingleSourceHigh
            | Self::FusedConfidenceAbove => ">=",
            Self::SourceCountry | Self::IpPattern => "in",
            Self::RepeatOffender => "==",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PlaybookCondition {
    pub condition_type: ConditionType,
    pub operator: String,
    pub value: String,
    pub value2: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionEvaluation {
    pub met: bool,
    pub details: String,
}

pub fn is_valid_operator(condition_type: &ConditionType, operator: &str) -> bool {
    match condition_type {
        ConditionType::Threshold => matches!(operator, ">=" | "<="),
        ConditionType::SourceCountry | ConditionType::IpPattern => matches!(operator, "in" | "not_in"),
        ConditionType::RepeatOffender => operator == "==",
        ConditionType::Frequency => operator == ">=",
        ConditionType::MultiSourceMin => operator == ">=",
        ConditionType::SingleSourceHigh => operator == ">=",
        ConditionType::FusedConfidenceAbove => matches!(operator, ">=" | "<="),
    }
}

impl PlaybookCondition {
    pub fn evaluate_event_fields(
        &self,
        event: &ThreatDetectedEvent,
        default_single_source_min_conf: f32,
    ) -> ConditionEvaluation {
        if !is_valid_operator(&self.condition_type, &self.operator) {
            return ConditionEvaluation {
                met: false,
                details: format!(
                    "invalid operator '{}' for condition type '{}'",
                    self.operator, self.condition_type
                ),
            };
        }

        match self.condition_type {
            ConditionType::Threshold => {
                let threshold = match self.value.parse::<f64>() {
                    Ok(v) => v,
                    Err(_) => {
                        return ConditionEvaluation {
                            met: false,
                            details: format!("invalid threshold value: {}", self.value),
                        };
                    }
                };
                let confidence = event.confidence as f64;
                let met = if self.operator == "<=" {
                    confidence <= threshold
                } else {
                    confidence >= threshold
                };
                ConditionEvaluation {
                    met,
                    details: format!("event.confidence={confidence:.3}"),
                }
            }
            ConditionType::SourceCountry => {
                let matches = event.geoip_country.as_ref().is_some_and(|country| {
                    self.value
                        .split(',')
                        .map(str::trim)
                        .any(|candidate| candidate.eq_ignore_ascii_case(country))
                });
                let met = if self.operator == "not_in" { !matches } else { matches };
                ConditionEvaluation {
                    met,
                    details: format!(
                        "event.geoip_country={}",
                        event.geoip_country.as_deref().unwrap_or("none")
                    ),
                }
            }
            ConditionType::IpPattern => {
                let ip = match event.source_ip.parse::<IpAddr>() {
                    Ok(a) => a,
                    Err(_) => {
                        return ConditionEvaluation {
                            met: false,
                            details: format!("invalid source_ip: {}", event.source_ip),
                        };
                    }
                };
                let matches = match ip_matches_cidr_pattern(&self.value, ip) {
                    Ok(matches) => matches,
                    Err(_) => {
                        return ConditionEvaluation {
                            met: false,
                            details: format!("invalid CIDR: {}", self.value),
                        };
                    }
                };
                let met = if self.operator == "not_in" { !matches } else { matches };
                ConditionEvaluation {
                    met,
                    details: format!("event.source_ip={}", event.source_ip),
                }
            }
            ConditionType::RepeatOffender => {
                let expected = self.value.eq_ignore_ascii_case("true");
                let met = event.is_repeat_offender == expected;
                ConditionEvaluation {
                    met,
                    details: format!("event.is_repeat_offender={}", event.is_repeat_offender),
                }
            }
            ConditionType::Frequency => ConditionEvaluation {
                met: false,
                details: "frequency condition requires runtime history from FrequencyTracker".to_string(),
            },
            ConditionType::MultiSourceMin => {
                let required = match self.value.parse::<usize>() {
                    Ok(v) => v,
                    Err(_) => {
                        return ConditionEvaluation {
                            met: false,
                            details: format!("invalid required count: {}", self.value),
                        };
                    }
                };
                let met = event.active_source_count >= required;
                ConditionEvaluation {
                    met,
                    details: format!(
                        "event.active_source_count={} required={required}",
                        event.active_source_count
                    ),
                }
            }
            ConditionType::SingleSourceHigh => {
                let target_source = match DetectionSource::from_str(&self.value) {
                    Ok(s) => s,
                    Err(_) => {
                        return ConditionEvaluation {
                            met: false,
                            details: format!("unknown DetectionSource: {}", self.value),
                        };
                    }
                };
                let min_conf = self
                    .value2
                    .as_ref()
                    .and_then(|s| s.parse::<f32>().ok())
                    .unwrap_or(default_single_source_min_conf);
                let solo_match =
                    event.active_source_count == 1 && event.sources.len() == 1 && event.sources[0] == target_source;
                let conf_met = event.confidence >= min_conf;
                let met = solo_match && conf_met;
                ConditionEvaluation {
                    met,
                    details: format!(
                        "sources={:?} count={} conf={:.3} target={} need_conf>={:.3}",
                        event.sources, event.active_source_count, event.confidence, self.value, min_conf
                    ),
                }
            }
            ConditionType::FusedConfidenceAbove => {
                let threshold = match self.value.parse::<f32>() {
                    Ok(v) => v,
                    Err(_) => {
                        return ConditionEvaluation {
                            met: false,
                            details: format!("invalid threshold: {}", self.value),
                        };
                    }
                };
                let met = if self.operator == "<=" {
                    event.fused_confidence <= threshold
                } else {
                    event.fused_confidence >= threshold
                };
                ConditionEvaluation {
                    met,
                    details: format!("event.fused_confidence={:.3}", event.fused_confidence),
                }
            }
        }
    }
}

pub fn ip_matches_cidr_pattern(pattern: &str, ip: IpAddr) -> Result<bool, ()> {
    let (network, prefix) = parse_ip_pattern(pattern)?;
    match (network, ip) {
        (IpAddr::V4(network), IpAddr::V4(ip)) => {
            let prefix = validate_prefix(prefix, 32, pattern)?;
            let mask = prefix_mask_u32(prefix);
            Ok((u32::from(network) & mask) == (u32::from(ip) & mask))
        }
        (IpAddr::V6(network), IpAddr::V6(ip)) => {
            let prefix = validate_prefix(prefix, 128, pattern)?;
            let mask = prefix_mask_u128(prefix);
            Ok((u128::from(network) & mask) == (u128::from(ip) & mask))
        }
        _ => Ok(false),
    }
}

pub fn is_valid_ip_pattern(pattern: &str) -> bool {
    parse_ip_pattern(pattern)
        .and_then(|(network, prefix)| match network {
            IpAddr::V4(_) => validate_prefix(prefix, 32, pattern).map(|_| ()),
            IpAddr::V6(_) => validate_prefix(prefix, 128, pattern).map(|_| ()),
        })
        .is_ok()
}

fn parse_ip_pattern(pattern: &str) -> Result<(IpAddr, u8), ()> {
    let trimmed = pattern.trim();
    let (ip_part, prefix_part) = match trimmed.split_once('/') {
        Some(parts) => parts,
        None => {
            let ip = trimmed.parse::<IpAddr>().map_err(|_| ())?;
            let prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            return Ok((ip, prefix));
        }
    };
    let ip = ip_part.parse::<IpAddr>().map_err(|_| ())?;
    let prefix = prefix_part.parse::<u8>().map_err(|_| ())?;
    Ok((ip, prefix))
}

fn validate_prefix(prefix: u8, max: u8, _pattern: &str) -> Result<u8, ()> {
    if prefix <= max { Ok(prefix) } else { Err(()) }
}

fn prefix_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) }
}

fn prefix_mask_u128(prefix: u8) -> u128 {
    if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) }
}
