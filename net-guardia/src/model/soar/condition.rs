use std::fmt;
use std::str::FromStr;

use crate::model::error::soar::SoarError;

/// Condition types for multi-condition playbook matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionType {
    /// Confidence threshold: event.confidence >= value
    Threshold,
    /// Source country match: event.geoip_country in comma-separated list
    SourceCountry,
    /// CIDR pattern match: event.source_ip in CIDR range
    IpPattern,
    /// Repeat offender flag: event.is_repeat_offender == value
    RepeatOffender,
    /// Frequency: N events from same source_ip within window_secs
    Frequency,
}

impl fmt::Display for ConditionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Threshold => write!(f, "threshold"),
            Self::SourceCountry => write!(f, "source_country"),
            Self::IpPattern => write!(f, "ip_pattern"),
            Self::RepeatOffender => write!(f, "repeat_offender"),
            Self::Frequency => write!(f, "frequency"),
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
            other => Err(SoarError::InvalidCondition {
                condition_type: other.to_string(),
                reason: "unknown condition type".to_string(),
            }),
        }
    }
}

/// A single condition attached to a playbook.
#[derive(Debug, Clone)]
pub struct PlaybookCondition {
    pub condition_type: ConditionType,
    /// Comparison operator: ">=", "<=", "in", "not_in", "==".
    pub operator: String,
    pub value: String,
    /// Secondary value: window_secs for Frequency conditions.
    pub value2: Option<String>,
}
