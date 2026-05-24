use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Ingress,
    Egress,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Ingress => write!(f, "Ingress"),
            Direction::Egress => write!(f, "Egress"),
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum FlowDirection {
    Source,
    Destination,
}

impl FlowDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Destination => "destination",
        }
    }
}

impl FromStr for FlowDirection {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "source" => Ok(Self::Source),
            "destination" => Ok(Self::Destination),
            other => Err(format!("unknown ACL direction: {other}")),
        }
    }
}
