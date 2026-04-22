use std::fmt;

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

#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum FlowDirection {
    Source,
    Destination,
}
