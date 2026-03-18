use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Ingress,
    Egress,
}

impl Direction {
    pub fn flip(self) -> Self {
        match self {
            Direction::Ingress => Direction::Egress,
            Direction::Egress => Direction::Ingress,
        }
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
