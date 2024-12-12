use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Source,
    Destination,
}
