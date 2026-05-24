use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ListType {
    #[serde(rename = "whitelist")]
    White,
    #[serde(rename = "blacklist")]
    Black,
}

impl ListType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::White => "whitelist",
            Self::Black => "blacklist",
        }
    }
}

impl FromStr for ListType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "whitelist" => Ok(Self::White),
            "blacklist" => Ok(Self::Black),
            other => Err(format!("unknown ACL list_type: {other}")),
        }
    }
}
