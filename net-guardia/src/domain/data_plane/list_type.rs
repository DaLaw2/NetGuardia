use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Hash)]
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
