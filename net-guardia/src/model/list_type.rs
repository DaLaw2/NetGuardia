use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ListType {
    #[serde(rename = "white_list")]
    White,
    #[serde(rename = "black_list")]
    Black,
}
