pub mod crypto;
pub mod database;
pub mod http;
pub mod io;
pub mod misc;
pub mod notification;
pub mod system;

use serde::{Deserialize, Serialize};

use crate::domain::common::error::crypto::CryptoError;
use crate::domain::common::error::database::DatabaseError;
use crate::domain::common::error::http::HttpError;
use crate::domain::common::error::io::IOError;
use crate::domain::common::error::misc::MiscError;
use crate::domain::common::error::notification::NotificationError;
use crate::domain::common::error::system::SystemError;
use crate::domain::data_plane::error::EbpfError;
use crate::domain::detection::error::MLError;
use crate::domain::detection::error::SuricataError;
use crate::domain::identity::error::AuthError;
use crate::domain::response::error::SoarError;

#[derive(Clone, Debug, thiserror::Error, Serialize, Deserialize)]
pub enum Error {
    #[error("{0}")]
    Auth(#[from] AuthError),
    #[error("{0}")]
    Crypto(#[from] CryptoError),
    #[error("{0}")]
    Database(#[from] DatabaseError),
    #[error("{0}")]
    Ebpf(#[from] EbpfError),
    #[error("{0}")]
    Http(#[from] HttpError),
    #[error("{0}")]
    ML(#[from] MLError),
    #[error("{0}")]
    IO(#[from] IOError),
    #[error("{0}")]
    Misc(#[from] MiscError),
    #[error("{0}")]
    Notification(#[from] NotificationError),
    #[error("{0}")]
    Soar(#[from] SoarError),
    #[error("{0}")]
    Suricata(#[from] SuricataError),
    #[error("{0}")]
    System(#[from] SystemError),
}
