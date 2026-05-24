pub mod codec;
pub mod crypto;
pub mod database;
pub mod http;
pub mod io;
pub mod notification;
pub mod suricata;
pub mod system;

use serde::{Deserialize, Serialize};

use crate::common::error::codec::CodecError;
use crate::common::error::crypto::CryptoError;
use crate::common::error::database::DatabaseError;
use crate::common::error::http::HttpError;
use crate::common::error::io::IOError;
use crate::common::error::notification::NotificationError;
use crate::common::error::suricata::SuricataError;
use crate::common::error::system::SystemError;
use crate::domain::data_plane::error::EbpfError;
use crate::domain::detection::error::MLError;
use crate::domain::identity::error::AuthError;
use crate::domain::report::error::ReportError;
use crate::domain::response::error::SoarError;

#[derive(Clone, Debug, thiserror::Error, Serialize, Deserialize)]
pub enum Error {
    #[error("{0}")]
    Auth(#[from] AuthError),
    #[error("{0}")]
    Codec(#[from] CodecError),
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
    Notification(#[from] NotificationError),
    #[error("{0}")]
    Report(#[from] ReportError),
    #[error("{0}")]
    Soar(#[from] SoarError),
    #[error("{0}")]
    Suricata(#[from] SuricataError),
    #[error("{0}")]
    System(#[from] SystemError),
}
