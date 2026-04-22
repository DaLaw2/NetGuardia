pub mod crypto;
pub mod database;
pub mod http;
pub mod io;
pub mod mcp;
pub mod misc;
pub mod notification;
pub mod system;

use serde::{Deserialize, Serialize};

use crate::domain::common::error::crypto::CryptoError;
use crate::domain::common::error::database::DatabaseError;
use crate::domain::common::error::http::HttpError;
use crate::domain::common::error::io::IOError;
use crate::domain::common::error::mcp::McpError;
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
    Auth(AuthError),
    #[error("{0}")]
    Crypto(CryptoError),
    #[error("{0}")]
    Database(DatabaseError),
    #[error("{0}")]
    Ebpf(EbpfError),
    #[error("{0}")]
    Http(HttpError),
    #[error("{0}")]
    ML(MLError),
    #[error("{0}")]
    IO(IOError),
    #[error("{0}")]
    Mcp(McpError),
    #[error("{0}")]
    Misc(MiscError),
    #[error("{0}")]
    Notification(NotificationError),
    #[error("{0}")]
    Soar(SoarError),
    #[error("{0}")]
    Suricata(SuricataError),
    #[error("{0}")]
    System(SystemError),
}

impl From<AuthError> for Error {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

impl From<CryptoError> for Error {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<DatabaseError> for Error {
    fn from(error: DatabaseError) -> Self {
        Self::Database(error)
    }
}

impl From<EbpfError> for Error {
    fn from(error: EbpfError) -> Self {
        Self::Ebpf(error)
    }
}

impl From<HttpError> for Error {
    fn from(error: HttpError) -> Self {
        Self::Http(error)
    }
}

impl From<IOError> for Error {
    fn from(error: IOError) -> Self {
        Self::IO(error)
    }
}

impl From<MiscError> for Error {
    fn from(error: MiscError) -> Self {
        Self::Misc(error)
    }
}

impl From<SystemError> for Error {
    fn from(error: SystemError) -> Self {
        Self::System(error)
    }
}

impl From<MLError> for Error {
    fn from(error: MLError) -> Self {
        Self::ML(error)
    }
}

impl From<NotificationError> for Error {
    fn from(error: NotificationError) -> Self {
        Self::Notification(error)
    }
}

impl From<SoarError> for Error {
    fn from(error: SoarError) -> Self {
        Self::Soar(error)
    }
}

impl From<SuricataError> for Error {
    fn from(error: SuricataError) -> Self {
        Self::Suricata(error)
    }
}

impl From<McpError> for Error {
    fn from(error: McpError) -> Self {
        Self::Mcp(error)
    }
}
