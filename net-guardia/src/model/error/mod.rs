pub mod auth;
pub mod database;
pub mod ebpf;
pub mod http;
pub mod io;
#[cfg(feature = "license")]
pub mod license;
pub mod misc;
pub mod ml;
pub mod system;

use serde::{Deserialize, Serialize};

use crate::model::error::auth::AuthError;
use crate::model::error::database::DatabaseError;
use crate::model::error::ebpf::EbpfError;
use crate::model::error::http::HttpError;
use crate::model::error::io::IOError;
#[cfg(feature = "license")]
use crate::model::error::license::LicenseError;
use crate::model::error::misc::MiscError;
use crate::model::error::ml::MLError;
use crate::model::error::system::SystemError;

#[derive(Clone, Debug, thiserror::Error, Serialize, Deserialize)]
pub enum Error {
    #[error("{0}")]
    Auth(AuthError),
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
    #[cfg(feature = "license")]
    #[error("{0}")]
    License(LicenseError),
    #[error("{0}")]
    Misc(MiscError),
    #[error("{0}")]
    System(SystemError),
}

impl From<AuthError> for Error {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
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

#[cfg(feature = "license")]
impl From<LicenseError> for Error {
    fn from(error: LicenseError) -> Self {
        Self::License(error)
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
