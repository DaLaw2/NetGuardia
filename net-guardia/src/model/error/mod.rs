pub mod ebpf;
pub mod http;
pub mod io;
pub mod misc;
pub mod system;

use serde::{Deserialize, Serialize};

use crate::model::error::ebpf::EbpfError;
use crate::model::error::http::HttpError;
use crate::model::error::io::IOError;
use crate::model::error::misc::MiscError;
use crate::model::error::system::SystemError;

#[derive(Clone, Debug, thiserror::Error, Serialize, Deserialize)]
pub enum Error {
    #[error("{0}")]
    Ebpf(EbpfError),
    #[error("{0}")]
    Http(HttpError),
    #[error("{0}")]
    IO(IOError),
    #[error("{0}")]
    Misc(MiscError),
    #[error("{0}")]
    System(SystemError),
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
