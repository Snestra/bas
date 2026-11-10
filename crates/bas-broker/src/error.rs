use std::fmt::{self, Display};

/// Failure with a message built only from fixed text, paths, and names, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<bas_core::Error> for Error {
    fn from(err: bas_core::Error) -> Self {
        Self(err.to_string())
    }
}
