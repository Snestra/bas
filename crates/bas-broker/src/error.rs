use std::fmt::{self, Display};

/// Failure with a message built only from fixed text, paths, and names, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
    kind: ErrorKind,
}

/// What kind of failure a client call met.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The broker answered and refused the request, so nothing changed.
    Refused,
    /// Anything else.
    Other,
}

impl Error {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self::with_kind(message, ErrorKind::Other)
    }

    pub(crate) fn with_kind(message: impl Into<String>, kind: ErrorKind) -> Self {
        Self {
            message: message.into(),
            kind,
        }
    }

    /// What kind of failure this is.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<bas_core::Error> for Error {
    fn from(err: bas_core::Error) -> Self {
        Self::new(err.to_string())
    }
}
