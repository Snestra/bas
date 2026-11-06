use std::fmt::{self, Display};

/// Failure whose message is built only from fixed text and nonsecret identifiers.
///
/// Upstream error bodies are never included, so the message is safe to show. Use
/// [`Error::is_usage`] to tell bad input apart from a failed operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Error {
    kind: Kind,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Usage,
    Failed,
}

impl Error {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            kind: Kind::Failed,
            message: message.into(),
        }
    }

    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Self {
            kind: Kind::Usage,
            message: message.into(),
        }
    }

    /// Whether the caller gave unusable input, such as a malformed name, ID, or URL.
    ///
    /// Any other error means a well-formed operation failed.
    #[must_use]
    pub fn is_usage(&self) -> bool {
        self.kind == Kind::Usage
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}
