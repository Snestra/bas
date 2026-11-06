//! Profiles, machine-token storage, secret references, and the Secrets Manager client used by
//! the `bas` command-line tool.
//!
//! The library never prints, reads a terminal, or starts an async runtime. Error messages
//! are built only from fixed text and nonsecret identifiers, so callers may show them.

pub mod credential;
mod error;
pub mod lock;
pub mod login;
pub mod profile;
pub mod reference;
pub mod secrets;

pub use error::Error;

/// Identity fingerprint of an Agent Access device, as stored in profiles.
pub use ap_client::IdentityFingerprint;
/// Secret, project, and organization identifier.
pub use uuid::Uuid;
/// Wrapper that zeroes its contents on drop, used for secret text and key material.
pub use zeroize::Zeroizing;
