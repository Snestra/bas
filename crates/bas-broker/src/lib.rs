//! The bas credential broker, which `bas broker` starts, and the client that `bas run` uses
//! to reach it.
//!
//! The broker is the only process that holds the Bitwarden machine token. It serves an
//! HTTP/1.1 and JSON API on a unix socket, where it identifies each caller by the kernel's
//! peer credentials, and an HTTPS proxy on a loopback port that adds a credential header to
//! requests for hosts named in the active policy. Each credential it hands out or adds is
//! written to the system journal with `BAS_AUDIT=1`.
//!
//! The crate builds only on Linux. On other systems it is empty.

#![cfg(target_os = "linux")]

mod audit;
pub mod client;
mod config;
mod error;
mod policy;
pub mod protocol;
mod proxy;
mod server;

pub use error::Error;
pub use server::{Options, serve};

/// Makes ring the process-wide rustls crypto provider.
///
/// hudsucker turns on rustls's aws-lc-rs provider next to the ring provider the rest of
/// `bas` uses, and with two providers rustls cannot choose one by itself, so every TLS
/// client in the process, including the Secrets Manager SDK, would panic. Call this once at
/// the start of `main`.
pub fn install_crypto_provider() {
    // A provider installed earlier is just as usable, so that error is ignored.
    let _ = hudsucker::rustls::crypto::ring::default_provider().install_default();
}
