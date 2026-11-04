//! Native credential store construction.
//!
//! Entries are built straight from the platform store, so no global default store is set.

use std::sync::{Arc, LazyLock};

use keyring_core::{CredentialStore, Entry, Error, Result};

/// Credential-store service name; the account name is the profile name.
const SERVICE: &str = "bas";

/// The platform store, created once per process.
static STORE: LazyLock<Result<Arc<CredentialStore>>> = LazyLock::new(platform_store);

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_store() -> Result<Arc<CredentialStore>> {
    let store = dbus_secret_service_keyring_store::Store::new()?;
    Ok(store)
}

#[cfg(target_os = "macos")]
fn platform_store() -> Result<Arc<CredentialStore>> {
    let store = apple_native_keyring_store::keychain::Store::new()?;
    Ok(store)
}

#[cfg(target_os = "windows")]
fn platform_store() -> Result<Arc<CredentialStore>> {
    let store = windows_native_keyring_store::Store::new()?;
    Ok(store)
}

/// Builds the entry for `account` in the platform store.
///
/// # Errors
///
/// Fails with [`Error::NoDefaultStore`] when the platform store could not be created, and
/// with the store's own error when it rejects the account.
pub(super) fn entry(account: &str) -> Result<Entry> {
    match &*STORE {
        Ok(store) => store.build(SERVICE, account, None),
        Err(_) => Err(Error::NoDefaultStore),
    }
}
