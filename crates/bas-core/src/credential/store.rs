//! Native credential store construction.
//!
//! Entries are built straight from the platform store, so no global default store is set.

use std::sync::{Arc, Mutex, PoisonError};

use keyring_core::{CredentialStore, Entry, Result};

/// Credential-store service name; the account name is the profile name.
const SERVICE: &str = "bas";

/// The platform store, kept once created. A failed creation is not kept, so a later call
/// tries again, for example after the user unlocks or starts the platform store.
static STORE: Mutex<Option<Arc<CredentialStore>>> = Mutex::new(None);

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
/// Fails with the platform's own error when the store could not be created, and with the
/// store's error when it rejects the account.
pub(super) fn entry(account: &str) -> Result<Entry> {
    let mut cached = STORE.lock().unwrap_or_else(PoisonError::into_inner);
    let store = match &*cached {
        Some(store) => Arc::clone(store),
        None => Arc::clone(cached.insert(platform_store()?)),
    };
    drop(cached);
    store.build(SERVICE, account, None)
}
