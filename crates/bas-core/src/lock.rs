//! Cross-process lock on the configuration directory.

use std::fs::{File, OpenOptions, TryLockError};

use crate::Error;
use crate::profile;

/// Lock file shared by every `bas` process using one configuration directory. It is
/// separate from the files it guards because saving replaces those files.
const LOCK_FILE: &str = "policy.lock";

/// Exclusive hold on the configuration-directory lock, released on drop.
///
/// Profile and grant writes need one, and a listener holds one from its final
/// authorization check until the SDK has handed that reply to the relay.
#[derive(Debug)]
pub struct ConfigLock {
    _file: File,
}

impl ConfigLock {
    /// Waits until the lock is free and takes it.
    ///
    /// Callers that tell the user about the wait call [`ConfigLock::try_acquire`] first.
    ///
    /// # Errors
    ///
    /// Fails when the configuration directory is unusable or the lock file cannot be
    /// opened or locked.
    pub fn acquire() -> Result<Self, Error> {
        let file = open_lock()?;
        file.lock().map_err(|_| lock_failed())?;
        Ok(Self { _file: file })
    }

    /// Takes the lock only when it is free. Returns `None` when another process holds it.
    ///
    /// # Errors
    ///
    /// Fails when the configuration directory is unusable or the lock file cannot be
    /// opened or locked.
    pub fn try_acquire() -> Result<Option<Self>, Error> {
        let file = open_lock()?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(_)) => Err(lock_failed()),
        }
    }
}

fn lock_failed() -> Error {
    Error::new("could not lock the bas policy; grants and profiles were not changed")
}

fn open_lock() -> Result<File, Error> {
    let dir = profile::config_dir()?;
    profile::create_private_dir(&dir).map_err(|_| lock_failed())?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(dir.join(LOCK_FILE)).map_err(|_| lock_failed())
}
