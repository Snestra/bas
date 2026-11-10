//! Private files in the broker's state and runtime directories.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::Error;

/// A file error that names the path and never the contents.
pub fn file_error(action: &str, path: &Path, err: &std::io::Error) -> Error {
    Error::new(format!("could not {action} {}: {err}", path.display()))
}

/// Creates `dir` and its parents, mode 0700.
pub fn create_dir(dir: &Path) -> Result<(), Error> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|err| file_error("create", dir, &err))
}

/// Creates `path`, which must not exist, and sets `mode` after writing, because the
/// service's umask would narrow a mode given at creation.
pub fn write_new(path: &Path, contents: &[u8], mode: u32) -> Result<(), Error> {
    let failed = |err: std::io::Error| file_error("write", path, &err);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(failed)?;
    file.write_all(contents).map_err(failed)?;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(failed)?;
    file.sync_all().map_err(failed)
}

/// Replaces `path` with `contents` in one rename, so a reader sees the old file or the new
/// one, never a part.
pub fn replace(path: &Path, contents: &[u8], mode: u32) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        create_dir(parent)?;
    }
    let mut staged = PathBuf::from(path);
    staged.as_mut_os_string().push(".new");
    match std::fs::remove_file(&staged) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(file_error("replace", &staged, &err)),
    }
    write_new(&staged, contents, mode)?;
    std::fs::rename(&staged, path).map_err(|err| file_error("write", path, &err))
}
