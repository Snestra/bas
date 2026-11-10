//! Reference-only environment templates.
//!
//! Grammar, one entry per line: blank lines, lines starting with `#`, and
//! `NAME=bas://<profile>/<secret-id>`. Surrounding spaces, a trailing `\r`, and a leading
//! UTF-8 byte-order mark are ignored. Nothing is expanded, substituted, or run by a shell,
//! and plaintext values are rejected. Errors give line numbers, never line text.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use crate::output::Error;
use bas_core::reference::{self, Binding};

const HEADER: &str = "# bas reference template. Values are resolved only when `bas env run` starts a \
                      command.\n";

/// Parses template text into bindings.
///
/// # Errors
///
/// Fails on a malformed line, a plaintext value, a duplicate variable, or an empty template.
pub fn parse(text: &str) -> Result<Vec<Binding>, Error> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let entries = text
        .split('\n')
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(number, line)| (format!("template line {number}"), line));
    let bindings = reference::parse_bindings(entries)?;
    if bindings.is_empty() {
        return Err(Error::usage("the template has no bindings"));
    }
    Ok(bindings)
}

/// Reads and parses a template file.
///
/// # Errors
///
/// Fails when the file is unreadable, not UTF-8, or malformed.
pub fn read(path: &Path) -> Result<Vec<Binding>, Error> {
    let bytes = fs::read(path)
        .map_err(|err| Error::new(format!("could not read template {}: {err}", path.display())))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| Error::usage(format!("template {} is not UTF-8 text", path.display())))?;
    parse(&text)
}

/// Whether `env write` may replace an existing file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overwrite {
    Refuse,
    Replace,
}

/// Writes a template containing only references.
///
/// The text goes to a temporary file in the same directory, which is then moved into place,
/// so a failed write never leaves a partial template behind.
///
/// # Errors
///
/// Fails when the file exists and `overwrite` is [`Overwrite::Refuse`], or on write errors.
pub fn write(path: &Path, bindings: &[Binding], overwrite: Overwrite) -> Result<(), Error> {
    let mut text = String::from(HEADER);
    for binding in bindings {
        text.push_str(&binding.to_string());
        text.push('\n');
    }
    let behavior = match overwrite {
        Overwrite::Refuse => atomicwrites::DisallowOverwrite,
        Overwrite::Replace => atomicwrites::AllowOverwrite,
    };
    atomicwrites::AtomicFile::new(path, behavior)
        .write(|file| file.write_all(text.as_bytes()))
        .map_err(|err| match io::Error::from(err) {
            err if err.kind() == io::ErrorKind::AlreadyExists => Error::new(format!(
                "{} already exists; pass --force to replace it",
                path.display()
            )),
            err => Error::new(format!(
                "could not write template {}: {err}",
                path.display()
            )),
        })
}
