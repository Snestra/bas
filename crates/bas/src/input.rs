//! Reads one secret value or machine token from piped stdin or the clipboard.

use std::io::{self, IsTerminal, Read};
use std::mem;

use bas_core::Zeroizing;
use bas_core::credential::SecretText;

use crate::output::Error;

/// Channel that supplies a secret value or token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputSource {
    Stdin,
    Clipboard,
}

/// Reads one secret from stdin or the clipboard.
///
/// The text must be UTF-8, because Secrets Manager stores text. Every byte is preserved,
/// including terminal line endings. Empty input is rejected. Machine-token parsing
/// handles token-specific line endings separately.
///
/// # Errors
///
/// Fails when stdin is a terminal, the input is not UTF-8 or is empty, or the clipboard
/// has no text.
pub fn read_secret(source: InputSource) -> Result<SecretText, Error> {
    let text = match source {
        InputSource::Stdin => read_stdin()?,
        InputSource::Clipboard => read_clipboard()?,
    };
    if text.is_empty() {
        return Err(Error::new("the secret input is empty"));
    }
    Ok(SecretText::from_zeroizing(text))
}

fn read_stdin() -> Result<Zeroizing<String>, Error> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err(Error::usage(
            "--stdin needs piped input; typing at a terminal would echo the secret",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    stdin
        .lock()
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new("could not read the secret from stdin"))?;
    match String::from_utf8(mem::take(&mut *bytes)) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(err) => {
            drop(Zeroizing::new(err.into_bytes()));
            Err(Error::new("the secret input is not valid UTF-8 text"))
        }
    }
}

fn read_clipboard() -> Result<Zeroizing<String>, Error> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|_| Error::new("no clipboard is available here; use --stdin"))?;
    match clipboard.get_text() {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(arboard::Error::ContentNotAvailable) => {
            Err(Error::new("the clipboard does not contain text"))
        }
        Err(_) => Err(Error::new("could not read the clipboard; use --stdin")),
    }
}
