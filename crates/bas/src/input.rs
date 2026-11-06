//! Reads one secret value or machine token from piped stdin, the clipboard, or a terminal
//! prompt that hides what is typed.

use std::io::{self, IsTerminal, Read, Write};
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

/// Whether a hidden prompt can ask the user, because stdin is a terminal.
pub fn can_prompt() -> bool {
    io::stdin().is_terminal()
}

/// Asks on the terminal for one line and hides what is typed or pasted.
///
/// `question` goes to stderr. Enter ends the input; Esc or Ctrl-C cancels it.
///
/// # Errors
///
/// Fails when the terminal cannot be read, the user cancels, or the input is empty.
pub fn prompt_hidden(question: &str) -> Result<SecretText, Error> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

    /// Leaves raw mode on every return path.
    struct RawMode;
    impl Drop for RawMode {
        fn drop(&mut self) {
            // Nothing else can restore the terminal; a failure leaves it as it was.
            drop(crossterm::terminal::disable_raw_mode());
        }
    }

    let failed = |_| Error::new("could not read the terminal");
    let mut stderr = io::stderr().lock();
    write!(stderr, "{question}")
        .and_then(|()| stderr.flush())
        .map_err(failed)?;
    let mut text = SecretText::default();
    let entered = {
        crossterm::terminal::enable_raw_mode().map_err(failed)?;
        let _raw = RawMode;
        loop {
            let Event::Key(key) = event::read().map_err(failed)? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            let typing = key.modifiers.difference(KeyModifiers::SHIFT).is_empty();
            match key.code {
                KeyCode::Enter => break true,
                KeyCode::Esc => break false,
                KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => break false,
                KeyCode::Backspace => text.pop(),
                KeyCode::Char(ch) if typing => text.push(ch),
                _ => {}
            }
        }
    };
    writeln!(stderr).map_err(failed)?;
    if !entered {
        return Err(Error::new("cancelled; nothing was saved"));
    }
    if text.is_empty() {
        return Err(Error::new("the secret input is empty"));
    }
    Ok(text)
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
