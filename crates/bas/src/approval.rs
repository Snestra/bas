//! Trusted-terminal approval for one exact pending request.
//!
//! The trusted terminal is the controlling terminal of the `bas` process (`/dev/tty`, or
//! the console on Windows), not its standard streams, so a program that feeds stdin or
//! reads stdout cannot answer. Every prompt asks for a fresh code and discards input typed
//! before it appeared, so an answer can never carry over to another request. Without a
//! usable terminal every prompt denies at once instead of waiting.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::thread;

use tokio::sync::mpsc::{self, error::TryRecvError};
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

/// Length of the code typed to approve one request.
const CODE_LENGTH: usize = 6;

/// The operator's answer to one prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The operator typed the expected text.
    Approved,
    /// The operator typed anything else, including an empty line.
    Denied,
    /// No answer arrived before the deadline.
    TimedOut,
    /// No trusted terminal is usable.
    Unavailable,
}

/// The controlling terminal, read line by line on a dedicated thread.
pub struct Terminal {
    output: File,
    lines: mpsc::UnboundedReceiver<String>,
}

impl Terminal {
    /// Opens the controlling terminal. Returns `None` when the process has none.
    pub fn open() -> Option<Self> {
        let (input, output) = open_terminal().ok()?;
        let (sender, lines) = mpsc::unbounded_channel();
        thread::Builder::new()
            .name("bas-terminal".to_owned())
            .spawn(move || {
                for line in BufReader::new(input).lines() {
                    let Ok(line) = line else { break };
                    if sender.send(line).is_err() {
                        break;
                    }
                }
            })
            .ok()?;
        Some(Self { output, lines })
    }

    /// Writes one line to the terminal. Returns `false` when the terminal is gone.
    pub fn say(&mut self, text: &str) -> bool {
        writeln!(self.output, "{text}")
            .and_then(|()| self.output.flush())
            .is_ok()
    }

    /// Shows `prompt` and approves only when the next line typed is `expected`.
    ///
    /// Comparison ignores surrounding whitespace and ASCII case.
    pub async fn confirm(&mut self, prompt: &str, expected: &str, deadline: Instant) -> Decision {
        if !self.discard_typed() {
            return Decision::Unavailable;
        }
        if write!(self.output, "{prompt} ")
            .and_then(|()| self.output.flush())
            .is_err()
        {
            return Decision::Unavailable;
        }
        match timeout_at(deadline, self.lines.recv()).await {
            Ok(Some(line)) if line.trim().eq_ignore_ascii_case(expected) => Decision::Approved,
            Ok(Some(_)) => Decision::Denied,
            Ok(None) => Decision::Unavailable,
            Err(_) => {
                self.say("");
                self.say("no answer in time; denied");
                Decision::TimedOut
            }
        }
    }

    /// Reads one line typed after the prompt, or `None` without an answer in time.
    pub async fn ask(&mut self, prompt: &str, deadline: Instant) -> Option<String> {
        if !self.discard_typed() {
            return None;
        }
        write!(self.output, "{prompt} ")
            .and_then(|()| self.output.flush())
            .ok()?;
        timeout_at(deadline, self.lines.recv()).await.ok().flatten()
    }

    /// Drops lines typed before a prompt. Returns `false` when the terminal is gone.
    fn discard_typed(&mut self) -> bool {
        loop {
            match self.lines.try_recv() {
                Ok(_) => {}
                Err(TryRecvError::Empty) => return true,
                Err(TryRecvError::Disconnected) => return false,
            }
        }
    }
}

/// A fresh random code that approves exactly one prompt.
pub fn approval_code() -> String {
    Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(CODE_LENGTH)
        .collect::<String>()
        .to_ascii_uppercase()
}

#[cfg(unix)]
fn open_terminal() -> io::Result<(File, File)> {
    let input = File::open("/dev/tty")?;
    let output = OpenOptions::new().write(true).open("/dev/tty")?;
    Ok((input, output))
}

#[cfg(windows)]
fn open_terminal() -> io::Result<(File, File)> {
    let input = OpenOptions::new().read(true).write(true).open("CONIN$")?;
    let output = OpenOptions::new().write(true).open("CONOUT$")?;
    Ok((input, output))
}
