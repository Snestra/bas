//! Copies a program's output while replacing injected values with `[bas:NAME]`.
//!
//! Masking stops a value from reaching a transcript by accident. It isn't a sandbox: a
//! program can still write a value to a file, send it over the network, or print it in
//! another encoding.

use std::io::{self, Read, Write};

use aho_corasick::{AhoCorasick, MatchKind};
use zeroize::Zeroizing;

/// Values shorter than this are not masked, because they would match ordinary output.
pub const MIN_MASKED_LEN: usize = 4;

/// Replaces every injected value in a byte stream with the name of its variable.
pub struct Masker {
    values: Vec<Zeroizing<Vec<u8>>>,
    labels: Vec<Vec<u8>>,
    finder: Option<AhoCorasick>,
}

impl Masker {
    /// Builds a masker from `(variable name, value)` pairs. When two variables hold the same
    /// value, the first name is shown.
    pub fn new<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> io::Result<Self> {
        let mut values: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut labels = Vec::new();
        for (name, value) in pairs {
            let bytes = value.as_bytes();
            if bytes.len() < MIN_MASKED_LEN || values.iter().any(|known| known[..] == *bytes) {
                continue;
            }
            values.push(Zeroizing::new(bytes.to_vec()));
            labels.push(format!("[bas:{name}]").into_bytes());
        }
        let finder = if values.is_empty() {
            None
        } else {
            let finder = AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(values.iter().map(|value| &value[..]))
                .map_err(io::Error::other)?;
            Some(finder)
        };
        Ok(Self {
            values,
            labels,
            finder,
        })
    }

    /// Copies `from` to `to` until end of input, flushing after every read.
    ///
    /// Only the end of the output that could be the start of a value waits for the next
    /// read, so prompts without a newline still appear at once.
    pub fn copy(&self, mut from: impl Read, mut to: impl Write) -> io::Result<()> {
        let mut pending = Zeroizing::new(Vec::new());
        let mut chunk = Zeroizing::new(vec![0_u8; 8192]);
        loop {
            let read = match from.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => read,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            };
            pending.extend_from_slice(&chunk[..read]);
            let held = self.write_masked(&pending, &mut to, false)?;
            let settled = pending.len() - held;
            pending.drain(..settled);
            to.flush()?;
        }
        self.write_masked(&pending, &mut to, true)?;
        to.flush()
    }

    /// Writes `buffer` with every value replaced, and returns how many bytes at its end were
    /// held back. Before the end of input, the longest end of `buffer` that is the start of
    /// some value is held back, even when it already holds a shorter value, because the next
    /// read could complete the longer one.
    fn write_masked(
        &self,
        buffer: &[u8],
        to: &mut impl Write,
        end_of_input: bool,
    ) -> io::Result<usize> {
        let Some(finder) = &self.finder else {
            to.write_all(buffer)?;
            return Ok(0);
        };
        let cut = if end_of_input {
            buffer.len()
        } else {
            buffer.len() - self.partial_value_at_end(buffer)
        };
        let mut written = 0;
        for found in finder.find_iter(buffer) {
            if found.start() >= cut {
                break;
            }
            to.write_all(&buffer[written..found.start()])?;
            to.write_all(&self.labels[found.pattern().as_usize()])?;
            written = found.end();
        }
        let settled = written.max(cut);
        to.write_all(&buffer[written..settled])?;
        Ok(buffer.len() - settled)
    }

    /// Length of the longest end of `buffer` that is the start of some value but not all of it.
    fn partial_value_at_end(&self, buffer: &[u8]) -> usize {
        self.values
            .iter()
            .map(|value| {
                let longest = (value.len() - 1).min(buffer.len());
                (1..=longest)
                    .rev()
                    .find(|&len| buffer.ends_with(&value[..len]))
                    .unwrap_or(0)
            })
            .max()
            .unwrap_or(0)
    }
}
