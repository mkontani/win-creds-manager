//! Human / JSON output helpers. Data goes to stdout, diagnostics to stderr.

use std::io::{self, IsTerminal, Write};

use serde::Serialize;
use wcm_core::{Error, Result};

/// Output configuration shared by all commands.
#[derive(Clone, Copy, Debug)]
pub struct Output {
    /// `--json`
    pub json: bool,
    /// `--quiet`
    pub quiet: bool,
}

impl Output {
    /// Prints `value` as a single JSON document on stdout.
    pub fn json<T: Serialize>(&self, value: &T) -> Result<()> {
        let s = serde_json::to_string_pretty(value)
            .map_err(|e| Error::Other(format!("json encode: {e}")))?;
        let mut out = io::stdout().lock();
        writeln!(out, "{s}").map_err(|e| Error::Io(format!("stdout: {e}")))?;
        Ok(())
    }

    /// Prints a line on stdout (human mode only; JSON mode callers use [`Output::json`]).
    pub fn line(&self, s: &str) -> Result<()> {
        let mut out = io::stdout().lock();
        writeln!(out, "{s}").map_err(|e| Error::Io(format!("stdout: {e}")))?;
        Ok(())
    }

    /// Writes raw bytes to stdout.
    pub fn bytes(&self, b: &[u8]) -> Result<()> {
        let mut out = io::stdout().lock();
        out.write_all(b)
            .map_err(|e| Error::Io(format!("stdout: {e}")))?;
        out.flush().map_err(|e| Error::Io(format!("stdout: {e}")))?;
        Ok(())
    }

    /// Informational message on stderr (suppressed by `--quiet`).
    pub fn notice(&self, s: &str) {
        if !self.quiet {
            eprintln!("{s}");
        }
    }

    /// Warning on stderr (never suppressed).
    pub fn warn(&self, s: &str) {
        eprintln!("warning: {s}");
    }

    /// Prints an error (human or JSON envelope) on stderr.
    pub fn error(&self, e: &Error) {
        if self.json {
            let env = ErrorEnvelope {
                error: ErrorBody {
                    code: e.code(),
                    message: e.to_string(),
                    hint: e.hint(),
                    exit: e.exit_code(),
                },
            };
            if let Ok(s) = serde_json::to_string(&env) {
                eprintln!("{s}");
                return;
            }
        }
        eprintln!("error: {e}");
        if let Some(h) = e.hint() {
            eprintln!("hint: {h}");
        }
    }

    /// Whether stdout is a terminal.
    pub fn stdout_is_tty(&self) -> bool {
        io::stdout().is_terminal()
    }

    /// Whether stdin is a terminal.
    pub fn stdin_is_tty(&self) -> bool {
        io::stdin().is_terminal()
    }
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
    exit: u8,
}

/// Number of bullets shown for any non-empty secret.
pub const MASK_WIDTH: usize = 8;

/// Masks a secret for display.
///
/// The width is fixed: a mask that tracked the real length would leak it for
/// short secrets (a 4-character PIN was previously shown as four bullets).
/// `len` only distinguishes empty from non-empty.
pub fn mask(len: usize) -> String {
    if len == 0 {
        String::new()
    } else {
        "•".repeat(MASK_WIDTH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_hides_the_length() {
        assert_eq!(mask(0), "");
        assert_eq!(mask(1), mask(3));
        assert_eq!(mask(3), mask(100));
        assert_eq!(mask(3).chars().count(), MASK_WIDTH);
    }

    #[test]
    fn error_envelope_serializes() {
        let env = ErrorEnvelope {
            error: ErrorBody {
                code: "NOT_FOUND",
                message: "x".into(),
                hint: None,
                exit: 3,
            },
        };
        let s = serde_json::to_string(&env).expect("json");
        assert_eq!(
            s,
            "{\"error\":{\"code\":\"NOT_FOUND\",\"message\":\"x\",\"exit\":3}}"
        );
    }
}
