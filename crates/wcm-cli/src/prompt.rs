//! Interactive prompting (`Prompter` implementation for the CLI).
//!
//! Secret resolution order: `WCM_PASSPHRASE` env → `--no-input` error → TTY prompt.
//! Inputs that look like a recovery key (`WCM1-…`) are normalized to the canonical
//! form so typing them in lowercase / without dashes still works.

use std::io::{self, BufRead, Write};

use secrecy::{ExposeSecret, SecretString};
use wcm_core::recovery_key::RecoveryKey;
use wcm_core::slot::Prompter;
use wcm_core::{Error, Result};

/// Environment variable supplying the passphrase / recovery key non-interactively.
pub const PASSPHRASE_ENV: &str = "WCM_PASSPHRASE";

/// CLI prompter.
#[derive(Clone, Debug)]
pub struct CliPrompter {
    /// `--no-input`
    pub no_input: bool,
    /// `--quiet`
    pub quiet: bool,
}

impl CliPrompter {
    /// Reads one hidden line from the TTY.
    pub fn read_hidden(&self, label: &str) -> Result<SecretString> {
        if self.no_input {
            return Err(Error::AuthUnavailable(format!(
                "{label} required but --no-input was given"
            )));
        }
        let s = rpassword::prompt_password(format!("{label}: "))
            .map_err(|e| Error::Io(format!("reading {label}: {e}")))?;
        Ok(SecretString::from(s))
    }

    /// Prompts twice and verifies both entries match.
    pub fn read_hidden_confirmed(&self, label: &str) -> Result<SecretString> {
        let a = self.read_hidden(label)?;
        let b = self.read_hidden(&format!("{label} (again)"))?;
        if a.expose_secret() != b.expose_secret() {
            return Err(Error::Invalid("entries did not match".into()));
        }
        Ok(a)
    }

    /// Reads a visible line from stdin (for confirmations).
    pub fn read_line(&self, prompt: &str) -> Result<String> {
        if self.no_input {
            return Err(Error::AuthUnavailable(format!(
                "input required ({prompt}) but --no-input was given"
            )));
        }
        eprint!("{prompt}");
        io::stderr().flush().ok();
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| Error::Io(format!("stdin: {e}")))?;
        Ok(line.trim().to_string())
    }
}

/// Canonicalizes recovery-key-looking input; other input is returned unchanged.
pub fn normalize_secret(input: SecretString) -> Result<SecretString> {
    if RecoveryKey::looks_like(input.expose_secret()) {
        let k = RecoveryKey::parse(input.expose_secret())?;
        return Ok(k.as_secret());
    }
    Ok(input)
}

/// Passphrase from the environment, if set (normalized).
pub fn passphrase_from_env() -> Result<Option<SecretString>> {
    match std::env::var(PASSPHRASE_ENV) {
        Ok(v) if !v.is_empty() => Ok(Some(normalize_secret(SecretString::from(v))?)),
        _ => Ok(None),
    }
}

impl Prompter for CliPrompter {
    fn secret(&self, label: &str) -> Result<SecretString> {
        if let Some(s) = passphrase_from_env()? {
            return Ok(s);
        }
        normalize_secret(self.read_hidden(label)?)
    }

    fn confirm(&self, msg: &str) -> Result<bool> {
        if self.no_input {
            return Ok(false);
        }
        let ans = self.read_line(&format!("{msg} [y/N] "))?;
        Ok(matches!(ans.to_ascii_lowercase().as_str(), "y" | "yes"))
    }

    fn notice(&self, msg: &str) {
        if !self.quiet {
            eprintln!("{msg}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_recovery_key_input() {
        let k = RecoveryKey::generate();
        let lower = SecretString::from(k.display().to_ascii_lowercase().replace('-', ""));
        assert_eq!(
            normalize_secret(lower).expect("norm").expose_secret(),
            k.display()
        );
        assert_eq!(
            normalize_secret(SecretString::from("plain".to_string()))
                .expect("norm")
                .expose_secret(),
            "plain"
        );
        assert!(matches!(
            normalize_secret(SecretString::from("WCM1-oops".to_string())),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn no_input_prompter_fails_closed() {
        let p = CliPrompter {
            no_input: true,
            quiet: true,
        };
        assert!(matches!(p.read_hidden("x"), Err(Error::AuthUnavailable(_))));
        assert_eq!(p.confirm("sure?").expect("confirm"), false);
        assert!(matches!(p.read_line("q"), Err(Error::AuthUnavailable(_))));
    }
}
