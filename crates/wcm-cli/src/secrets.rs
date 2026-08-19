//! Resolving secret input for `add` / `set` from `--stdin`, `--file`,
//! `--generate`, `--value` or an interactive hidden prompt.

use std::io::Read;

use secrecy::ExposeSecret;
use wcm_core::generate::{generate, GenOptions};
use wcm_core::item::FieldValue;
use wcm_core::{Error, Result};
use zeroize::Zeroizing;

use crate::cli::SecretSource;
use crate::prompt::CliPrompter;

/// Where a secret came from (affects auto-detection of item kind).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretOrigin {
    /// `--stdin`
    Stdin,
    /// `--file`
    File,
    /// `--generate`
    Generated,
    /// `--value`
    Value,
    /// Interactive prompt.
    Prompt,
}

/// A resolved secret.
pub struct SecretInput {
    /// Raw bytes.
    pub bytes: Zeroizing<Vec<u8>>,
    /// Origin.
    pub origin: SecretOrigin,
}

impl SecretInput {
    /// Converts to a field value: text when valid UTF-8 (unless `force_binary`), else bytes.
    pub fn into_value(self, force_binary: bool) -> FieldValue {
        if !force_binary {
            if let Ok(s) = std::str::from_utf8(&self.bytes) {
                return FieldValue::Text(s.to_string());
            }
        }
        FieldValue::Bytes(self.bytes.to_vec())
    }

    /// Generated / typed / piped text (lossy for binary).
    #[cfg(test)]
    pub fn text_lossy(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

/// Largest input wcm accepts from stdin or an import file (64 MiB).
///
/// The whole value is held in memory (and re-encrypted into the vault), so an
/// endless pipe must not be able to exhaust it.
pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// Error for input over [`MAX_INPUT_BYTES`].
fn too_large(what: &str) -> Error {
    Error::Invalid(format!("{what} is larger than 64 MiB"))
}

/// Reads all of stdin, up to [`MAX_INPUT_BYTES`].
pub fn read_stdin() -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(Vec::new());
    // One byte over the limit is enough to detect it.
    let limit = MAX_INPUT_BYTES as u64 + 1;
    std::io::stdin()
        .lock()
        .take(limit)
        .read_to_end(&mut buf)
        .map_err(|e| Error::Io(format!("stdin: {e}")))?;
    if buf.len() > MAX_INPUT_BYTES {
        return Err(too_large("input"));
    }
    Ok(buf)
}

/// Reads a file, refusing anything over [`MAX_INPUT_BYTES`].
pub fn read_file_capped(path: &std::path::Path) -> Result<Vec<u8>> {
    let meta =
        std::fs::metadata(path).map_err(|e| Error::Io(format!("{}: {e}", path.display())))?;
    if meta.len() > MAX_INPUT_BYTES as u64 {
        return Err(too_large(&path.display().to_string()));
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_INPUT_BYTES as u64 + 1).read_to_end(&mut buf))
        .map_err(|e| Error::Io(format!("{}: {e}", path.display())))?;
    // The file may have grown between the metadata call and the read.
    if buf.len() > MAX_INPUT_BYTES {
        return Err(too_large(&path.display().to_string()));
    }
    Ok(buf)
}

/// Strips exactly one trailing `\n` or `\r\n`.
pub fn strip_one_newline(mut b: Vec<u8>) -> Vec<u8> {
    if b.ends_with(b"\r\n") {
        b.truncate(b.len() - 2);
    } else if b.ends_with(b"\n") {
        b.truncate(b.len() - 1);
    }
    b
}

/// Resolves the secret per `source`.
///
/// - `--stdin`: all bytes; one trailing newline stripped when `strip_newline`.
/// - `--file`: raw file bytes.
/// - `--generate [LEN] [--words N] [--no-symbols]`: generated password.
/// - `--value`: literal.
/// - otherwise: hidden prompt (twice when `confirm`).
pub fn resolve_secret(
    source: &SecretSource,
    prompter: &CliPrompter,
    label: &str,
    strip_newline: bool,
    confirm: bool,
) -> Result<SecretInput> {
    if source.stdin {
        let raw = read_stdin()?;
        let bytes = if strip_newline {
            strip_one_newline(raw.to_vec())
        } else {
            raw.to_vec()
        };
        return Ok(SecretInput {
            bytes: Zeroizing::new(bytes),
            origin: SecretOrigin::Stdin,
        });
    }
    if let Some(path) = &source.file {
        let bytes =
            std::fs::read(path).map_err(|e| Error::Io(format!("{}: {e}", path.display())))?;
        return Ok(SecretInput {
            bytes: Zeroizing::new(bytes),
            origin: SecretOrigin::File,
        });
    }
    if let Some(len) = source.generate {
        let opts = GenOptions {
            length: len,
            symbols: !source.no_symbols,
            words: source.words,
            separator: "-".into(),
        };
        let pw = generate(&opts)?;
        return Ok(SecretInput {
            bytes: Zeroizing::new(pw.into_bytes()),
            origin: SecretOrigin::Generated,
        });
    }
    if let Some(v) = &source.value {
        return Ok(SecretInput {
            bytes: Zeroizing::new(v.clone().into_bytes()),
            origin: SecretOrigin::Value,
        });
    }
    let s = if confirm {
        prompter.read_hidden_confirmed(label)?
    } else {
        prompter.read_hidden(label)?
    };
    Ok(SecretInput {
        bytes: Zeroizing::new(s.expose_secret().as_bytes().to_vec()),
        origin: SecretOrigin::Prompt,
    })
}

/// Warns when the secret came from `--value`.
///
/// Command-line arguments are visible to every process on the machine
/// (`ps`, `/proc`, Task Manager), so the flag is hidden and discouraged.
pub fn warn_if_exposed(out: &crate::output::Output, input: &SecretInput) {
    if input.origin == SecretOrigin::Value {
        out.warn("--value exposes the secret in process listings; prefer --stdin");
    }
}

/// Parses `KEY=VALUE`.
pub fn parse_kv(s: &str) -> Result<(String, String)> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| Error::Invalid(format!("expected KEY=VALUE, got '{s}'")))?;
    wcm_core::item::validate_field_name(k)?;
    Ok((k.to_string(), v.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> SecretSource {
        SecretSource {
            stdin: false,
            file: None,
            generate: None,
            words: None,
            no_symbols: false,
            value: None,
        }
    }

    fn prompter() -> CliPrompter {
        CliPrompter {
            no_input: true,
            quiet: true,
        }
    }

    #[test]
    fn strip_newline_variants() {
        assert_eq!(strip_one_newline(b"a\n".to_vec()), b"a");
        assert_eq!(strip_one_newline(b"a\r\n".to_vec()), b"a");
        assert_eq!(strip_one_newline(b"a\n\n".to_vec()), b"a\n");
        assert_eq!(strip_one_newline(b"a".to_vec()), b"a");
    }

    #[test]
    fn value_and_generate_and_file_sources() {
        let s = SecretSource {
            value: Some("v".into()),
            ..src()
        };
        let r = resolve_secret(&s, &prompter(), "x", true, false).expect("value");
        assert_eq!(r.origin, SecretOrigin::Value);
        assert_eq!(r.text_lossy(), "v");
        assert_eq!(r.into_value(false), FieldValue::Text("v".into()));

        let s = SecretSource {
            generate: Some(16),
            no_symbols: true,
            ..src()
        };
        let r = resolve_secret(&s, &prompter(), "x", true, false).expect("gen");
        assert_eq!(r.origin, SecretOrigin::Generated);
        assert_eq!(r.bytes.len(), 16);

        let s = SecretSource {
            generate: Some(24),
            words: Some(3),
            ..src()
        };
        let r = resolve_secret(&s, &prompter(), "x", true, false).expect("words");
        assert_eq!(r.text_lossy().split('-').count(), 3);

        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("blob");
        std::fs::write(&p, [0u8, 255, 1]).expect("write");
        let s = SecretSource {
            file: Some(p),
            ..src()
        };
        let r = resolve_secret(&s, &prompter(), "x", true, false).expect("file");
        assert_eq!(r.origin, SecretOrigin::File);
        assert_eq!(r.into_value(false), FieldValue::Bytes(vec![0, 255, 1]));

        let s = SecretSource {
            file: Some("/nonexistent/zzz".into()),
            ..src()
        };
        assert!(matches!(
            resolve_secret(&s, &prompter(), "x", true, false),
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn prompt_source_respects_no_input() {
        let r = resolve_secret(&src(), &prompter(), "Secret", true, false);
        assert!(matches!(r, Err(Error::AuthUnavailable(_))));
    }

    #[test]
    fn force_binary_keeps_bytes() {
        let s = SecretInput {
            bytes: Zeroizing::new(b"abc".to_vec()),
            origin: SecretOrigin::Value,
        };
        assert_eq!(s.into_value(true), FieldValue::Bytes(b"abc".to_vec()));
    }

    #[test]
    fn oversized_files_are_rejected() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("small");
        std::fs::write(&p, b"hello").expect("write");
        assert_eq!(read_file_capped(&p).expect("read"), b"hello");
        assert!(matches!(
            read_file_capped(&dir.path().join("missing")),
            Err(Error::Io(_))
        ));
        // A sparse file over the cap is refused without being read.
        let big = dir.path().join("big");
        let f = std::fs::File::create(&big).expect("create");
        f.set_len(MAX_INPUT_BYTES as u64 + 1).expect("set_len");
        drop(f);
        match read_file_capped(&big) {
            Err(Error::Invalid(m)) => assert!(m.contains("64 MiB"), "{m}"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_kv_validates() {
        assert_eq!(parse_kv("a=b=c").expect("kv"), ("a".into(), "b=c".into()));
        assert!(matches!(parse_kv("nokv"), Err(Error::Invalid(_))));
        assert!(matches!(parse_kv("bad key=x"), Err(Error::Invalid(_))));
    }
}
