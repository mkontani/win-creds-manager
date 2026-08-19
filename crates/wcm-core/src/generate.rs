//! Password / passphrase generator.

use rand::seq::SliceRandom;
use rand::Rng;

use crate::{Error, Result};

/// Embedded EFF short wordlist (1296 words, CC-BY 3.0 US, eff.org).
pub const WORDLIST: &str = include_str!("eff_short_wordlist.txt");

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}:;,.?/";

/// Generation options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenOptions {
    /// Character-password length (ignored when `words` is set).
    pub length: usize,
    /// Include symbols.
    pub symbols: bool,
    /// If set, generate a passphrase of this many words instead.
    pub words: Option<usize>,
    /// Word separator.
    pub separator: String,
}

impl Default for GenOptions {
    fn default() -> Self {
        GenOptions {
            length: 24,
            symbols: true,
            words: None,
            separator: "-".into(),
        }
    }
}

/// Minimum character-password length.
pub const MIN_LENGTH: usize = 4;
/// Maximum character-password length.
pub const MAX_LENGTH: usize = 1024;
/// Maximum passphrase word count.
pub const MAX_WORDS: usize = 64;

/// Generates a password or passphrase from the OS CSPRNG.
///
/// Character passwords contain at least one lowercase, uppercase and digit
/// (and one symbol when enabled).
pub fn generate(opts: &GenOptions) -> Result<String> {
    let mut rng = rand::rngs::OsRng;
    if let Some(n) = opts.words {
        if n == 0 || n > MAX_WORDS {
            return Err(Error::Invalid(format!(
                "word count must be 1..={MAX_WORDS}"
            )));
        }
        let words: Vec<&str> = WORDLIST
            .lines()
            .map(str::trim)
            .filter(|w| !w.is_empty())
            .collect();
        let picked: Vec<&str> = (0..n)
            .map(|_| *words.choose(&mut rng).unwrap_or(&"word"))
            .collect();
        return Ok(picked.join(&opts.separator));
    }
    if opts.length < MIN_LENGTH || opts.length > MAX_LENGTH {
        return Err(Error::Invalid(format!(
            "length must be {MIN_LENGTH}..={MAX_LENGTH}"
        )));
    }
    let mut classes: Vec<&[u8]> = vec![LOWER, UPPER, DIGITS];
    if opts.symbols {
        classes.push(SYMBOLS);
    }
    let alphabet: Vec<u8> = classes.iter().flat_map(|c| c.iter().copied()).collect();
    let mut out: Vec<u8> = Vec::with_capacity(opts.length);
    for class in &classes {
        out.push(class[rng.gen_range(0..class.len())]);
    }
    while out.len() < opts.length {
        out.push(alphabet[rng.gen_range(0..alphabet.len())]);
    }
    out.shuffle(&mut rng);
    String::from_utf8(out).map_err(|e| Error::Other(format!("generator produced non-utf8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_complete() {
        let words: Vec<&str> = WORDLIST.lines().collect();
        assert_eq!(words.len(), 1296);
        assert!(words
            .iter()
            .all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase() || c == '-')));
    }

    #[test]
    fn character_password_has_all_classes() {
        for _ in 0..20 {
            let p = generate(&GenOptions {
                length: 12,
                symbols: true,
                ..Default::default()
            })
            .expect("gen");
            assert_eq!(p.len(), 12);
            assert!(p.bytes().any(|b| LOWER.contains(&b)));
            assert!(p.bytes().any(|b| UPPER.contains(&b)));
            assert!(p.bytes().any(|b| DIGITS.contains(&b)));
            assert!(p.bytes().any(|b| SYMBOLS.contains(&b)));
        }
        let p = generate(&GenOptions {
            length: 40,
            symbols: false,
            ..Default::default()
        })
        .expect("gen");
        assert_eq!(p.len(), 40);
        assert!(!p.bytes().any(|b| SYMBOLS.contains(&b)));
        assert_ne!(
            generate(&GenOptions::default()).expect("a"),
            generate(&GenOptions::default()).expect("b")
        );
    }

    #[test]
    fn passphrase_mode() {
        let p = generate(&GenOptions {
            words: Some(5),
            separator: " ".into(),
            ..Default::default()
        })
        .expect("gen");
        assert_eq!(p.split(' ').count(), 5);
        assert!(p.split(' ').all(|w| WORDLIST.lines().any(|x| x == w)));
    }

    #[test]
    fn limits() {
        assert!(matches!(
            generate(&GenOptions {
                length: 3,
                ..Default::default()
            }),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            generate(&GenOptions {
                length: 2000,
                ..Default::default()
            }),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            generate(&GenOptions {
                words: Some(0),
                ..Default::default()
            }),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            generate(&GenOptions {
                words: Some(65),
                ..Default::default()
            }),
            Err(Error::Invalid(_))
        ));
    }
}
