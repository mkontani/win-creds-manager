//! Recovery key: 18 random bytes + 2 checksum bytes, shown as
//! `WCM1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (base32, 8 groups of 4).
//!
//! The canonical display string (uppercase, with dashes) is what gets fed to
//! Argon2id, so the key behaves like a very strong passphrase.

use data_encoding::BASE32_NOPAD;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::aead::random_bytes;
use crate::{Error, Result};

/// Version prefix of the recovery key format.
pub const PREFIX: &str = "WCM1";
const RAW_LEN: usize = 20;
const RANDOM_LEN: usize = 18;
const GROUPS: usize = 8;

/// A parsed/generated recovery key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryKey(Zeroizing<[u8; RAW_LEN]>);

impl RecoveryKey {
    /// Generates a fresh random key.
    pub fn generate() -> RecoveryKey {
        let rnd: [u8; RANDOM_LEN] = random_bytes();
        let mut raw = [0u8; RAW_LEN];
        raw[..RANDOM_LEN].copy_from_slice(&rnd);
        let ck = checksum(&rnd);
        raw[RANDOM_LEN..].copy_from_slice(&ck);
        RecoveryKey(Zeroizing::new(raw))
    }

    /// Canonical human form: `WCM1-XXXX-...` (8 groups).
    pub fn display(&self) -> String {
        let enc = BASE32_NOPAD.encode(&self.0[..]);
        let mut out = String::with_capacity(PREFIX.len() + 1 + enc.len() + GROUPS);
        out.push_str(PREFIX);
        for chunk in enc.as_bytes().chunks(4) {
            out.push('-');
            out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        }
        out
    }

    /// Secret form used as passphrase material (same as [`RecoveryKey::display`]).
    pub fn as_secret(&self) -> SecretString {
        SecretString::from(self.display())
    }

    /// Raw 20 bytes (18 random + 2 checksum).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Parses user input: case-insensitive, dashes/spaces optional, prefix optional.
    pub fn parse(input: &str) -> Result<RecoveryKey> {
        let cleaned: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let body = cleaned.strip_prefix(PREFIX).unwrap_or(&cleaned);
        if body.len() != 32 {
            return Err(Error::Invalid(format!(
                "recovery key must have 32 base32 characters after '{PREFIX}-' (got {})",
                body.len()
            )));
        }
        // Common transcription fixes: base32 has no 0/1/8; map 0→O, 1→I, 8→B.
        let fixed: String = body
            .chars()
            .map(|c| match c {
                '0' => 'O',
                '1' => 'I',
                '8' => 'B',
                c => c,
            })
            .collect();
        let raw = BASE32_NOPAD
            .decode(fixed.as_bytes())
            .map_err(|_| Error::Invalid("recovery key contains invalid characters".into()))?;
        let arr: [u8; RAW_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("recovery key has wrong length".into()))?;
        if checksum(&arr[..RANDOM_LEN]) != arr[RANDOM_LEN..] {
            return Err(Error::Invalid(
                "recovery key checksum mismatch (typo?)".into(),
            ));
        }
        Ok(RecoveryKey(Zeroizing::new(arr)))
    }

    /// Whether `input` even looks like a recovery key (used to auto-detect input type).
    pub fn looks_like(input: &str) -> bool {
        input.trim().to_ascii_uppercase().starts_with(PREFIX)
    }
}

fn checksum(random: &[u8]) -> [u8; 2] {
    let d = Sha256::digest(random);
    [d[0], d[1]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn display_parse_roundtrip() {
        let k = RecoveryKey::generate();
        let s = k.display();
        assert!(s.starts_with("WCM1-"));
        assert_eq!(s.len(), 4 + 8 * 5);
        assert_eq!(s.split('-').count(), 9);
        assert_eq!(RecoveryKey::parse(&s).expect("parse"), k);
        assert_eq!(k.as_secret().expose_secret(), s);
        assert_eq!(k.as_bytes().len(), 20);
        assert!(RecoveryKey::looks_like(&s));
        assert!(!RecoveryKey::looks_like("hunter2"));
    }

    #[test]
    fn parse_is_lenient_about_case_dashes_and_prefix() {
        let k = RecoveryKey::generate();
        let s = k.display();
        let lower = s.to_ascii_lowercase();
        assert_eq!(RecoveryKey::parse(&lower).expect("lower"), k);
        let nodash = s.replace('-', "");
        assert_eq!(RecoveryKey::parse(&nodash).expect("nodash"), k);
        let noprefix = &s[5..];
        assert_eq!(RecoveryKey::parse(noprefix).expect("noprefix"), k);
        let spaced = s.replace('-', " ");
        assert_eq!(
            RecoveryKey::parse(&format!("  {spaced} ")).expect("spaced"),
            k
        );
    }

    #[test]
    fn parse_rejects_typos() {
        let k = RecoveryKey::generate();
        let s = k.display();
        assert!(matches!(
            RecoveryKey::parse("WCM1-ABCD"),
            Err(Error::Invalid(_))
        ));
        let mut chars: Vec<char> = s.chars().collect();
        // flip one body char to a different valid base32 char
        let i = 6;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(matches!(RecoveryKey::parse(&typo), Err(Error::Invalid(_))));
        assert!(matches!(
            RecoveryKey::parse(&s.replace('C', "!")),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn keys_are_unique() {
        assert_ne!(RecoveryKey::generate(), RecoveryKey::generate());
    }
}
