//! XChaCha20-Poly1305 seal/open and CSPRNG helpers.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// AEAD key length in bytes.
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Encrypts `plaintext` under `key`/`nonce`, binding `aad`. Returns ciphertext || tag.
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Integrity("AEAD encryption failed".into()))
}

/// Decrypts and authenticates `ciphertext` (ciphertext || tag) under `key`/`nonce`/`aad`.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| {
            Error::Integrity("AEAD authentication failed (wrong key or tampered data)".into())
        })
}

/// Fresh random nonce from the OS CSPRNG.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    random_bytes()
}

/// Fresh random 256-bit key from the OS CSPRNG.
pub fn random_key() -> Zeroizing<[u8; KEY_LEN]> {
    Zeroizing::new(random_bytes())
}

/// `N` random bytes from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

/// Converts a slice into a fixed-size array, reporting a format error on length mismatch.
pub fn to_array<const N: usize>(what: &str, bytes: &[u8]) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| Error::Integrity(format!("{what}: expected {N} bytes, got {}", bytes.len())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = random_key();
        let nonce = random_nonce();
        let ct = seal(&key, &nonce, b"aad", b"hello world").expect("seal");
        assert_eq!(ct.len(), 11 + TAG_LEN);
        let pt = open(&key, &nonce, b"aad", &ct).expect("open");
        assert_eq!(&pt[..], b"hello world");
    }

    #[test]
    fn open_rejects_tampered_aad_ciphertext_and_wrong_key() {
        let key = random_key();
        let nonce = random_nonce();
        let ct = seal(&key, &nonce, b"aad", b"secret").expect("seal");

        assert!(matches!(
            open(&key, &nonce, b"AAD", &ct),
            Err(Error::Integrity(_))
        ));

        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(matches!(
            open(&key, &nonce, b"aad", &bad),
            Err(Error::Integrity(_))
        ));

        let other = random_key();
        assert!(matches!(
            open(&other, &nonce, b"aad", &ct),
            Err(Error::Integrity(_))
        ));
    }

    #[test]
    fn random_helpers_are_not_constant() {
        assert_ne!(random_nonce(), random_nonce());
        assert_ne!(*random_key(), *random_key());
        let a: [u8; 16] = random_bytes();
        let b: [u8; 16] = random_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn to_array_checks_length() {
        assert!(to_array::<4>("x", &[1, 2, 3, 4]).is_ok());
        assert!(matches!(
            to_array::<4>("x", &[1, 2, 3]),
            Err(Error::Integrity(_))
        ));
    }
}
