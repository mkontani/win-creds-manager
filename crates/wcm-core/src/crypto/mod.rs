//! Cryptographic primitives used by the vault format.
//!
//! All algorithms are fixed for format v1:
//! - AEAD: XChaCha20-Poly1305 (24-byte nonce)
//! - KDF: HKDF-SHA256 (KEK), Argon2id (passphrase → ikm)
//! - Hello signature verification: RSASSA-PKCS1-v1_5 / SHA-256

pub mod aead;
pub mod kdf;
