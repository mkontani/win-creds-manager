//! Key derivation: HKDF-SHA256 for KEKs, Argon2id for passphrases,
//! and RSASSA-PKCS1-v1_5 verification of Windows Hello signatures.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// HKDF info label for KEKs derived from a Windows Hello signature.
pub const INFO_HELLO: &[u8] = b"wcm/v1/kek/hello";
/// HKDF info label for KEKs derived from a passphrase / recovery key.
pub const INFO_PASSPHRASE: &[u8] = b"wcm/v1/kek/passphrase";
/// Derived key length in bytes.
pub const KEK_LEN: usize = 32;

/// Derives a 32-byte KEK: `HKDF-SHA256(ikm, salt, info = label || vault_id)`.
pub fn derive_kek(
    ikm: &[u8],
    salt: &[u8; 32],
    info_label: &[u8],
    vault_id: &[u8; 16],
) -> Zeroizing<[u8; KEK_LEN]> {
    let mut info = Vec::with_capacity(info_label.len() + vault_id.len());
    info.extend_from_slice(info_label);
    info.extend_from_slice(vault_id);
    let mut kek = Zeroizing::new([0u8; KEK_LEN]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(&info, kek.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    kek
}

/// Argon2id cost parameters (stored in the key slot so they can be upgraded later).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

impl Argon2Params {
    /// Production default: 64 MiB, 3 passes, 1 lane.
    pub const DEFAULT: Self = Self {
        m_kib: 65536,
        t: 3,
        p: 1,
    };
    /// Tiny parameters for unit/integration tests only.
    pub const FAST_TEST: Self = Self {
        m_kib: 64,
        t: 1,
        p: 1,
    };
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Argon2id(secret, salt) → 32 bytes of input keying material.
pub fn argon2id(
    secret: &[u8],
    salt: &[u8; 32],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>> {
    let p = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| Error::Invalid(format!("invalid argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(secret, salt, out.as_mut())
        .map_err(|e| Error::Other(format!("argon2 failed: {e}")))?;
    Ok(out)
}

/// Verifies that `sig` is the RSASSA-PKCS1-v1_5/SHA-256 signature of `challenge`
/// under the RSA public key `spki_der` (X.509 SubjectPublicKeyInfo, DER).
///
/// PKCS#1 v1.5 signatures are deterministic, so a successful verification also
/// proves the signature is the unique value Windows Hello will return again.
/// A randomized (PSS) or otherwise different signature fails closed with
/// [`Error::Integrity`] and must never be fed into a KDF.
pub fn verify_hello_signature(spki_der: &[u8], challenge: &[u8; 32], sig: &[u8]) -> Result<()> {
    let pk = RsaPublicKey::from_public_key_der(spki_der)
        .map_err(|e| Error::Integrity(format!("stored Hello public key is malformed: {e}")))?;
    let vk = VerifyingKey::<Sha256>::new(pk);
    let s = Signature::try_from(sig)
        .map_err(|e| Error::Integrity(format!("Hello signature malformed: {e}")))?;
    vk.verify(challenge, &s).map_err(|_| {
        Error::Integrity(
            "Windows Hello signature did not verify (unexpected padding or key)".into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;

    #[test]
    fn derive_kek_is_deterministic_and_domain_separated() {
        let salt = [7u8; 32];
        let vid = [9u8; 16];
        let a = derive_kek(b"ikm", &salt, INFO_HELLO, &vid);
        let b = derive_kek(b"ikm", &salt, INFO_HELLO, &vid);
        assert_eq!(*a, *b);
        assert_ne!(*a, *derive_kek(b"ikm", &salt, INFO_PASSPHRASE, &vid));
        assert_ne!(*a, *derive_kek(b"ikm", &[8u8; 32], INFO_HELLO, &vid));
        assert_ne!(*a, *derive_kek(b"ikm", &salt, INFO_HELLO, &[1u8; 16]));
        assert_ne!(*a, *derive_kek(b"ikm2", &salt, INFO_HELLO, &vid));
    }

    #[test]
    fn derive_kek_matches_known_vector() {
        // Pin the derivation so a silent change of label/salt handling is caught.
        let kek = derive_kek(b"ikm", &[0u8; 32], INFO_HELLO, &[0u8; 16]);
        let hex: String = kek.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex.len(), 64);
        // Regenerate with: derive_kek(b"ikm", &[0;32], INFO_HELLO, &[0;16])
        assert_eq!(hex, EXPECTED_KEK_HEX);
    }

    const EXPECTED_KEK_HEX: &str =
        "5a9321816d17ea0bc5fa6269162a1d90568e3d151746bc39aee1f527c5e20262";

    #[test]
    fn argon2id_deterministic_for_same_inputs() {
        let a = argon2id(b"pw", &[1u8; 32], Argon2Params::FAST_TEST).expect("argon2");
        let b = argon2id(b"pw", &[1u8; 32], Argon2Params::FAST_TEST).expect("argon2");
        assert_eq!(*a, *b);
        assert_ne!(
            *a,
            *argon2id(b"pw2", &[1u8; 32], Argon2Params::FAST_TEST).expect("argon2")
        );
    }

    #[test]
    fn argon2id_rejects_invalid_params() {
        let bad = Argon2Params {
            m_kib: 1,
            t: 0,
            p: 0,
        };
        assert!(matches!(
            argon2id(b"pw", &[1u8; 32], bad),
            Err(Error::Invalid(_))
        ));
    }

    fn test_key() -> (RsaPrivateKey, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let sk = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let spki = sk
            .to_public_key()
            .to_public_key_der()
            .expect("spki")
            .as_bytes()
            .to_vec();
        (sk, spki)
    }

    #[test]
    fn verify_accepts_pkcs1v15_and_rejects_pss_and_tampering() {
        let (sk, spki) = test_key();
        let challenge = [0x42u8; 32];

        let sig = SigningKey::<Sha256>::new(sk.clone())
            .sign(&challenge)
            .to_vec();
        assert_eq!(sig.len(), 256);
        verify_hello_signature(&spki, &challenge, &sig).expect("pkcs1v15 verifies");
        // deterministic: signing again yields identical bytes
        assert_eq!(
            sig,
            SigningKey::<Sha256>::new(sk.clone())
                .sign(&challenge)
                .to_vec()
        );

        let mut tampered = sig.clone();
        tampered[10] ^= 0xff;
        assert!(matches!(
            verify_hello_signature(&spki, &challenge, &tampered),
            Err(Error::Integrity(_))
        ));
        assert!(matches!(
            verify_hello_signature(&spki, &[0u8; 32], &sig),
            Err(Error::Integrity(_))
        ));

        let pss = rsa::pss::SigningKey::<Sha256>::new(sk)
            .sign_with_rng(&mut rand::thread_rng(), &challenge)
            .to_vec();
        assert!(matches!(
            verify_hello_signature(&spki, &challenge, &pss),
            Err(Error::Integrity(_))
        ));

        assert!(matches!(
            verify_hello_signature(b"not-der", &challenge, &sig),
            Err(Error::Integrity(_))
        ));
        assert!(matches!(
            verify_hello_signature(&spki, &challenge, b"short"),
            Err(Error::Integrity(_))
        ));
    }
}
