//! Thin trait over the five `KeyCredentialManager` operations we use, so the
//! open→create→sign state machine and error mapping can be tested without WinRT.

use wcm_core::Result;

/// Outcome of a KeyCredentialManager call (mirrors `KeyCredentialStatus`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KcmStatus {
    /// Operation succeeded.
    Success,
    /// No credential with that name exists.
    NotFound,
    /// The user dismissed the Windows Hello prompt.
    UserCanceled,
    /// The user chose to use a password instead.
    UserPrefersPassword,
    /// `RequestCreate` with `FailIfExists` found an existing credential.
    CredentialAlreadyExists,
    /// The TPM / security device is locked out.
    SecurityDeviceLocked,
    /// Any other status / HRESULT.
    UnknownError(String),
}

/// Abstraction over the WinRT KeyCredentialManager API.
pub trait KcmApi {
    /// `KeyCredentialManager.IsSupportedAsync()`.
    fn is_supported(&self) -> Result<bool>;
    /// `KeyCredentialManager.OpenAsync(name)` — status only (no prompt).
    fn open(&self, name: &str) -> Result<KcmStatus>;
    /// `KeyCredentialManager.RequestCreateAsync(name, FailIfExists)` — prompts.
    fn create(&self, name: &str) -> Result<KcmStatus>;
    /// `KeyCredential.RequestSignAsync(challenge)` — prompts; returns signature bytes on success.
    fn sign(&self, name: &str, challenge: &[u8]) -> Result<(KcmStatus, Vec<u8>)>;
    /// `KeyCredential.RetrievePublicKeyWithDefaultBlobType()` — X.509 SPKI DER.
    fn public_key(&self, name: &str) -> Result<Vec<u8>>;
    /// `KeyCredential.GetAttestationAsync()` — true when attestation status is Success (TPM-backed).
    fn attest(&self, name: &str) -> Result<bool>;
    /// `KeyCredentialManager.DeleteAsync(name)`.
    fn delete(&self, name: &str) -> Result<()>;
}

/// Scripted fake for tests (available with feature `test-util`).
#[cfg(any(test, feature = "test-util"))]
pub mod fake {
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;
    use sha2::Sha256;

    use super::{KcmApi, KcmStatus};
    use wcm_core::{Error, Result};

    /// In-memory KeyCredentialManager with real RSA keys.
    pub struct FakeKcm {
        /// Value returned by `is_supported`.
        pub supported: bool,
        /// Existing credentials (name → key).
        pub keys: RefCell<HashMap<String, RsaPrivateKey>>,
        /// Status returned by `create` instead of creating (None = create normally).
        pub create_status: Option<KcmStatus>,
        /// Status returned by `sign` instead of signing (None = sign normally).
        pub sign_status: Option<KcmStatus>,
        /// If true, `sign` returns a randomized PSS signature instead of PKCS#1 v1.5.
        pub sign_with_pss: bool,
        /// If true, `attest` reports hardware backing.
        pub hw_backed: bool,
        /// Number of prompts (create + sign) shown.
        pub prompts: Cell<u32>,
        /// Number of `delete` calls.
        pub deletes: Cell<u32>,
    }

    impl FakeKcm {
        /// Fake with Hello supported and no credentials.
        pub fn new() -> Self {
            FakeKcm {
                supported: true,
                keys: RefCell::new(HashMap::new()),
                create_status: None,
                sign_status: None,
                sign_with_pss: false,
                hw_backed: true,
                prompts: Cell::new(0),
                deletes: Cell::new(0),
            }
        }

        /// Fake that already holds a credential named `name`.
        pub fn with_existing(name: &str) -> Self {
            let f = Self::new();
            f.keys.borrow_mut().insert(name.to_string(), gen_key());
            f
        }
    }

    impl Default for FakeKcm {
        fn default() -> Self {
            Self::new()
        }
    }

    fn gen_key() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("rsa keygen")
    }

    impl KcmApi for FakeKcm {
        fn is_supported(&self) -> Result<bool> {
            Ok(self.supported)
        }
        fn open(&self, name: &str) -> Result<KcmStatus> {
            if self.keys.borrow().contains_key(name) {
                Ok(KcmStatus::Success)
            } else {
                Ok(KcmStatus::NotFound)
            }
        }
        fn create(&self, name: &str) -> Result<KcmStatus> {
            self.prompts.set(self.prompts.get() + 1);
            if let Some(s) = &self.create_status {
                return Ok(s.clone());
            }
            if self.keys.borrow().contains_key(name) {
                return Ok(KcmStatus::CredentialAlreadyExists);
            }
            self.keys.borrow_mut().insert(name.to_string(), gen_key());
            Ok(KcmStatus::Success)
        }
        fn sign(&self, name: &str, challenge: &[u8]) -> Result<(KcmStatus, Vec<u8>)> {
            self.prompts.set(self.prompts.get() + 1);
            if let Some(s) = &self.sign_status {
                return Ok((s.clone(), Vec::new()));
            }
            let keys = self.keys.borrow();
            let Some(sk) = keys.get(name) else {
                return Ok((KcmStatus::NotFound, Vec::new()));
            };
            let sig = if self.sign_with_pss {
                use rsa::signature::RandomizedSigner;
                rsa::pss::SigningKey::<Sha256>::new(sk.clone())
                    .sign_with_rng(&mut rand::thread_rng(), challenge)
                    .to_vec()
            } else {
                SigningKey::<Sha256>::new(sk.clone())
                    .sign(challenge)
                    .to_vec()
            };
            Ok((KcmStatus::Success, sig))
        }
        fn public_key(&self, name: &str) -> Result<Vec<u8>> {
            let keys = self.keys.borrow();
            let sk = keys
                .get(name)
                .ok_or_else(|| Error::AuthUnavailable("credential not found".into()))?;
            Ok(sk
                .to_public_key()
                .to_public_key_der()
                .expect("spki")
                .as_bytes()
                .to_vec())
        }
        fn attest(&self, _name: &str) -> Result<bool> {
            Ok(self.hw_backed)
        }
        fn delete(&self, name: &str) -> Result<()> {
            self.deletes.set(self.deletes.get() + 1);
            self.keys.borrow_mut().remove(name);
            Ok(())
        }
    }
}
