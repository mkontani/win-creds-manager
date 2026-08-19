//! Key slots: each slot wraps the vault's Data Encryption Key (DEK) under a
//! Key Encryption Key (KEK) derived from backend-provided input keying material.
//!
//! Backends ([`KeySlotBackend`]) only produce *ikm*; HKDF and AEAD wrapping
//! are performed here so the wrap/unwrap path is fully testable on any OS.

#[cfg(any(test, feature = "test-util"))]
pub mod mock;
pub mod passphrase;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::aead::{self, KEY_LEN, NONCE_LEN};
use crate::crypto::kdf::{self, Argon2Params};
use crate::{Error, Result};

/// The vault's data encryption key.
pub type Dek = Zeroizing<[u8; KEY_LEN]>;

/// Kind of key slot; the numeric value is part of the slot AAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SlotKind {
    /// Windows Hello (KeyCredentialManager) signature-derived KEK.
    Hello = 1,
    /// Argon2id passphrase / recovery-key derived KEK.
    Passphrase = 2,
}

impl SlotKind {
    /// Human-readable name.
    pub fn as_str(&self) -> &'static str {
        match self {
            SlotKind::Hello => "hello",
            SlotKind::Passphrase => "passphrase",
        }
    }
}

/// Backend-specific parameters stored (in plaintext) with a slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SlotParams {
    /// Windows Hello slot.
    Hello {
        /// KeyCredentialManager credential name (`wcm-v1-<vault_id hex>`).
        cred_name: String,
        /// Fixed 32-byte challenge signed on every unlock.
        #[serde(with = "serde_bytes")]
        challenge: Vec<u8>,
        /// SubjectPublicKeyInfo (DER) of the Hello key, used to verify signatures.
        #[serde(with = "serde_bytes")]
        spki_der: Vec<u8>,
        /// Whether `ct` is additionally wrapped with DPAPI.
        dpapi: bool,
        /// Whether attestation reported a hardware (TPM) backed key.
        hw_backed: bool,
    },
    /// Passphrase / recovery-key slot.
    Passphrase {
        /// Argon2id parameters.
        argon2: Argon2Params,
    },
}

impl SlotParams {
    /// Kind implied by the params variant.
    pub fn kind(&self) -> SlotKind {
        match self {
            SlotParams::Hello { .. } => SlotKind::Hello,
            SlotParams::Passphrase { .. } => SlotKind::Passphrase,
        }
    }
}

/// One wrapped copy of the DEK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySlot {
    /// Slot id (unique within a vault).
    pub id: u8,
    /// Human label: "hello", "recovery", "passphrase", ...
    pub label: String,
    /// 32-byte HKDF salt (also the Argon2 salt for passphrase slots).
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
    /// 24-byte AEAD nonce for the wrapped DEK.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// Wrapped DEK (48 bytes) — possibly further enveloped (DPAPI).
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
    /// Backend parameters.
    pub params: SlotParams,
}

impl KeySlot {
    /// Slot kind.
    pub fn kind(&self) -> SlotKind {
        self.params.kind()
    }
}

/// Whether a backend can currently be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Availability {
    /// Ready to enroll/open.
    Available,
    /// Backend works but the user has not enrolled (e.g. no Hello PIN).
    NotEnrolled,
    /// Backend cannot work on this machine/build.
    Unsupported(String),
    /// Running without an interactive desktop session (session 0 / SSH).
    NoInteractiveSession,
}

/// User-interaction hooks provided by the front-end (CLI, GUI, tests).
pub trait Prompter {
    /// Ask for a secret (passphrase, recovery key). Must not echo.
    fn secret(&self, label: &str) -> Result<SecretString>;
    /// Ask a yes/no question.
    fn confirm(&self, msg: &str) -> Result<bool>;
    /// Show an informational message (stderr / dialog).
    fn notice(&self, msg: &str);
}

/// Context passed to backends for enroll/open.
pub struct UnlockContext<'a> {
    /// Vault id (binds slots to the vault).
    pub vault_id: [u8; 16],
    /// Human-readable reason shown in prompts.
    pub reason: &'a str,
    /// Interaction hooks.
    pub prompter: &'a dyn Prompter,
    /// Whether UI prompts may be shown at all.
    pub allow_ui: bool,
}

/// A source of input keying material for one slot kind.
pub trait KeySlotBackend {
    /// Slot kind produced by this backend.
    fn kind(&self) -> SlotKind;
    /// Current availability.
    fn availability(&self) -> Availability;
    /// Create any external state (e.g. a Hello credential) and return `(params, ikm)`.
    fn enroll(&self, ctx: &UnlockContext) -> Result<(SlotParams, Zeroizing<Vec<u8>>)>;
    /// Re-derive the ikm for an existing slot. May prompt.
    fn open(&self, ctx: &UnlockContext, params: &SlotParams) -> Result<Zeroizing<Vec<u8>>>;
    /// Remove external state. No-op for passphrase slots.
    fn destroy(&self, params: &SlotParams) -> Result<()>;
}

/// Optional extra envelope around the wrapped DEK (DPAPI on Windows).
pub trait Envelope {
    /// Protects `data` (applied *after* AEAD wrapping).
    fn protect(&self, vault_id: &[u8; 16], data: &[u8]) -> Result<Vec<u8>>;
    /// Reverses [`Envelope::protect`].
    fn unprotect(&self, vault_id: &[u8; 16], data: &[u8]) -> Result<Vec<u8>>;
}

/// Envelope that does nothing (non-Windows, recovery slots).
pub struct IdentityEnvelope;

impl Envelope for IdentityEnvelope {
    fn protect(&self, _vault_id: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    fn unprotect(&self, _vault_id: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
}

/// AAD binding a wrapped DEK to its vault, slot id and slot kind.
pub fn slot_aad(vault_id: &[u8; 16], id: u8, kind: SlotKind) -> Vec<u8> {
    let mut aad = Vec::with_capacity(11 + 16 + 2);
    aad.extend_from_slice(b"wcm/v1/slot");
    aad.extend_from_slice(vault_id);
    aad.push(id);
    aad.push(kind as u8);
    aad
}

fn info_label(kind: SlotKind) -> &'static [u8] {
    match kind {
        SlotKind::Hello => kdf::INFO_HELLO,
        SlotKind::Passphrase => kdf::INFO_PASSPHRASE,
    }
}

/// Enrolls `backend`, derives a KEK and wraps `dek` into a new [`KeySlot`].
pub fn seal_slot(
    id: u8,
    label: &str,
    backend: &dyn KeySlotBackend,
    envelope: &dyn Envelope,
    ctx: &UnlockContext,
    dek: &Dek,
) -> Result<KeySlot> {
    let salt: [u8; 32] = aead::random_bytes();
    let (params, ikm) = enroll_with_salt(backend, ctx, &salt)?;
    let kind = params.kind();
    let kek = kdf::derive_kek(&ikm, &salt, info_label(kind), &ctx.vault_id);
    let nonce = aead::random_nonce();
    let wrapped = aead::seal(
        &kek,
        &nonce,
        &slot_aad(&ctx.vault_id, id, kind),
        dek.as_ref(),
    )?;
    let ct = envelope.protect(&ctx.vault_id, &wrapped)?;
    Ok(KeySlot {
        id,
        label: label.to_string(),
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        ct,
        params,
    })
}

/// Opens `slot` with `backend` and returns the DEK.
pub fn open_slot(
    slot: &KeySlot,
    backend: &dyn KeySlotBackend,
    envelope: &dyn Envelope,
    ctx: &UnlockContext,
) -> Result<Dek> {
    if backend.kind() != slot.kind() {
        return Err(Error::Invalid(format!(
            "backend kind {:?} cannot open a {:?} slot",
            backend.kind(),
            slot.kind()
        )));
    }
    let salt: [u8; 32] = aead::to_array("slot salt", &slot.salt)?;
    let nonce: [u8; NONCE_LEN] = aead::to_array("slot nonce", &slot.nonce)?;
    let ikm = open_with_salt(backend, ctx, &slot.params, &salt)?;
    let kek = kdf::derive_kek(&ikm, &salt, info_label(slot.kind()), &ctx.vault_id);
    let wrapped = envelope.unprotect(&ctx.vault_id, &slot.ct)?;
    let dek_bytes = aead::open(
        &kek,
        &nonce,
        &slot_aad(&ctx.vault_id, slot.id, slot.kind()),
        &wrapped,
    )?;
    let dek: [u8; KEY_LEN] = aead::to_array("unwrapped DEK", &dek_bytes)?;
    Ok(Zeroizing::new(dek))
}

// Passphrase backends need the slot salt as their Argon2 salt. To keep the
// backend trait uniform, the salt is passed through a thread-local set only
// for the duration of the enroll/open call.
thread_local! {
    static CURRENT_SALT: std::cell::Cell<Option<[u8; 32]>> = const { std::cell::Cell::new(None) };
}

/// Returns the salt of the slot currently being sealed/opened on this thread.
pub(crate) fn current_salt() -> Option<[u8; 32]> {
    CURRENT_SALT.with(|c| c.get())
}

fn enroll_with_salt(
    backend: &dyn KeySlotBackend,
    ctx: &UnlockContext,
    salt: &[u8; 32],
) -> Result<(SlotParams, Zeroizing<Vec<u8>>)> {
    CURRENT_SALT.with(|c| c.set(Some(*salt)));
    let r = backend.enroll(ctx);
    CURRENT_SALT.with(|c| c.set(None));
    r
}

fn open_with_salt(
    backend: &dyn KeySlotBackend,
    ctx: &UnlockContext,
    params: &SlotParams,
    salt: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>> {
    CURRENT_SALT.with(|c| c.set(Some(*salt)));
    let r = backend.open(ctx, params);
    CURRENT_SALT.with(|c| c.set(None));
    r
}

#[cfg(test)]
mod tests {
    use super::mock::{MockBackend, TestPrompter};
    use super::*;

    fn ctx<'a>(p: &'a TestPrompter) -> UnlockContext<'a> {
        UnlockContext {
            vault_id: [3u8; 16],
            reason: "test",
            prompter: p,
            allow_ui: true,
        }
    }

    #[test]
    fn seal_then_open_returns_same_dek() {
        let p = TestPrompter::default();
        let c = ctx(&p);
        let backend = MockBackend::hello(b"ikm-bytes".to_vec());
        let dek: Dek = aead::random_key();
        let slot = seal_slot(1, "hello", &backend, &IdentityEnvelope, &c, &dek).expect("seal");
        assert_eq!(slot.id, 1);
        assert_eq!(slot.kind(), SlotKind::Hello);
        assert_eq!(slot.salt.len(), 32);
        assert_eq!(slot.nonce.len(), 24);
        assert_eq!(slot.ct.len(), 48);
        let opened = open_slot(&slot, &backend, &IdentityEnvelope, &c).expect("open");
        assert_eq!(*opened, *dek);
    }

    #[test]
    fn wrong_ikm_fails_with_integrity() {
        let p = TestPrompter::default();
        let c = ctx(&p);
        let dek: Dek = aead::random_key();
        let slot = seal_slot(
            1,
            "hello",
            &MockBackend::hello(b"a".to_vec()),
            &IdentityEnvelope,
            &c,
            &dek,
        )
        .expect("seal");
        let r = open_slot(
            &slot,
            &MockBackend::hello(b"b".to_vec()),
            &IdentityEnvelope,
            &c,
        );
        assert!(matches!(r, Err(Error::Integrity(_))));
    }

    #[test]
    fn slot_aad_binds_vault_id_slot_id_and_kind() {
        let p = TestPrompter::default();
        let c = ctx(&p);
        let backend = MockBackend::hello(b"a".to_vec());
        let dek: Dek = aead::random_key();
        let slot = seal_slot(1, "hello", &backend, &IdentityEnvelope, &c, &dek).expect("seal");

        let mut moved = slot.clone();
        moved.id = 2;
        assert!(matches!(
            open_slot(&moved, &backend, &IdentityEnvelope, &c),
            Err(Error::Integrity(_))
        ));

        let other_vault = UnlockContext {
            vault_id: [4u8; 16],
            ..ctx(&p)
        };
        assert!(matches!(
            open_slot(&slot, &backend, &IdentityEnvelope, &other_vault),
            Err(Error::Integrity(_))
        ));

        let aad = slot_aad(&[3u8; 16], 1, SlotKind::Hello);
        assert_eq!(&aad[..11], b"wcm/v1/slot");
        assert_eq!(aad[27], 1);
        assert_eq!(aad[28], SlotKind::Hello as u8);
    }

    #[test]
    fn kind_mismatch_is_rejected() {
        let p = TestPrompter::default();
        let c = ctx(&p);
        let dek: Dek = aead::random_key();
        let slot = seal_slot(
            1,
            "hello",
            &MockBackend::hello(b"a".to_vec()),
            &IdentityEnvelope,
            &c,
            &dek,
        )
        .expect("seal");
        let pass = MockBackend::passphrase(b"a".to_vec());
        assert!(matches!(
            open_slot(&slot, &pass, &IdentityEnvelope, &c),
            Err(Error::Invalid(_))
        ));
    }

    struct XorEnvelope;
    impl Envelope for XorEnvelope {
        fn protect(&self, _v: &[u8; 16], d: &[u8]) -> Result<Vec<u8>> {
            Ok(d.iter().map(|b| b ^ 0x5a).collect())
        }
        fn unprotect(&self, _v: &[u8; 16], d: &[u8]) -> Result<Vec<u8>> {
            Ok(d.iter().map(|b| b ^ 0x5a).collect())
        }
    }

    #[test]
    fn envelope_is_applied_outside_the_aead_layer() {
        let p = TestPrompter::default();
        let c = ctx(&p);
        let backend = MockBackend::hello(b"a".to_vec());
        let dek: Dek = aead::random_key();
        let slot = seal_slot(1, "hello", &backend, &XorEnvelope, &c, &dek).expect("seal");
        // Without the envelope the AEAD layer must reject the ciphertext.
        assert!(matches!(
            open_slot(&slot, &backend, &IdentityEnvelope, &c),
            Err(Error::Integrity(_))
        ));
        assert_eq!(
            *open_slot(&slot, &backend, &XorEnvelope, &c).expect("open"),
            *dek
        );
    }

    #[test]
    fn slot_params_serde_roundtrip_uses_byte_strings() {
        let params = SlotParams::Hello {
            cred_name: "wcm-v1-00".into(),
            challenge: vec![1u8; 32],
            spki_der: vec![2u8; 10],
            dpapi: true,
            hw_backed: false,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&params, &mut buf).expect("cbor");
        // A CBOR byte string of 32 bytes is encoded as 0x58 0x20 followed by the data
        // (an int array would be 0x98 0x20 ...). Ensure `serde_bytes` produced a bstr.
        let mut needle = vec![0x58u8, 0x20];
        needle.extend(std::iter::repeat_n(1u8, 32));
        assert!(
            buf.windows(needle.len()).any(|w| w == needle.as_slice()),
            "challenge not encoded as bstr"
        );
        let back: SlotParams = ciborium::from_reader(&buf[..]).expect("decode");
        assert_eq!(back, params);
    }
}
