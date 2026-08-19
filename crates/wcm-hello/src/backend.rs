//! `HelloBackend`: KeySlotBackend that derives ikm from a Windows Hello signature.
//!
//! Flow (enroll): `open(name)` → `create` when NotFound → `sign(challenge)` →
//! verify against SPKI → ikm = signature. Flow (open): `open` → `sign` → verify.
//! Only [`KcmApi`] touches WinRT, so the whole state machine is unit-tested
//! with [`crate::kcm_api::fake::FakeKcm`].

use std::time::Duration;

use wcm_core::crypto::aead::random_bytes;
use wcm_core::crypto::kdf::verify_hello_signature;
use wcm_core::slot::{Availability, KeySlotBackend, SlotKind, SlotParams, UnlockContext};
use wcm_core::{Error, Result};
use zeroize::Zeroizing;

use crate::focus::FocusGuard;
use crate::kcm_api::{KcmApi, KcmStatus};

/// KeyCredentialManager credential name for a vault: `wcm-v1-<32 hex>`.
pub fn cred_name(vault_id: &[u8; 16]) -> String {
    let hex: String = vault_id.iter().map(|b| format!("{b:02x}")).collect();
    format!("wcm-v1-{hex}")
}

/// HRESULTs (as they appear in error messages) that are worth one retry.
const TRANSIENT_HRESULTS: [&str; 4] = ["0x8028008B", "0x80280095", "0x80280159", "0x80098046"];
const RETRY_DELAY: Duration = Duration::from_millis(500);

/// Windows Hello key-slot backend.
pub struct HelloBackend<K: KcmApi> {
    /// WinRT (or fake) API.
    pub api: K,
    /// Whether `enroll` may create a new credential (false for plain unlocks).
    pub allow_create: bool,
    /// Whether the process runs in an interactive desktop session.
    pub session_interactive: bool,
    /// Whether to record `dpapi: true` in the slot params (the envelope is applied by core).
    pub dpapi: bool,
    /// Whether to run the foreground-focus helper while prompting.
    pub focus: bool,
}

impl<K: KcmApi> HelloBackend<K> {
    /// New backend.
    pub fn new(api: K) -> Self {
        HelloBackend {
            api,
            allow_create: true,
            session_interactive: true,
            dpapi: true,
            focus: true,
        }
    }

    fn check_session(&self, ctx: &UnlockContext) -> Result<()> {
        if !self.session_interactive {
            return Err(Error::AuthUnavailable(
                "no interactive Windows desktop session (session 0 / SSH): Windows Hello cannot prompt".into(),
            ));
        }
        if !ctx.allow_ui {
            return Err(Error::AuthUnavailable(
                "Windows Hello requires a prompt but prompting is disabled (--no-input)".into(),
            ));
        }
        Ok(())
    }

    fn with_retry<T>(&self, mut f: impl FnMut() -> Result<T>) -> Result<T> {
        match f() {
            Err(e) if is_transient(&e) => {
                std::thread::sleep(RETRY_DELAY);
                f()
            }
            r => r,
        }
    }

    fn map_status(status: &KcmStatus, what: &str) -> Result<()> {
        match status {
            KcmStatus::Success => Ok(()),
            KcmStatus::UserCanceled | KcmStatus::UserPrefersPassword => Err(Error::AuthCancelled),
            KcmStatus::NotFound => Err(Error::AuthUnavailable(
                "Windows Hello key for this vault is gone (PIN reset or profile change?)".into(),
            )),
            KcmStatus::SecurityDeviceLocked => Err(Error::AuthUnavailable(
                "the TPM / security device is locked out; wait and try again".into(),
            )),
            KcmStatus::CredentialAlreadyExists => Err(Error::AuthUnavailable(format!(
                "{what}: credential already exists"
            ))),
            KcmStatus::UnknownError(msg) => Err(Error::AuthUnavailable(format!("{what}: {msg}"))),
        }
    }

    /// Opens the credential, creating it when allowed. Returns `true` if created.
    fn open_or_create(&self, ctx: &UnlockContext, name: &str) -> Result<bool> {
        match self.api.open(name)? {
            KcmStatus::Success => return Ok(false),
            KcmStatus::NotFound if self.allow_create => {}
            status => return Self::map_status(&status, "OpenAsync").map(|_| false),
        }
        ctx.prompter.notice(
            "Windows Hello: creating a new key for this vault — confirm with your PIN/biometric…",
        );
        let _focus = FocusGuard::start(self.focus);
        let status = self.with_retry(|| self.api.create(name))?;
        match status {
            KcmStatus::Success => Ok(true),
            KcmStatus::CredentialAlreadyExists => Ok(false),
            other => Self::map_status(&other, "RequestCreateAsync").map(|_| false),
        }
    }

    fn sign_verified(
        &self,
        ctx: &UnlockContext,
        name: &str,
        challenge: &[u8; 32],
        spki_der: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        ctx.prompter
            .notice("Windows Hello: waiting for your PIN/biometric…");
        let _focus = FocusGuard::start(self.focus);
        let (status, sig) = self.with_retry(|| self.api.sign(name, challenge))?;
        Self::map_status(&status, "RequestSignAsync")?;
        let sig = Zeroizing::new(sig);
        verify_hello_signature(spki_der, challenge, &sig)?;
        Ok(sig)
    }
}

fn is_transient(e: &Error) -> bool {
    let msg = e.to_string();
    TRANSIENT_HRESULTS.iter().any(|h| msg.contains(h))
}

impl<K: KcmApi> KeySlotBackend for HelloBackend<K> {
    fn kind(&self) -> SlotKind {
        SlotKind::Hello
    }

    fn availability(&self) -> Availability {
        if !self.session_interactive {
            return Availability::NoInteractiveSession;
        }
        match self.api.is_supported() {
            Ok(true) => Availability::Available,
            Ok(false) => Availability::NotEnrolled,
            Err(e) => Availability::Unsupported(e.to_string()),
        }
    }

    fn enroll(&self, ctx: &UnlockContext) -> Result<(SlotParams, Zeroizing<Vec<u8>>)> {
        self.check_session(ctx)?;
        if !self.api.is_supported()? {
            return Err(Error::AuthUnavailable(
                "Windows Hello is not set up on this machine (add a PIN under Settings > Accounts > Sign-in options)".into(),
            ));
        }
        let name = cred_name(&ctx.vault_id);
        let created = self.open_or_create(ctx, &name)?;
        if !created {
            ctx.prompter
                .notice(&format!("Windows Hello: reusing existing key '{name}'"));
        }
        let challenge: [u8; 32] = random_bytes();
        let spki_der = self.api.public_key(&name)?;
        let ikm = self.sign_verified(ctx, &name, &challenge, &spki_der)?;
        let hw_backed = self.api.attest(&name).unwrap_or(false);
        Ok((
            SlotParams::Hello {
                cred_name: name,
                challenge: challenge.to_vec(),
                spki_der,
                dpapi: self.dpapi,
                hw_backed,
            },
            ikm,
        ))
    }

    fn open(&self, ctx: &UnlockContext, params: &SlotParams) -> Result<Zeroizing<Vec<u8>>> {
        let SlotParams::Hello {
            cred_name: name,
            challenge,
            spki_der,
            ..
        } = params
        else {
            return Err(Error::Invalid(
                "Hello backend given non-Hello slot params".into(),
            ));
        };
        self.check_session(ctx)?;
        let challenge: [u8; 32] = challenge
            .as_slice()
            .try_into()
            .map_err(|_| Error::Integrity("Hello slot challenge must be 32 bytes".into()))?;
        match self.api.open(name)? {
            KcmStatus::Success => {}
            status => {
                return Self::map_status(&status, "OpenAsync").map(|_| Zeroizing::new(Vec::new()))
            }
        }
        self.sign_verified(ctx, name, &challenge, spki_der)
    }

    fn destroy(&self, params: &SlotParams) -> Result<()> {
        let SlotParams::Hello {
            cred_name: name, ..
        } = params
        else {
            return Ok(());
        };
        self.api.delete(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kcm_api::fake::FakeKcm;
    use wcm_core::crypto::aead::random_key;
    use wcm_core::slot::mock::TestPrompter;
    use wcm_core::slot::{open_slot, seal_slot, Dek, IdentityEnvelope};

    const VID: [u8; 16] = [7u8; 16];

    fn ctx<'a>(p: &'a TestPrompter, allow_ui: bool) -> UnlockContext<'a> {
        UnlockContext {
            vault_id: VID,
            reason: "t",
            prompter: p,
            allow_ui,
        }
    }

    fn backend(api: FakeKcm) -> HelloBackend<FakeKcm> {
        let mut b = HelloBackend::new(api);
        b.focus = false;
        b
    }

    #[test]
    fn cred_name_format() {
        let n = cred_name(&VID);
        assert_eq!(n, format!("wcm-v1-{}", "07".repeat(16)));
        assert!(!n.contains('/'));
    }

    #[test]
    fn enroll_creates_key_signs_and_open_roundtrips() {
        let p = TestPrompter::default();
        let c = ctx(&p, true);
        let b = backend(FakeKcm::new());
        let dek: Dek = random_key();
        let slot = seal_slot(1, "hello", &b, &IdentityEnvelope, &c, &dek).expect("seal");
        assert_eq!(slot.kind(), SlotKind::Hello);
        let SlotParams::Hello {
            cred_name: name,
            challenge,
            spki_der,
            dpapi,
            hw_backed,
        } = &slot.params
        else {
            panic!("expected hello params");
        };
        assert_eq!(name, &cred_name(&VID));
        assert_eq!(challenge.len(), 32);
        assert!(!spki_der.is_empty());
        assert!(*dpapi);
        assert!(*hw_backed);
        assert_eq!(b.api.prompts.get(), 2, "create + sign");

        // Open: one prompt (sign only), same DEK.
        let opened = open_slot(&slot, &b, &IdentityEnvelope, &c).expect("open");
        assert_eq!(*opened, *dek);
        assert_eq!(b.api.prompts.get(), 3);
        assert!(p
            .notices
            .borrow()
            .iter()
            .any(|n| n.contains("Windows Hello")));
    }

    #[test]
    fn enroll_reuses_existing_credential_without_create_prompt() {
        let p = TestPrompter::default();
        let c = ctx(&p, true);
        let b = backend(FakeKcm::with_existing(&cred_name(&VID)));
        let dek: Dek = random_key();
        let _ = seal_slot(1, "hello", &b, &IdentityEnvelope, &c, &dek).expect("seal");
        assert_eq!(b.api.prompts.get(), 1, "sign only");
        assert!(p.notices.borrow().iter().any(|n| n.contains("reusing")));
    }

    #[test]
    fn open_without_key_is_auth_unavailable_and_never_creates() {
        let p = TestPrompter::default();
        let c = ctx(&p, true);
        let enroll = backend(FakeKcm::new());
        let dek: Dek = random_key();
        let slot = seal_slot(1, "hello", &enroll, &IdentityEnvelope, &c, &dek).expect("seal");

        let mut fresh = backend(FakeKcm::new()); // no keys: simulates PIN reset
        fresh.allow_create = false;
        let err = open_slot(&slot, &fresh, &IdentityEnvelope, &c).expect_err("gone");
        assert!(
            matches!(err, Error::AuthUnavailable(ref m) if m.contains("gone")),
            "{err:?}"
        );
        assert_eq!(fresh.api.prompts.get(), 0);
        assert!(fresh.api.keys.borrow().is_empty());
    }

    #[test]
    fn user_cancel_maps_to_auth_cancelled() {
        let p = TestPrompter::default();
        let c = ctx(&p, true);
        let mut api = FakeKcm::with_existing(&cred_name(&VID));
        api.sign_status = Some(KcmStatus::UserCanceled);
        let b = backend(api);
        let dek: Dek = random_key();
        assert!(matches!(
            seal_slot(1, "hello", &b, &IdentityEnvelope, &c, &dek),
            Err(Error::AuthCancelled)
        ));

        let mut api = FakeKcm::new();
        api.create_status = Some(KcmStatus::UserCanceled);
        let b = backend(api);
        assert!(matches!(
            seal_slot(1, "hello", &b, &IdentityEnvelope, &c, &dek),
            Err(Error::AuthCancelled)
        ));
    }

    #[test]
    fn device_locked_and_unknown_map_to_auth_unavailable() {
        let p = TestPrompter::default();
        let c = ctx(&p, true);
        let dek: Dek = random_key();
        let mut api = FakeKcm::with_existing(&cred_name(&VID));
        api.sign_status = Some(KcmStatus::SecurityDeviceLocked);
        let b = backend(api);
        assert!(matches!(
            seal_slot(1, "hello", &b, &IdentityEnvelope, &c, &dek),
            Err(Error::AuthUnavailable(_))
        ));
        let mut api = FakeKcm::with_existing(&cred_name(&VID));
        api.sign_status = Some(KcmStatus::UnknownError("0x80090030".into()));
        let b = backend(api);
        assert!(matches!(
            seal_slot(1, "hello", &b, &IdentityEnvelope, &c, &dek),
            Err(Error::AuthUnavailable(_))
        ));
    }

    #[test]
    fn pss_signature_fails_closed_with_integrity() {
        let p = TestPrompter::default();
        let c = ctx(&p, true);
        let mut api = FakeKcm::new();
        api.sign_with_pss = true;
        let b = backend(api);
        let dek: Dek = random_key();
        assert!(matches!(
            seal_slot(1, "hello", &b, &IdentityEnvelope, &c, &dek),
            Err(Error::Integrity(_))
        ));
    }

    #[test]
    fn non_interactive_session_and_no_input_are_unavailable() {
        let p = TestPrompter::default();
        let dek: Dek = random_key();
        let mut b = backend(FakeKcm::new());
        b.session_interactive = false;
        assert_eq!(b.availability(), Availability::NoInteractiveSession);
        let c = ctx(&p, true);
        assert!(matches!(
            seal_slot(1, "hello", &b, &IdentityEnvelope, &c, &dek),
            Err(Error::AuthUnavailable(_))
        ));

        let b = backend(FakeKcm::new());
        let no_ui = ctx(&p, false);
        assert!(matches!(
            seal_slot(1, "hello", &b, &IdentityEnvelope, &no_ui, &dek),
            Err(Error::AuthUnavailable(_))
        ));
        assert_eq!(b.api.prompts.get(), 0);
    }

    #[test]
    fn unsupported_hello_reports_not_enrolled() {
        let mut api = FakeKcm::new();
        api.supported = false;
        let b = backend(api);
        assert_eq!(b.availability(), Availability::NotEnrolled);
        let p = TestPrompter::default();
        let c = ctx(&p, true);
        let dek: Dek = random_key();
        let err = seal_slot(1, "hello", &b, &IdentityEnvelope, &c, &dek).expect_err("unsupported");
        assert!(matches!(err, Error::AuthUnavailable(ref m) if m.contains("not set up")));
    }

    #[test]
    fn destroy_deletes_credential() {
        let b = backend(FakeKcm::with_existing(&cred_name(&VID)));
        let params = SlotParams::Hello {
            cred_name: cred_name(&VID),
            challenge: vec![0; 32],
            spki_der: vec![],
            dpapi: false,
            hw_backed: false,
        };
        b.destroy(&params).expect("destroy");
        assert_eq!(b.api.deletes.get(), 1);
        assert!(b.api.keys.borrow().is_empty());
        b.destroy(&SlotParams::Passphrase {
            argon2: wcm_core::crypto::kdf::Argon2Params::FAST_TEST,
        })
        .expect("noop");
        assert_eq!(b.api.deletes.get(), 1);
    }

    #[test]
    fn wrong_params_kind_is_invalid() {
        let p = TestPrompter::default();
        let c = ctx(&p, true);
        let b = backend(FakeKcm::new());
        let r = b.open(
            &c,
            &SlotParams::Passphrase {
                argon2: wcm_core::crypto::kdf::Argon2Params::FAST_TEST,
            },
        );
        assert!(matches!(r, Err(Error::Invalid(_))));
    }

    #[test]
    fn transient_errors_are_retried_once() {
        struct Flaky {
            inner: FakeKcm,
            fails_left: std::cell::Cell<u32>,
        }
        impl KcmApi for Flaky {
            fn is_supported(&self) -> Result<bool> {
                self.inner.is_supported()
            }
            fn open(&self, n: &str) -> Result<KcmStatus> {
                self.inner.open(n)
            }
            fn create(&self, n: &str) -> Result<KcmStatus> {
                self.inner.create(n)
            }
            fn sign(&self, n: &str, c: &[u8]) -> Result<(KcmStatus, Vec<u8>)> {
                if self.fails_left.get() > 0 {
                    self.fails_left.set(self.fails_left.get() - 1);
                    return Err(Error::AuthUnavailable(
                        "RequestSignAsync failed: 0x8028008B TPM busy".into(),
                    ));
                }
                self.inner.sign(n, c)
            }
            fn public_key(&self, n: &str) -> Result<Vec<u8>> {
                self.inner.public_key(n)
            }
            fn attest(&self, n: &str) -> Result<bool> {
                self.inner.attest(n)
            }
            fn delete(&self, n: &str) -> Result<()> {
                self.inner.delete(n)
            }
        }
        let p = TestPrompter::default();
        let c = ctx(&p, true);
        let dek: Dek = random_key();
        let mut b = HelloBackend::new(Flaky {
            inner: FakeKcm::new(),
            fails_left: std::cell::Cell::new(1),
        });
        b.focus = false;
        assert!(seal_slot(1, "hello", &b, &IdentityEnvelope, &c, &dek).is_ok());

        let mut b = HelloBackend::new(Flaky {
            inner: FakeKcm::new(),
            fails_left: std::cell::Cell::new(2),
        });
        b.focus = false;
        assert!(matches!(
            seal_slot(1, "hello", &b, &IdentityEnvelope, &c, &dek),
            Err(Error::AuthUnavailable(_))
        ));
    }
}
