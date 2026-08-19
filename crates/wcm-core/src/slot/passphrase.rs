//! Passphrase / recovery-key backend (all platforms).

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use super::{current_salt, Availability, KeySlotBackend, SlotKind, SlotParams, UnlockContext};
use crate::crypto::kdf::{self, Argon2Params};
use crate::{Error, Result};

/// Derives ikm with Argon2id from a passphrase (or a normalized recovery key).
///
/// If `secret` is `None`, the passphrase is requested from `ctx.prompter`.
pub struct PassphraseBackend {
    /// Argon2id cost parameters used when enrolling.
    pub params: Argon2Params,
    /// Pre-supplied secret (tests, `WCM_PASSPHRASE`, recovery key already parsed).
    pub secret: Option<SecretString>,
    /// Label used when prompting.
    pub prompt_label: String,
}

impl PassphraseBackend {
    /// Backend that prompts for a passphrase with default Argon2 parameters.
    pub fn prompting(label: &str) -> Self {
        Self {
            params: Argon2Params::DEFAULT,
            secret: None,
            prompt_label: label.to_string(),
        }
    }

    /// Backend with a fixed secret.
    pub fn with_secret(secret: SecretString, params: Argon2Params) -> Self {
        Self {
            params,
            secret: Some(secret),
            prompt_label: "Passphrase".to_string(),
        }
    }

    fn resolve_secret(&self, ctx: &UnlockContext) -> Result<SecretString> {
        if let Some(s) = &self.secret {
            return Ok(s.clone());
        }
        if !ctx.allow_ui {
            return Err(Error::AuthUnavailable(
                "passphrase required but prompting is disabled (--no-input)".into(),
            ));
        }
        ctx.prompter.secret(&self.prompt_label)
    }

    fn ikm(&self, secret: &SecretString, params: Argon2Params) -> Result<Zeroizing<Vec<u8>>> {
        let salt = current_salt()
            .ok_or_else(|| Error::Other("passphrase backend used outside seal/open".into()))?;
        let out = kdf::argon2id(secret.expose_secret().as_bytes(), &salt, params)?;
        Ok(Zeroizing::new(out.to_vec()))
    }
}

impl KeySlotBackend for PassphraseBackend {
    fn kind(&self) -> SlotKind {
        SlotKind::Passphrase
    }

    fn availability(&self) -> Availability {
        Availability::Available
    }

    fn enroll(&self, ctx: &UnlockContext) -> Result<(SlotParams, Zeroizing<Vec<u8>>)> {
        let secret = self.resolve_secret(ctx)?;
        if secret.expose_secret().is_empty() {
            return Err(Error::Invalid("passphrase must not be empty".into()));
        }
        let ikm = self.ikm(&secret, self.params)?;
        Ok((
            SlotParams::Passphrase {
                argon2: self.params,
            },
            ikm,
        ))
    }

    fn open(&self, ctx: &UnlockContext, params: &SlotParams) -> Result<Zeroizing<Vec<u8>>> {
        let SlotParams::Passphrase { argon2 } = params else {
            return Err(Error::Invalid(
                "passphrase backend given non-passphrase slot params".into(),
            ));
        };
        let secret = self.resolve_secret(ctx)?;
        self.ikm(&secret, *argon2)
    }

    fn destroy(&self, _params: &SlotParams) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead;
    use crate::slot::mock::TestPrompter;
    use crate::slot::{open_slot, seal_slot, Dek, IdentityEnvelope};

    fn ctx<'a>(p: &'a TestPrompter, allow_ui: bool) -> UnlockContext<'a> {
        UnlockContext {
            vault_id: [1u8; 16],
            reason: "t",
            prompter: p,
            allow_ui,
        }
    }

    #[test]
    fn fixed_secret_roundtrip_and_wrong_passphrase() {
        let p = TestPrompter::default();
        let c = ctx(&p, true);
        let dek: Dek = aead::random_key();
        let good = PassphraseBackend::with_secret("correct horse".into(), Argon2Params::FAST_TEST);
        let slot = seal_slot(2, "recovery", &good, &IdentityEnvelope, &c, &dek).expect("seal");
        assert_eq!(
            slot.params,
            SlotParams::Passphrase {
                argon2: Argon2Params::FAST_TEST
            }
        );
        assert_eq!(
            *open_slot(&slot, &good, &IdentityEnvelope, &c).expect("open"),
            *dek
        );

        let bad = PassphraseBackend::with_secret("wrong".into(), Argon2Params::FAST_TEST);
        assert!(matches!(
            open_slot(&slot, &bad, &IdentityEnvelope, &c),
            Err(Error::Integrity(_))
        ));
        assert_eq!(p.secret_calls(), 0);
    }

    #[test]
    fn prompts_when_no_secret_and_respects_no_input() {
        let p = TestPrompter::with_secret("from-prompt");
        let c = ctx(&p, true);
        let dek: Dek = aead::random_key();
        let mut b = PassphraseBackend::prompting("Recovery key");
        b.params = Argon2Params::FAST_TEST;
        let slot = seal_slot(2, "recovery", &b, &IdentityEnvelope, &c, &dek).expect("seal");
        assert_eq!(p.secret_calls(), 1);
        assert_eq!(
            *open_slot(&slot, &b, &IdentityEnvelope, &c).expect("open"),
            *dek
        );
        assert_eq!(p.secret_calls(), 2);

        let no_ui = ctx(&p, false);
        assert!(matches!(
            open_slot(&slot, &b, &IdentityEnvelope, &no_ui),
            Err(Error::AuthUnavailable(_))
        ));
    }

    #[test]
    fn empty_passphrase_rejected_on_enroll() {
        let p = TestPrompter::default();
        let c = ctx(&p, true);
        let dek: Dek = aead::random_key();
        let b = PassphraseBackend::with_secret("".into(), Argon2Params::FAST_TEST);
        assert!(matches!(
            seal_slot(2, "r", &b, &IdentityEnvelope, &c, &dek),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn open_uses_slot_params_not_backend_params() {
        // Enroll with FAST_TEST, then open with a backend configured differently: must still work.
        let p = TestPrompter::default();
        let c = ctx(&p, true);
        let dek: Dek = aead::random_key();
        let enroll = PassphraseBackend::with_secret("pw".into(), Argon2Params::FAST_TEST);
        let slot = seal_slot(2, "r", &enroll, &IdentityEnvelope, &c, &dek).expect("seal");
        let open = PassphraseBackend::with_secret(
            "pw".into(),
            Argon2Params {
                m_kib: 128,
                t: 2,
                p: 1,
            },
        );
        assert_eq!(
            *open_slot(&slot, &open, &IdentityEnvelope, &c).expect("open"),
            *dek
        );
    }
}
