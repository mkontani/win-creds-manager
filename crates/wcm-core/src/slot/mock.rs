//! Test doubles: a backend with fixed ikm and a scripted prompter.

use std::cell::{Cell, RefCell};

use secrecy::SecretString;
use zeroize::Zeroizing;

use super::{Availability, KeySlotBackend, Prompter, SlotKind, SlotParams, UnlockContext};
use crate::{Error, Result};

/// Backend returning fixed ikm; can simulate failures.
pub struct MockBackend {
    /// Kind reported.
    pub kind: SlotKind,
    /// Fixed input keying material.
    pub ikm: Vec<u8>,
    /// Reported availability.
    pub availability: Availability,
    /// If set, `open` fails with this error.
    pub fail_open: Option<Error>,
    /// If set, `enroll` fails with this error.
    pub fail_enroll: Option<Error>,
    /// Number of `open` calls.
    pub open_calls: Cell<u32>,
    /// Number of `destroy` calls.
    pub destroy_calls: Cell<u32>,
}

impl MockBackend {
    /// Mock Hello backend with fixed ikm.
    pub fn hello(ikm: Vec<u8>) -> Self {
        Self::new(SlotKind::Hello, ikm)
    }

    /// Mock passphrase-kind backend with fixed ikm (does not use Argon2).
    pub fn passphrase(ikm: Vec<u8>) -> Self {
        Self::new(SlotKind::Passphrase, ikm)
    }

    fn new(kind: SlotKind, ikm: Vec<u8>) -> Self {
        Self {
            kind,
            ikm,
            availability: Availability::Available,
            fail_open: None,
            fail_enroll: None,
            open_calls: Cell::new(0),
            destroy_calls: Cell::new(0),
        }
    }

    fn params(&self) -> SlotParams {
        match self.kind {
            SlotKind::Hello => SlotParams::Hello {
                cred_name: "wcm-v1-mock".into(),
                challenge: vec![0u8; 32],
                spki_der: vec![],
                dpapi: false,
                hw_backed: false,
            },
            SlotKind::Passphrase => SlotParams::Passphrase {
                argon2: crate::crypto::kdf::Argon2Params::FAST_TEST,
            },
        }
    }
}

impl KeySlotBackend for MockBackend {
    fn kind(&self) -> SlotKind {
        self.kind
    }
    fn availability(&self) -> Availability {
        self.availability.clone()
    }
    fn enroll(&self, _ctx: &UnlockContext) -> Result<(SlotParams, Zeroizing<Vec<u8>>)> {
        if let Some(e) = &self.fail_enroll {
            return Err(e.clone());
        }
        Ok((self.params(), Zeroizing::new(self.ikm.clone())))
    }
    fn open(&self, _ctx: &UnlockContext, _params: &SlotParams) -> Result<Zeroizing<Vec<u8>>> {
        self.open_calls.set(self.open_calls.get() + 1);
        if let Some(e) = &self.fail_open {
            return Err(e.clone());
        }
        Ok(Zeroizing::new(self.ikm.clone()))
    }
    fn destroy(&self, _params: &SlotParams) -> Result<()> {
        self.destroy_calls.set(self.destroy_calls.get() + 1);
        Ok(())
    }
}

/// Prompter returning scripted answers and counting calls.
#[derive(Default)]
pub struct TestPrompter {
    secret: Option<String>,
    confirm: bool,
    secret_calls: Cell<u32>,
    /// Notices received.
    pub notices: RefCell<Vec<String>>,
}

impl TestPrompter {
    /// Prompter that answers every secret prompt with `s`.
    pub fn with_secret(s: &str) -> Self {
        Self {
            secret: Some(s.to_string()),
            ..Default::default()
        }
    }
    /// Prompter that answers confirmations with `yes`.
    pub fn confirming(mut self, yes: bool) -> Self {
        self.confirm = yes;
        self
    }
    /// How many times `secret` was called.
    pub fn secret_calls(&self) -> u32 {
        self.secret_calls.get()
    }
}

impl Prompter for TestPrompter {
    fn secret(&self, _label: &str) -> Result<SecretString> {
        self.secret_calls.set(self.secret_calls.get() + 1);
        match &self.secret {
            Some(s) => Ok(SecretString::from(s.clone())),
            None => Err(Error::AuthCancelled),
        }
    }
    fn confirm(&self, _msg: &str) -> Result<bool> {
        Ok(self.confirm)
    }
    fn notice(&self, msg: &str) {
        self.notices.borrow_mut().push(msg.to_string());
    }
}
