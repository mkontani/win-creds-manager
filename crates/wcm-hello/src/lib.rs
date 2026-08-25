//! Windows Hello (`KeyCredentialManager`) key-slot backend for wcm.
//!
//! The crate compiles on every platform: on non-Windows targets the system
//! backend reports [`Availability::Unsupported`] and DPAPI is unavailable, so
//! front-ends need no `cfg` gymnastics.

pub mod backend;
pub mod dpapi;
pub mod focus;
pub mod kcm;
pub mod kcm_api;
pub mod process;
pub mod session;

use wcm_core::slot::{
    Availability, Envelope, IdentityEnvelope, KeySlotBackend, SlotKind, SlotParams, UnlockContext,
};
use wcm_core::{Error, Result};
use zeroize::Zeroizing;

pub use backend::{cred_name, HelloBackend};
pub use dpapi::DpapiEnvelope;
pub use kcm_api::{KcmApi, KcmStatus};

/// Options for [`system_backend`].
#[derive(Clone, Copy, Debug)]
pub struct HelloOptions {
    /// Allow creating a new credential during enroll.
    pub allow_create: bool,
    /// Record/apply DPAPI on the Hello slot.
    pub dpapi: bool,
    /// Run the foreground-focus helper while prompting.
    pub focus: bool,
}

impl Default for HelloOptions {
    fn default() -> Self {
        HelloOptions {
            allow_create: true,
            dpapi: true,
            focus: true,
        }
    }
}

/// Backend used on platforms without Windows Hello.
pub struct UnsupportedBackend;

impl KeySlotBackend for UnsupportedBackend {
    fn kind(&self) -> SlotKind {
        SlotKind::Hello
    }
    fn availability(&self) -> Availability {
        Availability::Unsupported("Windows Hello is only available on Windows".into())
    }
    fn enroll(&self, _ctx: &UnlockContext) -> Result<(SlotParams, Zeroizing<Vec<u8>>)> {
        Err(Error::AuthUnavailable(
            "Windows Hello is only available on Windows".into(),
        ))
    }
    fn open(&self, _ctx: &UnlockContext, _params: &SlotParams) -> Result<Zeroizing<Vec<u8>>> {
        Err(Error::AuthUnavailable(
            "Windows Hello is only available on Windows".into(),
        ))
    }
    fn destroy(&self, _params: &SlotParams) -> Result<()> {
        Ok(())
    }
}

/// The Windows Hello backend for this machine (real WinRT on Windows, a stub elsewhere).
pub fn system_backend(opts: HelloOptions) -> Box<dyn KeySlotBackend> {
    #[cfg(windows)]
    {
        let mut b = HelloBackend::new(kcm::WinRtKcm);
        b.allow_create = opts.allow_create;
        b.dpapi = opts.dpapi;
        b.focus = opts.focus;
        b.session_interactive = session::is_interactive();
        Box::new(b)
    }
    #[cfg(not(windows))]
    {
        let _ = opts;
        Box::new(UnsupportedBackend)
    }
}

/// Envelope for a Hello slot: DPAPI when `dpapi` is set, identity otherwise.
pub fn system_envelope(dpapi: bool) -> Box<dyn Envelope> {
    if dpapi {
        Box::new(DpapiEnvelope)
    } else {
        Box::new(IdentityEnvelope)
    }
}

/// Envelope matching a stored slot's params (`dpapi` flag).
pub fn envelope_for(params: &SlotParams) -> Box<dyn Envelope> {
    match params {
        SlotParams::Hello { dpapi, .. } => system_envelope(*dpapi),
        SlotParams::Passphrase { .. } => Box::new(IdentityEnvelope),
    }
}

/// Diagnostic snapshot for `wcm doctor`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct HelloInfo {
    /// Whether this build has the WinRT backend compiled in.
    pub compiled_in: bool,
    /// `KeyCredentialManager.IsSupportedAsync()` (None when not available).
    pub supported: Option<bool>,
    /// Windows session id (None off-Windows).
    pub session_id: Option<u32>,
    /// Whether Hello can prompt in this session.
    pub interactive: bool,
    /// Whether DPAPI is available.
    pub dpapi_available: bool,
    /// Human-readable availability.
    pub availability: String,
}

/// Collects [`HelloInfo`] without prompting.
pub fn info() -> HelloInfo {
    let backend = system_backend(HelloOptions::default());
    let availability = backend.availability();
    let supported = match &availability {
        Availability::Available => Some(true),
        Availability::NotEnrolled => Some(false),
        _ => None,
    };
    HelloInfo {
        compiled_in: cfg!(windows),
        supported,
        session_id: session::session_id(),
        interactive: session::is_interactive(),
        dpapi_available: dpapi::is_available(),
        availability: match availability {
            Availability::Available => "available".into(),
            Availability::NotEnrolled => "not enrolled (set up a Windows Hello PIN)".into(),
            Availability::Unsupported(r) => format!("unsupported: {r}"),
            Availability::NoInteractiveSession => "no interactive session".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_and_stub_backend_behave_off_windows() {
        let i = info();
        assert_eq!(i.compiled_in, cfg!(windows));
        if !cfg!(windows) {
            assert_eq!(i.supported, None);
            assert!(i.availability.starts_with("unsupported"));
            let b = system_backend(HelloOptions::default());
            assert_eq!(b.kind(), SlotKind::Hello);
            assert!(matches!(b.availability(), Availability::Unsupported(_)));
        }
    }

    #[test]
    fn envelope_for_params() {
        let hello_dpapi = SlotParams::Hello {
            cred_name: "x".into(),
            challenge: vec![0; 32],
            spki_der: vec![],
            dpapi: true,
            hw_backed: false,
        };
        let e = envelope_for(&hello_dpapi);
        if !cfg!(windows) {
            assert!(e.protect(&[0; 16], b"x").is_err());
        }
        let pass = SlotParams::Passphrase {
            argon2: wcm_core::crypto::kdf::Argon2Params::FAST_TEST,
        };
        assert_eq!(
            envelope_for(&pass)
                .protect(&[0; 16], b"x")
                .expect("identity"),
            b"x"
        );
        assert_eq!(
            system_envelope(false)
                .protect(&[0; 16], b"y")
                .expect("identity"),
            b"y"
        );
    }
}
