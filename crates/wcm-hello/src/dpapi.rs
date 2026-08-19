//! DPAPI envelope (`CryptProtectData` / `CryptUnprotectData`) applied to the
//! Hello slot's wrapped DEK. Binds the slot to the Windows user profile as
//! defense in depth. Never applied to the recovery slot (must stay portable).

use wcm_core::slot::Envelope;
use wcm_core::Result;

/// DPAPI description string stored in the blob.
pub const DPAPI_DESCRIPTION: &str = "wcm";

/// Envelope using the current user's DPAPI master key with `vault_id` as extra entropy.
pub struct DpapiEnvelope;

impl Envelope for DpapiEnvelope {
    fn protect(&self, vault_id: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        platform::protect(data, vault_id)
    }
    fn unprotect(&self, vault_id: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        platform::unprotect(data, vault_id)
    }
}

/// Whether DPAPI is available on this platform.
pub fn is_available() -> bool {
    cfg!(windows)
}

#[cfg(windows)]
mod platform {
    use wcm_core::{Error, Result};
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    #[allow(unsafe_code)]
    fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        // SAFETY: `out` was filled by DPAPI with `cbData` valid bytes at `pbData`,
        // allocated with LocalAlloc; we copy them out and free exactly once.
        unsafe {
            let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            let _ = LocalFree(Some(HLOCAL(out.pbData as *mut _)));
            v
        }
    }

    #[allow(unsafe_code)]
    pub fn protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        let din = blob(data);
        let ent = blob(entropy);
        let desc = HSTRING::from(super::DPAPI_DESCRIPTION);
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: all pointers reference live stack/heap data for the duration of the call.
        unsafe {
            CryptProtectData(
                &din,
                PCWSTR(desc.as_ptr()),
                Some(&ent),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
            .map_err(|e| Error::AuthUnavailable(format!("DPAPI protect failed: {e}")))?;
        }
        Ok(take(out))
    }

    #[allow(unsafe_code)]
    pub fn unprotect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        let din = blob(data);
        let ent = blob(entropy);
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: see `protect`.
        unsafe {
            CryptUnprotectData(
                &din,
                None,
                Some(&ent),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
            .map_err(|e| {
                Error::AuthUnavailable(format!(
                    "DPAPI unprotect failed (different Windows user/profile?): {e}"
                ))
            })?;
        }
        Ok(take(out))
    }
}

#[cfg(not(windows))]
mod platform {
    use wcm_core::{Error, Result};

    pub fn protect(_data: &[u8], _entropy: &[u8]) -> Result<Vec<u8>> {
        Err(Error::AuthUnavailable(
            "DPAPI is only available on Windows".into(),
        ))
    }
    pub fn unprotect(_data: &[u8], _entropy: &[u8]) -> Result<Vec<u8>> {
        Err(Error::AuthUnavailable(
            "DPAPI is only available on Windows".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_windows_reports_unavailable() {
        if !cfg!(windows) {
            assert!(!is_available());
            assert!(matches!(
                DpapiEnvelope.protect(&[0; 16], b"x"),
                Err(wcm_core::Error::AuthUnavailable(_))
            ));
            assert!(matches!(
                DpapiEnvelope.unprotect(&[0; 16], b"x"),
                Err(wcm_core::Error::AuthUnavailable(_))
            ));
        }
    }

    #[test]
    #[cfg_attr(not(windows), ignore = "requires Windows DPAPI")]
    fn windows_roundtrip() {
        let ct = DpapiEnvelope.protect(&[1; 16], b"secret").expect("protect");
        assert_ne!(ct, b"secret");
        assert_eq!(
            DpapiEnvelope.unprotect(&[1; 16], &ct).expect("unprotect"),
            b"secret"
        );
        assert!(
            DpapiEnvelope.unprotect(&[2; 16], &ct).is_err(),
            "entropy mismatch must fail"
        );
    }
}
