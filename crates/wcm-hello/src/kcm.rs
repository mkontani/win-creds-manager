//! Real `KeyCredentialManager` implementation of [`KcmApi`] (Windows only).
//!
//! Every WinRT async operation is awaited with `.join()`; the CLI is a plain
//! console process (implicit MTA), so blocking is fine. GUI front-ends must
//! call this from a worker thread, never from an STA/UI thread.

#![cfg(windows)]

use wcm_core::{Error, Result};
use windows::core::{Array, HSTRING};
use windows::Security::Credentials::{
    KeyCredentialAttestationStatus, KeyCredentialCreationOption, KeyCredentialManager,
    KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;

use crate::kcm_api::{KcmApi, KcmStatus};

/// `KcmApi` backed by WinRT.
#[derive(Default, Clone, Copy)]
pub struct WinRtKcm;

const ERROR_CANCELLED_HRESULT: i32 = 0x800704C7u32 as i32;

fn win_err(what: &str, e: windows::core::Error) -> Error {
    if e.code().0 == ERROR_CANCELLED_HRESULT {
        return Error::AuthCancelled;
    }
    Error::AuthUnavailable(format!(
        "{what} failed: 0x{:08X} {}",
        e.code().0 as u32,
        e.message()
    ))
}

fn status(s: KeyCredentialStatus) -> KcmStatus {
    match s {
        KeyCredentialStatus::Success => KcmStatus::Success,
        KeyCredentialStatus::NotFound => KcmStatus::NotFound,
        KeyCredentialStatus::UserCanceled => KcmStatus::UserCanceled,
        KeyCredentialStatus::UserPrefersPassword => KcmStatus::UserPrefersPassword,
        KeyCredentialStatus::CredentialAlreadyExists => KcmStatus::CredentialAlreadyExists,
        KeyCredentialStatus::SecurityDeviceLocked => KcmStatus::SecurityDeviceLocked,
        other => KcmStatus::UnknownError(format!("KeyCredentialStatus({})", other.0)),
    }
}

fn ibuffer_to_vec(buf: &IBuffer) -> windows::core::Result<Vec<u8>> {
    let mut arr = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(buf, &mut arr)?;
    Ok(arr.to_vec())
}

fn open_credential(name: &str) -> Result<windows::Security::Credentials::KeyCredential> {
    let res = KeyCredentialManager::OpenAsync(&HSTRING::from(name))
        .and_then(|op| op.join())
        .map_err(|e| win_err("OpenAsync", e))?;
    let st = res.Status().map_err(|e| win_err("OpenAsync.Status", e))?;
    if st != KeyCredentialStatus::Success {
        return Err(Error::AuthUnavailable(format!(
            "OpenAsync: {:?}",
            status(st)
        )));
    }
    res.Credential()
        .map_err(|e| win_err("OpenAsync.Credential", e))
}

impl KcmApi for WinRtKcm {
    fn is_supported(&self) -> Result<bool> {
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.join())
            .map_err(|e| win_err("IsSupportedAsync", e))
    }

    fn open(&self, name: &str) -> Result<KcmStatus> {
        let res = KeyCredentialManager::OpenAsync(&HSTRING::from(name))
            .and_then(|op| op.join())
            .map_err(|e| win_err("OpenAsync", e))?;
        Ok(status(
            res.Status().map_err(|e| win_err("OpenAsync.Status", e))?,
        ))
    }

    fn create(&self, name: &str) -> Result<KcmStatus> {
        let res = KeyCredentialManager::RequestCreateAsync(
            &HSTRING::from(name),
            KeyCredentialCreationOption::FailIfExists,
        )
        .and_then(|op| op.join())
        .map_err(|e| win_err("RequestCreateAsync", e))?;
        Ok(status(
            res.Status()
                .map_err(|e| win_err("RequestCreateAsync.Status", e))?,
        ))
    }

    fn sign(&self, name: &str, challenge: &[u8]) -> Result<(KcmStatus, Vec<u8>)> {
        let cred = open_credential(name)?;
        let buf = CryptographicBuffer::CreateFromByteArray(challenge)
            .map_err(|e| win_err("CreateFromByteArray", e))?;
        let res = cred
            .RequestSignAsync(&buf)
            .and_then(|op| op.join())
            .map_err(|e| win_err("RequestSignAsync", e))?;
        let st = status(
            res.Status()
                .map_err(|e| win_err("RequestSignAsync.Status", e))?,
        );
        if st != KcmStatus::Success {
            return Ok((st, Vec::new()));
        }
        let sig = res
            .Result()
            .and_then(|b| ibuffer_to_vec(&b))
            .map_err(|e| win_err("RequestSignAsync.Result", e))?;
        Ok((st, sig))
    }

    fn public_key(&self, name: &str) -> Result<Vec<u8>> {
        let cred = open_credential(name)?;
        cred.RetrievePublicKeyWithDefaultBlobType()
            .and_then(|b| ibuffer_to_vec(&b))
            .map_err(|e| win_err("RetrievePublicKey", e))
    }

    fn attest(&self, name: &str) -> Result<bool> {
        let cred = open_credential(name)?;
        let res = cred
            .GetAttestationAsync()
            .and_then(|op| op.join())
            .map_err(|e| win_err("GetAttestationAsync", e))?;
        let st = res
            .Status()
            .map_err(|e| win_err("GetAttestationAsync.Status", e))?;
        Ok(st == KeyCredentialAttestationStatus::Success)
    }

    fn delete(&self, name: &str) -> Result<()> {
        KeyCredentialManager::DeleteAsync(&HSTRING::from(name))
            .and_then(|op| op.join())
            .map_err(|e| win_err("DeleteAsync", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "interactive: shows Windows Hello prompts"]
    fn live_create_sign_delete() {
        let api = WinRtKcm;
        assert!(api.is_supported().expect("supported"));
        let name = "wcm-v1-selftest";
        let _ = api.delete(name);
        assert_eq!(api.open(name).expect("open"), KcmStatus::NotFound);
        assert_eq!(api.create(name).expect("create"), KcmStatus::Success);
        let spki = api.public_key(name).expect("spki");
        let challenge = [0x42u8; 32];
        let (st, sig) = api.sign(name, &challenge).expect("sign");
        assert_eq!(st, KcmStatus::Success);
        wcm_core::crypto::kdf::verify_hello_signature(&spki, &challenge, &sig)
            .expect("pkcs1v15 verify");
        let (_, sig2) = api.sign(name, &challenge).expect("sign again");
        assert_eq!(sig, sig2, "signature must be deterministic");
        api.delete(name).expect("delete");
    }
}
