//! OpenSSH private-key inspection shared by `add` (kind auto-detection, derived
//! `public_key` / `fingerprint` fields) and `ssh` subcommands.

use ssh_key::{HashAlg, PrivateKey};
use wcm_core::{Error, Result};

/// Facts derived from an OpenSSH private key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshKeyInfo {
    /// `authorized_keys` line (`ssh-ed25519 AAAA... comment`).
    pub public_key: String,
    /// `SHA256:...` fingerprint.
    pub fingerprint: String,
    /// Key comment (may be empty).
    pub comment: String,
    /// Algorithm name (`ssh-ed25519`, `ssh-rsa`, ...).
    pub algorithm: String,
    /// Whether the private key is itself passphrase-encrypted.
    pub encrypted: bool,
}

/// Whether `bytes` look like an OpenSSH private key (PEM header check only).
pub fn looks_like_openssh_private_key(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(64)];
    head.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----")
        || head.starts_with(b"-----BEGIN RSA PRIVATE KEY-----")
        || head.starts_with(b"-----BEGIN EC PRIVATE KEY-----")
        || head.starts_with(b"-----BEGIN PRIVATE KEY-----")
}

/// Parses an OpenSSH private key and derives its public half + fingerprint.
/// Encrypted keys are supported: the public part is still readable.
pub fn inspect(bytes: &[u8]) -> Result<SshKeyInfo> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Invalid("SSH key is not valid UTF-8".into()))?;
    let key = PrivateKey::from_openssh(text)
        .map_err(|e| Error::Invalid(format!("not an OpenSSH private key: {e}")))?;
    let public = key.public_key();
    let public_key = public
        .to_openssh()
        .map_err(|e| Error::Invalid(format!("cannot encode public key: {e}")))?;
    Ok(SshKeyInfo {
        public_key,
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        comment: key.comment().to_string(),
        algorithm: key.algorithm().to_string(),
        encrypted: key.is_encrypted(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, LineEnding};

    fn ed25519_pem() -> String {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("keygen");
        let mut key = key;
        key.set_comment("test@wcm");
        key.to_openssh(LineEnding::LF).expect("pem").to_string()
    }

    #[test]
    fn detects_and_inspects_ed25519() {
        let pem = ed25519_pem();
        assert!(looks_like_openssh_private_key(pem.as_bytes()));
        assert!(!looks_like_openssh_private_key(b"hunter2"));
        let info = inspect(pem.as_bytes()).expect("inspect");
        assert!(info.public_key.starts_with("ssh-ed25519 AAAA"));
        assert!(info.public_key.ends_with(" test@wcm"));
        assert!(info.fingerprint.starts_with("SHA256:"));
        assert_eq!(info.comment, "test@wcm");
        assert_eq!(info.algorithm, "ssh-ed25519");
        assert!(!info.encrypted);
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(inspect(b"not a key"), Err(Error::Invalid(_))));
        assert!(matches!(inspect(&[0xff, 0xfe]), Err(Error::Invalid(_))));
    }
}
