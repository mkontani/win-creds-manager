//! `wcm ssh add|pubkey|remove` — hand stored OpenSSH keys to `ssh-agent`.
//!
//! One unlock per invocation; the private key is piped to `ssh-add -` and never
//! written to disk or printed.

use std::path::{Path, PathBuf};

use serde::Serialize;
use wcm_core::item::{Item, ItemKind};
use wcm_core::{Error, Result};
use zeroize::Zeroizing;

use crate::cli::{SshAddArgs, SshArgs, SshCommand, SshNameArgs};
use crate::context::Ctx;
use crate::ssh::{find_ssh_add, ssh_add_remove, ssh_add_stdin};
use crate::sshkey;

/// Field holding the OpenSSH private key.
pub const FIELD_PRIVATE_KEY: &str = "private_key";
/// Field holding the `authorized_keys` line.
pub const FIELD_PUBLIC_KEY: &str = "public_key";
/// Field holding the `SHA256:...` fingerprint.
pub const FIELD_FINGERPRINT: &str = "fingerprint";

pub fn run(ctx: &Ctx, args: &SshArgs) -> Result<()> {
    match &args.command {
        SshCommand::Add(a) => add(ctx, a),
        SshCommand::Pubkey(a) => pubkey(ctx, a),
        SshCommand::Remove(a) => remove(ctx, a),
    }
}

/// Key material extracted from an `ssh-key` item.
#[derive(Debug)]
pub struct KeyMaterial {
    /// Private key bytes (`private_key` field), if present.
    pub private_key: Option<Zeroizing<Vec<u8>>>,
    /// `authorized_keys` line: the `public_key` field, else derived from the private key.
    pub public_key: Option<String>,
    /// Fingerprint: the `fingerprint` field, else derived from the private key.
    pub fingerprint: Option<String>,
    /// Whether the private key is passphrase-protected (only known when it parses).
    pub encrypted: bool,
}

impl KeyMaterial {
    /// Extracts key material; `Invalid` if the item is not an `ssh-key`.
    ///
    /// Derivation from the private key is best-effort: a private key that
    /// `ssh-key` cannot parse is still usable by `ssh-add`, so parse errors
    /// are only surfaced when the caller needs the derived value.
    pub fn from_item(item: &Item) -> Result<KeyMaterial> {
        if item.kind != ItemKind::SshKey {
            return Err(Error::Invalid(format!(
                "item '{}' is not an ssh-key (kind: {})",
                item.name, item.kind
            )));
        }
        let private_key = item
            .fields
            .get(FIELD_PRIVATE_KEY)
            .map(|f| Zeroizing::new(f.value.as_bytes().to_vec()));
        let field_text = |name: &str| {
            item.fields
                .get(name)
                .and_then(|f| f.value.as_text())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        let info = private_key.as_ref().and_then(|pk| sshkey::inspect(pk).ok());
        Ok(KeyMaterial {
            public_key: field_text(FIELD_PUBLIC_KEY)
                .or_else(|| info.as_ref().map(|i| i.public_key.clone())),
            fingerprint: field_text(FIELD_FINGERPRINT)
                .or_else(|| info.as_ref().map(|i| i.fingerprint.clone())),
            encrypted: info.as_ref().is_some_and(|i| i.encrypted),
            private_key,
        })
    }

    /// The private key, `NotFound` when the field is absent.
    pub fn require_private_key(&self, name: &str) -> Result<&Zeroizing<Vec<u8>>> {
        self.private_key
            .as_ref()
            .ok_or_else(|| Error::NotFound(format!("field '{FIELD_PRIVATE_KEY}' of item '{name}'")))
    }

    /// The public key line; derived from the private key when the field is
    /// absent (parse errors propagate as `Invalid`), `NotFound` when neither exists.
    pub fn require_public_key(&self, name: &str) -> Result<String> {
        if let Some(p) = &self.public_key {
            return Ok(p.clone());
        }
        match &self.private_key {
            Some(pk) => Ok(sshkey::inspect(pk)?.public_key),
            None => Err(Error::NotFound(format!(
                "field '{FIELD_PUBLIC_KEY}' of item '{name}' (and no private_key to derive it from)"
            ))),
        }
    }
}

/// Unlocks once, copies the key material of item `name` out and drops the
/// vault again (so it is not held while `ssh-add` runs).
fn load_key(ctx: &Ctx, name: &str, reason: &str) -> Result<KeyMaterial> {
    let v = ctx.unlock(reason)?;
    let item = v
        .body
        .get(name)
        .ok_or_else(|| Error::NotFound(name.to_string()))?;
    KeyMaterial::from_item(item)
}

fn locate_ssh_add(explicit: Option<&Path>) -> Result<PathBuf> {
    find_ssh_add(explicit).ok_or_else(|| {
        Error::Helper("ssh-add not found on PATH (install OpenSSH or pass --ssh-add PATH)".into())
    })
}

#[derive(Serialize)]
struct AddReport {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    ssh_add: String,
}

/// `wcm ssh add <name> [-t LIFETIME] [--ssh-add PATH]`
fn add(ctx: &Ctx, args: &SshAddArgs) -> Result<()> {
    let key = load_key(
        ctx,
        &args.name,
        &format!("load SSH key '{}' into ssh-agent", args.name),
    )?;
    let private_key = key.require_private_key(&args.name)?;
    let ssh_add = locate_ssh_add(args.ssh_add.as_deref())?;
    if key.encrypted {
        ctx.out.warn(&format!(
            "the private key of '{}' is passphrase-protected; ssh-add will prompt for the key passphrase",
            args.name
        ));
    }
    let extra: Vec<String> = match &args.lifetime {
        Some(t) => vec!["-t".to_string(), t.clone()],
        None => Vec::new(),
    };
    if args.lifetime.is_some() && cfg!(windows) {
        ctx.out.notice(
            "note: the Windows ssh-agent service ignores -t and keeps the key until `ssh-add -d`",
        );
    }
    ssh_add_stdin(&ssh_add, &extra, private_key)?;
    let report = AddReport {
        name: args.name.clone(),
        fingerprint: key.fingerprint.clone(),
        ssh_add: ssh_add.display().to_string(),
    };
    if ctx.out.json {
        return ctx.out.json(&report);
    }
    let fp = report
        .fingerprint
        .as_deref()
        .unwrap_or("unknown fingerprint");
    ctx.out
        .notice(&format!("Added {} ({fp}) to ssh-agent", report.name));
    Ok(())
}

#[derive(Serialize)]
struct PubkeyReport {
    name: String,
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
}

/// `wcm ssh pubkey <name>`
fn pubkey(ctx: &Ctx, args: &SshNameArgs) -> Result<()> {
    let key = load_key(
        ctx,
        &args.name,
        &format!("read public key of '{}'", args.name),
    )?;
    let public_key = key.require_public_key(&args.name)?;
    let fingerprint = key.fingerprint.clone().or_else(|| {
        key.private_key
            .as_ref()
            .and_then(|pk| sshkey::inspect(pk).ok())
            .map(|i| i.fingerprint)
    });
    let report = PubkeyReport {
        name: args.name.clone(),
        public_key,
        fingerprint,
    };
    if ctx.out.json {
        return ctx.out.json(&report);
    }
    ctx.out.line(&report.public_key)
}

#[derive(Serialize)]
struct RemoveReport {
    name: String,
    removed: bool,
    ssh_add: String,
}

/// `wcm ssh remove <name>`
fn remove(ctx: &Ctx, args: &SshNameArgs) -> Result<()> {
    let key = load_key(
        ctx,
        &args.name,
        &format!("remove SSH key '{}' from ssh-agent", args.name),
    )?;
    let public_key = key.require_public_key(&args.name)?;
    let ssh_add = locate_ssh_add(args.ssh_add.as_deref())?;
    ssh_add_remove(&ssh_add, &public_key)?;
    let report = RemoveReport {
        name: args.name.clone(),
        removed: true,
        ssh_add: ssh_add.display().to_string(),
    };
    if ctx.out.json {
        return ctx.out.json(&report);
    }
    ctx.out
        .notice(&format!("Removed {} from ssh-agent", report.name));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
    use wcm_core::item::Field;

    fn keypair() -> (String, String, String) {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("keygen");
        let pem = key.to_openssh(LineEnding::LF).expect("pem").to_string();
        let public = key.public_key().to_openssh().expect("pub");
        let fp = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        (pem, public, fp)
    }

    fn ssh_item(name: &str) -> Item {
        Item::new(name, ItemKind::SshKey, "2026-01-01T00:00:00Z")
    }

    #[test]
    fn rejects_non_ssh_items() {
        let item = Item::new("x", ItemKind::Login, "t");
        assert!(matches!(
            KeyMaterial::from_item(&item),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn uses_stored_fields_when_present() {
        let (pem, public, fp) = keypair();
        let item = ssh_item("k")
            .with_field(FIELD_PRIVATE_KEY, Field::secret_text(pem.clone()))
            .with_field(FIELD_PUBLIC_KEY, Field::public_text("ssh-ed25519 STORED x"))
            .with_field(FIELD_FINGERPRINT, Field::public_text("SHA256:stored"));
        let m = KeyMaterial::from_item(&item).expect("material");
        assert_eq!(m.public_key.as_deref(), Some("ssh-ed25519 STORED x"));
        assert_eq!(m.fingerprint.as_deref(), Some("SHA256:stored"));
        assert_eq!(
            m.require_private_key("k").expect("pk").as_slice(),
            pem.as_bytes()
        );
        assert_eq!(
            m.require_public_key("k").expect("pub"),
            "ssh-ed25519 STORED x"
        );
        assert!(!m.encrypted);
        // sanity: derived values differ from stored placeholders
        assert_ne!(public, "ssh-ed25519 STORED x");
        assert_ne!(fp, "SHA256:stored");
    }

    #[test]
    fn derives_public_key_and_fingerprint_from_private_key() {
        let (pem, public, fp) = keypair();
        let item = ssh_item("k").with_field(
            FIELD_PRIVATE_KEY,
            Field::secret_bytes(pem.clone().into_bytes()),
        );
        let m = KeyMaterial::from_item(&item).expect("material");
        assert_eq!(m.public_key.as_deref(), Some(public.as_str()));
        assert_eq!(m.fingerprint.as_deref(), Some(fp.as_str()));
        assert_eq!(m.require_public_key("k").expect("pub"), public);
    }

    #[test]
    fn detects_encrypted_private_key() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("keygen");
        let enc = key.encrypt(&mut OsRng, "pw").expect("encrypt");
        let pem = enc.to_openssh(LineEnding::LF).expect("pem").to_string();
        let item = ssh_item("k").with_field(FIELD_PRIVATE_KEY, Field::secret_text(pem));
        let m = KeyMaterial::from_item(&item).expect("material");
        assert!(m.encrypted);
        assert!(m.public_key.is_some());
    }

    #[test]
    fn missing_fields_are_not_found_or_invalid() {
        let m = KeyMaterial::from_item(&ssh_item("k")).expect("material");
        assert!(matches!(
            m.require_private_key("k"),
            Err(Error::NotFound(_))
        ));
        assert!(matches!(m.require_public_key("k"), Err(Error::NotFound(_))));

        let garbage = ssh_item("k").with_field(FIELD_PRIVATE_KEY, Field::secret_text("not a key"));
        let m = KeyMaterial::from_item(&garbage).expect("material");
        assert!(m.require_private_key("k").is_ok());
        assert!(matches!(m.require_public_key("k"), Err(Error::Invalid(_))));
        assert!(m.fingerprint.is_none());
        assert!(!m.encrypted);
    }

    #[test]
    fn locate_ssh_add_honors_explicit_path() {
        // The "nothing on PATH" branch is covered by the integration tests
        // (mutating PATH here would race with other in-process tests).
        assert_eq!(
            locate_ssh_add(Some(Path::new("/x/ssh-add"))).expect("explicit"),
            PathBuf::from("/x/ssh-add")
        );
    }
}
