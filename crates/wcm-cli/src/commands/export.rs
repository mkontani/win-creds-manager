//! `wcm export` — write the vault as a standalone encrypted `.wcm` file (one
//! passphrase slot labelled `export`) or, with `--plaintext --i-know`, as a
//! plaintext JSON document.
//!
//! The export passphrase comes from `WCM_EXPORT_PASSPHRASE` when set, otherwise
//! it is prompted (twice). The source vault records `settings.last_export`.

use std::path::{Path, PathBuf};

use secrecy::SecretString;
use serde::Serialize;
use wcm_core::crypto::aead::random_key;
use wcm_core::export::PlainExport;
use wcm_core::slot::passphrase::PassphraseBackend;
use wcm_core::slot::{seal_slot, IdentityEnvelope, KeySlot, UnlockContext};
use wcm_core::vault::file::{backup_path, lock_path};
use wcm_core::vault::{new_vault_id, now_rfc3339, Settings, Vault, VaultBody};
use wcm_core::{Error, Result};

use crate::cli::ExportArgs;
use crate::context::Ctx;

/// Environment variable supplying the export passphrase non-interactively.
pub const EXPORT_PASSPHRASE_ENV: &str = "WCM_EXPORT_PASSPHRASE";
/// Label of the single key slot in an encrypted export.
pub const EXPORT_SLOT_LABEL: &str = "export";
/// Prompt label for the export passphrase.
const EXPORT_PROMPT: &str = "Export passphrase";

#[derive(Serialize)]
struct ExportReport {
    file: Option<String>,
    items: usize,
    encrypted: bool,
}

/// Export passphrase: `WCM_EXPORT_PASSPHRASE`, else a hidden prompt (confirmed when `confirm`).
pub fn export_passphrase(ctx: &Ctx, confirm: bool) -> Result<SecretString> {
    if let Ok(v) = std::env::var(EXPORT_PASSPHRASE_ENV) {
        if !v.is_empty() {
            return Ok(SecretString::from(v));
        }
    }
    if confirm {
        ctx.prompter.read_hidden_confirmed(EXPORT_PROMPT)
    } else {
        ctx.prompter.read_hidden(EXPORT_PROMPT)
    }
}

/// Default export file name: `wcm-export-<YYYYMMDD>.wcm`.
pub fn default_export_name(now_rfc3339: &str) -> String {
    let date: String = now_rfc3339
        .chars()
        .take(10)
        .filter(|c| c.is_ascii_digit())
        .collect();
    format!("wcm-export-{date}.wcm")
}

fn ensure_absent(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(Error::AlreadyExists(format!(
            "{} (choose another -o/--out path)",
            path.display()
        )));
    }
    Ok(())
}

pub fn run(ctx: &Ctx, args: &ExportArgs) -> Result<()> {
    if args.plaintext && !args.i_know {
        return Err(Error::Invalid(
            "--plaintext writes every secret unencrypted; add --i-know to confirm".into(),
        ));
    }
    let now = now_rfc3339();
    let out_path: Option<PathBuf> = match (&args.out, args.plaintext) {
        (Some(p), _) => Some(p.clone()),
        (None, true) => None,
        (None, false) => Some(PathBuf::from(default_export_name(&now))),
    };
    if let Some(p) = &out_path {
        ensure_absent(p)?;
    }
    // Resolve the export passphrase before unlocking so a missing passphrase
    // does not cost the user a Hello prompt.
    let export_secret = if args.plaintext {
        None
    } else {
        Some(export_passphrase(ctx, true)?)
    };

    let mut v = ctx.unlock("export vault")?;
    let items = v.body.items.len();

    let report = if args.plaintext {
        ctx.out
            .warn("plaintext export contains every secret unencrypted; delete it when done");
        let doc = PlainExport::from_body(&v.body, &now).to_json()?;
        match &out_path {
            Some(p) => {
                crate::outfile::write_new(p, doc.as_bytes())?;
                ExportReport {
                    file: Some(p.display().to_string()),
                    items,
                    encrypted: false,
                }
            }
            None => {
                ctx.out.line(&doc)?;
                ExportReport {
                    file: None,
                    items,
                    encrypted: false,
                }
            }
        }
    } else {
        let (Some(p), Some(secret)) = (&out_path, export_secret) else {
            return Err(Error::Other("export target not resolved".into()));
        };
        write_encrypted_export(ctx, p, secret, &v.body, args.argon2_test_params, &now)?;
        ExportReport {
            file: Some(p.display().to_string()),
            items,
            encrypted: true,
        }
    };

    v = v.map_body(|b| {
        Ok(b.with_settings(Settings {
            last_export: Some(now.clone()),
        }))
    })?;
    ctx.save(&mut v)?;

    if report.file.is_none() {
        // The document itself was the stdout payload.
        return Ok(());
    }
    if ctx.out.json {
        return ctx.out.json(&report);
    }
    let how = if report.encrypted {
        "encrypted with the export passphrase"
    } else {
        "PLAINTEXT"
    };
    ctx.out.line(&format!(
        "Exported {} items to {} ({how})",
        report.items,
        report.file.as_deref().unwrap_or("-")
    ))
}

/// Creates a fresh vault at `path` holding `body`, sealed by one passphrase slot.
fn write_encrypted_export(
    ctx: &Ctx,
    path: &Path,
    secret: SecretString,
    body: &VaultBody,
    argon2_test_params: bool,
    now: &str,
) -> Result<()> {
    let vault_id = new_vault_id();
    let dek = random_key();
    let uctx: UnlockContext = ctx.unlock_ctx(vault_id, "create export");
    let backend = PassphraseBackend::with_secret(secret, Ctx::argon2_params(argon2_test_params));
    let slot: KeySlot = seal_slot(
        1,
        EXPORT_SLOT_LABEL,
        &backend,
        &IdentityEnvelope,
        &uctx,
        &dek,
    )?;
    let export_vault = Vault::new(path);
    let mut exported = export_vault
        .create(vec![slot], dek, vault_id, now)?
        .with_body(VaultBody {
            items: body.items.clone(),
            settings: Settings::default(),
        });
    exported.save(&export_vault)?;
    // A standalone export should not leave vault housekeeping files behind.
    let _ = std::fs::remove_file(backup_path(path));
    let _ = std::fs::remove_file(lock_path(path));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_name_uses_date() {
        assert_eq!(
            default_export_name("2026-08-19T01:02:03Z"),
            "wcm-export-20260819.wcm"
        );
    }

    #[test]
    fn ensure_absent_refuses_existing() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("x.json");
        std::fs::write(&p, b"a").expect("write");
        assert!(matches!(ensure_absent(&p), Err(Error::AlreadyExists(_))));
        assert!(ensure_absent(&dir.path().join("none")).is_ok());
    }
}
