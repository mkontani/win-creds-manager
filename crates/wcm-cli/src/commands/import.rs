//! `wcm import FILE` — merge items from an encrypted export (`.wcm`, opened
//! with the export passphrase from `WCM_EXPORT_PASSPHRASE` or a prompt) or a
//! plaintext JSON export into the vault.

use serde::Serialize;
use wcm_core::export::{merge, MergeMode, PlainExport};
use wcm_core::item::Item;
use wcm_core::slot::passphrase::PassphraseBackend;
use wcm_core::slot::{Envelope, IdentityEnvelope, KeySlot, KeySlotBackend, Prompter, SlotKind};
use wcm_core::vault::header::MAGIC;
use wcm_core::vault::{SlotResolver, Vault};
use wcm_core::{Error, Result};

use crate::cli::ImportArgs;
use crate::commands::export::export_passphrase;
use crate::context::Ctx;

#[derive(Serialize)]
struct ImportReport {
    file: String,
    added: usize,
    overwritten: usize,
    skipped: usize,
}

/// Resolver for export files: passphrase slots only (Hello slots are skipped).
struct ExportResolver {
    passphrase: PassphraseBackend,
}

impl SlotResolver for ExportResolver {
    fn resolve(&self, slot: &KeySlot) -> Option<(&dyn KeySlotBackend, &dyn Envelope)> {
        match slot.kind() {
            SlotKind::Passphrase => Some((&self.passphrase, &IdentityEnvelope)),
            SlotKind::Hello => None,
        }
    }
}

/// Merge mode from flags.
pub fn merge_mode(overwrite: bool, replace: bool) -> MergeMode {
    match (replace, overwrite) {
        (true, _) => MergeMode::Replace,
        (false, true) => MergeMode::Overwrite,
        (false, false) => MergeMode::Merge,
    }
}

/// Whether `bytes` look like an encrypted vault / export file.
pub fn is_vault_file(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC.len() && bytes[..MAGIC.len()] == MAGIC
}

/// Parses a plaintext export document.
fn parse_plain(bytes: &[u8]) -> Result<Vec<Item>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Format("not a wcm export file (neither .wcm nor JSON)".into()))?;
    Ok(PlainExport::from_json(text)?.items)
}

/// Opens an encrypted export with the export passphrase and returns its items.
fn read_encrypted(ctx: &Ctx, args: &ImportArgs) -> Result<Vec<Item>> {
    let export_vault = Vault::new(&args.file);
    let header = export_vault.read_header()?;
    if !header
        .slots
        .iter()
        .any(|s| s.kind() == SlotKind::Passphrase)
    {
        return Err(Error::Format(
            "export file has no passphrase slot; it cannot be opened on this machine".into(),
        ));
    }
    let secret = export_passphrase(ctx, false)?;
    let resolver = ExportResolver {
        // Argon2 parameters are taken from the slot when opening.
        passphrase: PassphraseBackend::with_secret(secret, Ctx::argon2_params(true)),
    };
    let uctx = ctx.unlock_ctx(header.vault_id_arr(), "open export file");
    let opened = export_vault.unlock(&resolver, &uctx, None)?;
    Ok(opened.body.items)
}

/// `--replace` throws away every stored item: refuse unless `-f` or the user
/// confirms (which `--no-input` answers with "no").
fn confirm_replace(ctx: &Ctx, args: &ImportArgs) -> Result<()> {
    if !args.replace || args.force {
        return Ok(());
    }
    let ok = ctx.prompter.confirm(&format!(
        "--replace deletes every item in {} before importing. Continue?",
        ctx.vault.path.display()
    ))?;
    if !ok {
        return Err(Error::Invalid(
            "--replace not confirmed; pass -f/--force to delete every stored item".into(),
        ));
    }
    Ok(())
}

pub fn run(ctx: &Ctx, args: &ImportArgs) -> Result<()> {
    // Fail fast on the destination before touching the import file.
    ctx.vault.read_header()?;
    confirm_replace(ctx, args)?;
    let bytes = crate::secrets::read_file_capped(&args.file)?;
    let incoming = if is_vault_file(&bytes) {
        read_encrypted(ctx, args)?
    } else {
        parse_plain(&bytes)?
    };
    drop(bytes);

    let mode = merge_mode(args.overwrite, args.replace);
    let mut v = ctx.unlock("import items")?;
    let (body, report) = merge(&v.body, &incoming, mode)?;
    v = v.with_body(body);
    ctx.save(&mut v)?;

    let out = ImportReport {
        file: args.file.display().to_string(),
        added: report.added,
        overwritten: report.overwritten,
        skipped: report.skipped,
    };
    if ctx.out.json {
        return ctx.out.json(&out);
    }
    ctx.out.line(&format!(
        "Imported: added {}, overwritten {}, skipped {}",
        out.added, out.overwritten, out.skipped
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_mode_from_flags() {
        assert_eq!(merge_mode(false, false), MergeMode::Merge);
        assert_eq!(merge_mode(true, false), MergeMode::Overwrite);
        assert_eq!(merge_mode(false, true), MergeMode::Replace);
        assert_eq!(merge_mode(true, true), MergeMode::Replace);
    }

    #[test]
    fn detects_vault_magic() {
        assert!(is_vault_file(b"WCM\x01rest"));
        assert!(!is_vault_file(b"WCM"));
        assert!(!is_vault_file(b"{\"version\":1}"));
    }

    #[test]
    fn plain_parse_errors_are_format_errors() {
        assert!(matches!(parse_plain(&[0xff, 0xfe]), Err(Error::Format(_))));
        assert!(matches!(parse_plain(b"{}"), Err(Error::Format(_))));
        let ok = parse_plain(b"{\"version\":1,\"exported\":\"x\",\"items\":[]}").expect("ok");
        assert!(ok.is_empty());
    }
}
