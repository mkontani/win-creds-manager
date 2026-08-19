//! `wcm slot ls|add|rm` — manage key slots.
//!
//! `ls` reads only the header. `add`/`rm` unlock the vault once (to obtain the
//! DEK / prove possession). New passphrases come from `WCM_NEW_PASSPHRASE`,
//! else `WCM_PASSPHRASE`, else a confirmed hidden prompt.

use secrecy::SecretString;
use serde::Serialize;
use wcm_core::slot::passphrase::PassphraseBackend;
use wcm_core::slot::{seal_slot, Availability, IdentityEnvelope, KeySlot, Prompter, SlotParams};
use wcm_core::vault::UnlockedVault;
use wcm_core::{Error, Result};

use crate::cli::{SlotAddArgs, SlotArgs, SlotCommand, SlotRmArgs};
use crate::commands::init::{LABEL_HELLO, LABEL_PASSPHRASE};
use crate::context::Ctx;
use crate::prompt::passphrase_from_env;

/// Environment variable supplying a *new* passphrase (recover, rekey, slot add).
pub const NEW_PASSPHRASE_ENV: &str = "WCM_NEW_PASSPHRASE";

/// One row of `slot ls` (also reused by `recover`).
#[derive(Serialize)]
pub struct SlotRow {
    pub id: u8,
    pub label: String,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hw_backed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpapi: Option<bool>,
}

impl SlotRow {
    /// Summarizes a slot.
    pub fn from_slot(slot: &KeySlot) -> SlotRow {
        let (hw_backed, dpapi) = match &slot.params {
            SlotParams::Hello {
                hw_backed, dpapi, ..
            } => (Some(*hw_backed), Some(*dpapi)),
            SlotParams::Passphrase { .. } => (None, None),
        };
        SlotRow {
            id: slot.id,
            label: slot.label.clone(),
            kind: slot.kind().as_str(),
            hw_backed,
            dpapi,
        }
    }
}

/// A new passphrase: `WCM_NEW_PASSPHRASE`, else `WCM_PASSPHRASE`, else a confirmed prompt.
pub fn new_passphrase_secret(ctx: &Ctx, label: &str) -> Result<SecretString> {
    if let Ok(v) = std::env::var(NEW_PASSPHRASE_ENV) {
        if !v.is_empty() {
            return Ok(SecretString::from(v));
        }
    }
    if let Some(s) = passphrase_from_env()? {
        return Ok(s);
    }
    ctx.prompter.read_hidden_confirmed(label)
}

/// Human description of a backend availability state.
pub fn describe_availability(a: &Availability) -> String {
    match a {
        Availability::Available => "available".into(),
        Availability::NotEnrolled => {
            "Windows Hello is not set up (add a PIN in Settings > Accounts > Sign-in options)"
                .into()
        }
        Availability::Unsupported(r) => r.clone(),
        Availability::NoInteractiveSession => "no interactive desktop session".into(),
    }
}

/// Fails with `AlreadyExists` if a slot with `label` exists.
pub fn ensure_label_free(slots: &[KeySlot], label: &str) -> Result<()> {
    if slots.iter().any(|s| s.label == label) {
        return Err(Error::AlreadyExists(format!(
            "key slot '{label}' (choose another --label or remove it first)"
        )));
    }
    Ok(())
}

/// Seals a new passphrase slot with `secret`.
pub fn seal_passphrase_slot(
    ctx: &Ctx,
    v: &UnlockedVault,
    id: u8,
    label: &str,
    secret: SecretString,
    argon2_test_params: bool,
) -> Result<KeySlot> {
    let uctx = ctx.unlock_ctx(v.header.vault_id_arr(), "add passphrase slot");
    let backend = PassphraseBackend::with_secret(secret, Ctx::argon2_params(argon2_test_params));
    seal_slot(id, label, &backend, &IdentityEnvelope, &uctx, v.dek())
}

/// Seals a new Windows Hello slot (errors with `AuthUnavailable` where Hello cannot be used).
pub fn seal_hello_slot(
    ctx: &Ctx,
    v: &UnlockedVault,
    id: u8,
    label: &str,
    dpapi: bool,
) -> Result<KeySlot> {
    let backend = ctx.hello_backend(true, dpapi);
    match backend.availability() {
        Availability::Available => {}
        other => {
            return Err(Error::AuthUnavailable(format!(
                "Windows Hello slot cannot be created: {}",
                describe_availability(&other)
            )));
        }
    }
    let envelope = wcm_hello::system_envelope(dpapi);
    let uctx = ctx.unlock_ctx(v.header.vault_id_arr(), "add Windows Hello slot");
    let slot = seal_slot(
        id,
        label,
        backend.as_ref(),
        envelope.as_ref(),
        &uctx,
        v.dek(),
    )?;
    if let SlotParams::Hello {
        hw_backed: false, ..
    } = &slot.params
    {
        ctx.out
            .warn("the Windows Hello key is not hardware (TPM) backed on this machine");
    }
    Ok(slot)
}

/// Whether the Hello credential backing `slot` is still referenced by `kept`.
///
/// Destroying it would break those slots, so the cleanup is skipped. Non-Hello
/// slots have no external state and are never "shared".
pub fn credential_shared(slot: &KeySlot, kept: &[KeySlot]) -> bool {
    let SlotParams::Hello { cred_name, .. } = &slot.params else {
        return false;
    };
    kept.iter().any(
        |s| matches!(&s.params, SlotParams::Hello { cred_name: other, .. } if other == cred_name),
    )
}

/// Best-effort removal of external state (Hello credential) for `slot`.
///
/// `kept` are the slots that survive the change **as saved on disk**; a
/// credential one of them still uses is left alone.
pub fn destroy_slot_state(ctx: &Ctx, slot: &KeySlot, kept: &[KeySlot]) {
    let SlotParams::Hello { dpapi, .. } = &slot.params else {
        return;
    };
    if credential_shared(slot, kept) {
        return;
    }
    if let Err(e) = ctx.hello_backend(false, *dpapi).destroy(&slot.params) {
        ctx.out.notice(&format!(
            "note: could not delete the Windows Hello credential for slot '{}': {e}",
            slot.label
        ));
    }
}

pub fn run(ctx: &Ctx, args: &SlotArgs) -> Result<()> {
    match &args.command {
        SlotCommand::Ls => ls(ctx),
        SlotCommand::Add(a) => add(ctx, a),
        SlotCommand::Rm(a) => rm(ctx, a),
    }
}

fn ls(ctx: &Ctx) -> Result<()> {
    let header = ctx.vault.read_header()?;
    let rows: Vec<SlotRow> = header.slots.iter().map(SlotRow::from_slot).collect();
    if ctx.out.json {
        return ctx.out.json(&rows);
    }
    ctx.out.line(&format!(
        "{:>3}  {:<16} {:<12} {}",
        "ID", "LABEL", "KIND", "DETAILS"
    ))?;
    for r in &rows {
        let details = match (r.hw_backed, r.dpapi) {
            (Some(hw), Some(dp)) => format!("tpm={hw} dpapi={dp}"),
            _ => String::new(),
        };
        ctx.out.line(&format!(
            "{:>3}  {:<16} {:<12} {}",
            r.id, r.label, r.kind, details
        ))?;
    }
    Ok(())
}

#[derive(Serialize)]
struct AddReport {
    id: u8,
    label: String,
    kind: &'static str,
}

fn add(ctx: &Ctx, args: &SlotAddArgs) -> Result<()> {
    if !args.passphrase && !args.hello {
        return Err(Error::Invalid(
            "choose the slot kind: --passphrase or --hello".into(),
        ));
    }
    let default_label = if args.hello {
        LABEL_HELLO
    } else {
        LABEL_PASSPHRASE
    };
    let label = args
        .label
        .clone()
        .unwrap_or_else(|| default_label.to_string());
    if label.is_empty() {
        return Err(Error::Invalid("slot label must not be empty".into()));
    }
    // Cheap checks before the unlock prompt.
    let header = ctx.vault.read_header()?;
    ensure_label_free(&header.slots, &label)?;

    let mut v = ctx.unlock("add key slot")?;
    ensure_label_free(&v.header.slots, &label)?;
    let id = v.header.next_slot_id()?;
    let slot = if args.hello {
        seal_hello_slot(ctx, &v, id, &label, !args.no_dpapi)?
    } else {
        let secret = new_passphrase_secret(ctx, "New passphrase")?;
        seal_passphrase_slot(ctx, &v, id, &label, secret, args.argon2_test_params)?
    };
    let report = AddReport {
        id: slot.id,
        label: slot.label.clone(),
        kind: slot.kind().as_str(),
    };
    let slots: Vec<KeySlot> = v
        .header
        .slots
        .iter()
        .cloned()
        .chain(std::iter::once(slot))
        .collect();
    v = v.with_slots(slots);
    ctx.save(&mut v)?;

    if ctx.out.json {
        return ctx.out.json(&report);
    }
    ctx.out.line(&format!(
        "Added {} slot '{}' (id {})",
        report.kind, report.label, report.id
    ))
}

#[derive(Serialize)]
struct RmReport {
    removed: String,
}

fn rm(ctx: &Ctx, args: &SlotRmArgs) -> Result<()> {
    let header = ctx.vault.read_header()?;
    check_removable(&header.slots, &args.label)?;
    if !args.force {
        let ok = ctx
            .prompter
            .confirm(&format!("Remove key slot '{}'?", args.label))?;
        if !ok {
            return Err(Error::Invalid(format!(
                "removal of key slot '{}' not confirmed (use -f/--force to skip the prompt)",
                args.label
            )));
        }
    }
    let mut v = ctx.unlock("remove key slot")?;
    check_removable(&v.header.slots, &args.label)?;
    let (removed, remaining): (Vec<KeySlot>, Vec<KeySlot>) = v
        .header
        .slots
        .iter()
        .cloned()
        .partition(|s| s.label == args.label);
    v = v.with_slots(remaining);
    // Save first: external state is only destroyed once the vault that no
    // longer needs it is durably on disk.
    ctx.save_dropping_backup(&mut v)?;
    for s in &removed {
        destroy_slot_state(ctx, s, &v.header.slots);
    }

    let report = RmReport {
        removed: args.label.clone(),
    };
    if ctx.out.json {
        return ctx.out.json(&report);
    }
    ctx.out
        .line(&format!("Removed key slot '{}'", report.removed))
}

/// Validates that `label` exists and is not the last slot.
fn check_removable(slots: &[KeySlot], label: &str) -> Result<()> {
    if !slots.iter().any(|s| s.label == label) {
        return Err(Error::Invalid(format!(
            "no key slot labelled '{label}' (see `wcm slot ls`)"
        )));
    }
    if slots.len() <= 1 {
        return Err(Error::Invalid(
            "cannot remove the last remaining key slot (add another slot first)".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wcm_core::crypto::kdf::Argon2Params;

    fn pass_slot(id: u8, label: &str) -> KeySlot {
        KeySlot {
            id,
            label: label.into(),
            salt: vec![0; 32],
            nonce: vec![0; 24],
            ct: vec![0; 48],
            params: SlotParams::Passphrase {
                argon2: Argon2Params::FAST_TEST,
            },
        }
    }

    fn hello_slot(id: u8, label: &str, cred: &str) -> KeySlot {
        KeySlot {
            id,
            label: label.into(),
            salt: vec![0; 32],
            nonce: vec![0; 24],
            ct: vec![0; 48],
            params: SlotParams::Hello {
                cred_name: cred.into(),
                challenge: vec![0; 32],
                spki_der: vec![],
                dpapi: true,
                hw_backed: true,
            },
        }
    }

    #[test]
    fn removable_checks() {
        let slots = vec![pass_slot(1, "recovery"), pass_slot(2, "passphrase")];
        assert!(check_removable(&slots, "passphrase").is_ok());
        assert!(matches!(
            check_removable(&slots, "nope"),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            check_removable(&slots[..1], "recovery"),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn credentials_still_referenced_are_kept() {
        let old = hello_slot(1, "hello", "wcm-vault-1");
        // The replacement slot derives the same credential name from the vault id.
        let new = hello_slot(2, "hello", "wcm-vault-1");
        assert!(credential_shared(&old, std::slice::from_ref(&new)));
        assert!(!credential_shared(
            &old,
            &[hello_slot(2, "hello", "other"), pass_slot(3, "recovery")]
        ));
        assert!(!credential_shared(&old, &[]));
        // Passphrase slots have no external state.
        assert!(!credential_shared(&pass_slot(1, "recovery"), &[old]));
    }

    #[test]
    fn label_uniqueness() {
        let slots = vec![pass_slot(1, "recovery")];
        assert!(ensure_label_free(&slots, "x").is_ok());
        assert!(matches!(
            ensure_label_free(&slots, "recovery"),
            Err(Error::AlreadyExists(_))
        ));
    }

    #[test]
    fn slot_rows_and_kind_str() {
        let r = SlotRow::from_slot(&hello_slot(1, "hello", "c"));
        assert_eq!(
            (r.id, r.kind, r.hw_backed, r.dpapi),
            (1, "hello", Some(true), Some(true))
        );
        let r = SlotRow::from_slot(&pass_slot(2, "recovery"));
        assert_eq!((r.kind, r.hw_backed, r.dpapi), ("passphrase", None, None));
        assert_eq!(
            describe_availability(&Availability::Unsupported("x".into())),
            "x"
        );
        assert!(describe_availability(&Availability::NotEnrolled).contains("PIN"));
        assert_eq!(describe_availability(&Availability::Available), "available");
        assert!(describe_availability(&Availability::NoInteractiveSession).contains("session"));
    }
}
