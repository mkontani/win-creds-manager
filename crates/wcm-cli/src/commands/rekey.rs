//! `wcm rekey` — rotate the data encryption key and re-seal every key slot.
//!
//! - `recovery` slot: a NEW recovery key is generated and shown once.
//! - other passphrase slots: `WCM_PASSPHRASE` (used for all of them) or one
//!   confirmed prompt per slot.
//! - Hello slots: re-enrolled via Windows Hello (one prompt each); off-Windows
//!   the command refuses before changing anything.

use secrecy::SecretString;
use serde::Serialize;
use wcm_core::crypto::aead::random_key;
use wcm_core::recovery_key::RecoveryKey;
use wcm_core::slot::passphrase::PassphraseBackend;
use wcm_core::slot::{seal_slot, Availability, IdentityEnvelope, KeySlot, SlotKind, SlotParams};
use wcm_core::{Error, Result};

use crate::cli::RekeyArgs;
use crate::commands::init::LABEL_RECOVERY;
use crate::commands::slot::describe_availability;
use crate::context::Ctx;
use crate::prompt::passphrase_from_env;

#[derive(Serialize)]
struct RekeyReport {
    slots: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_key: Option<String>,
}

/// Passphrase for re-sealing `label`: `WCM_PASSPHRASE` if set, else a confirmed prompt.
fn passphrase_for(ctx: &Ctx, label: &str) -> Result<SecretString> {
    if let Some(s) = passphrase_from_env()? {
        return Ok(s);
    }
    ctx.prompter
        .read_hidden_confirmed(&format!("Passphrase for key slot '{label}'"))
}

/// `dpapi` flag of a Hello slot.
fn hello_dpapi(slot: &KeySlot) -> bool {
    matches!(slot.params, SlotParams::Hello { dpapi: true, .. })
}

pub fn run(ctx: &Ctx, args: &RekeyArgs) -> Result<()> {
    let header = ctx.vault.read_header()?;
    // Refuse up front if a Hello slot cannot be re-enrolled on this machine.
    if let Some(h) = header.slots.iter().find(|s| s.kind() == SlotKind::Hello) {
        let availability = ctx.hello_backend(true, hello_dpapi(h)).availability();
        if availability != Availability::Available {
            return Err(Error::AuthUnavailable(format!(
                "key slot '{}' is a Windows Hello slot and cannot be re-sealed here: {}; \
                 remove it with `wcm slot rm {}` or run `wcm rekey` on the Windows machine",
                h.label,
                describe_availability(&availability),
                h.label
            )));
        }
    }

    let mut v = ctx.unlock("rotate the vault key")?;
    let new_dek = random_key();
    let uctx = ctx.unlock_ctx(v.header.vault_id_arr(), "re-seal key slots");
    let argon2 = Ctx::argon2_params(args.argon2_test_params);
    let mut recovery_key: Option<RecoveryKey> = None;
    let mut new_slots: Vec<KeySlot> = Vec::with_capacity(v.header.slots.len());

    for slot in &v.header.slots {
        let sealed = match slot.kind() {
            SlotKind::Passphrase if slot.label == LABEL_RECOVERY => {
                let key = RecoveryKey::generate();
                let backend = PassphraseBackend::with_secret(key.as_secret(), argon2);
                recovery_key = Some(key);
                seal_slot(
                    slot.id,
                    &slot.label,
                    &backend,
                    &IdentityEnvelope,
                    &uctx,
                    &new_dek,
                )?
            }
            SlotKind::Passphrase => {
                let backend =
                    PassphraseBackend::with_secret(passphrase_for(ctx, &slot.label)?, argon2);
                seal_slot(
                    slot.id,
                    &slot.label,
                    &backend,
                    &IdentityEnvelope,
                    &uctx,
                    &new_dek,
                )?
            }
            SlotKind::Hello => {
                let dpapi = hello_dpapi(slot);
                let backend = ctx.hello_backend(true, dpapi);
                let envelope = wcm_hello::system_envelope(dpapi);
                seal_slot(
                    slot.id,
                    &slot.label,
                    backend.as_ref(),
                    envelope.as_ref(),
                    &uctx,
                    &new_dek,
                )?
            }
        };
        new_slots.push(sealed);
    }

    let report = RekeyReport {
        slots: new_slots.iter().map(|s| s.label.clone()).collect(),
        recovery_key: recovery_key.as_ref().map(RecoveryKey::display),
    };
    v = v.with_dek(new_dek).with_slots(new_slots);
    ctx.save_dropping_backup(&mut v)?;

    if ctx.out.json {
        return ctx.out.json(&report);
    }
    ctx.out.line(&format!(
        "Rotated the vault key; re-sealed key slots: {}",
        report.slots.join(", ")
    ))?;
    if let Some(key) = &report.recovery_key {
        ctx.out.line("")?;
        ctx.out
            .line("  NEW RECOVERY KEY (shown once — the previous recovery key no longer works):")?;
        ctx.out.line("")?;
        ctx.out.line(&format!("      {key}"))?;
        ctx.out.line("")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wcm_core::crypto::kdf::Argon2Params;

    #[test]
    fn hello_dpapi_flag() {
        let mk = |dpapi| KeySlot {
            id: 1,
            label: "hello".into(),
            salt: vec![0; 32],
            nonce: vec![0; 24],
            ct: vec![0; 48],
            params: SlotParams::Hello {
                cred_name: "c".into(),
                challenge: vec![0; 32],
                spki_der: vec![],
                dpapi,
                hw_backed: false,
            },
        };
        assert!(hello_dpapi(&mk(true)));
        assert!(!hello_dpapi(&mk(false)));
        let pass = KeySlot {
            id: 2,
            label: "p".into(),
            salt: vec![0; 32],
            nonce: vec![0; 24],
            ct: vec![0; 48],
            params: SlotParams::Passphrase {
                argon2: Argon2Params::FAST_TEST,
            },
        };
        assert!(!hello_dpapi(&pass));
    }
}
