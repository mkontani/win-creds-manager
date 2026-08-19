//! `wcm init` — create a vault with a Windows Hello slot and a mandatory recovery slot.

use secrecy::SecretString;
use serde::Serialize;
use wcm_core::crypto::aead::random_key;
use wcm_core::recovery_key::RecoveryKey;
use wcm_core::slot::passphrase::PassphraseBackend;
use wcm_core::slot::{seal_slot, Availability, IdentityEnvelope, KeySlot, SlotParams};
use wcm_core::vault::{new_vault_id, now_rfc3339};
use wcm_core::{Error, Result};

use crate::cli::InitArgs;
use crate::context::Ctx;
use crate::prompt::passphrase_from_env;

/// Slot labels used by `init`.
pub const LABEL_HELLO: &str = "hello";
pub const LABEL_RECOVERY: &str = "recovery";
pub const LABEL_PASSPHRASE: &str = "passphrase";

#[derive(Serialize)]
struct SlotSummary {
    id: u8,
    label: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hw_backed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dpapi: Option<bool>,
}

#[derive(Serialize)]
struct InitReport {
    vault: String,
    vault_id: String,
    hello_enrolled: bool,
    slots: Vec<SlotSummary>,
    recovery_key: String,
}

/// Summarizes a slot for status/init output.
pub fn summarize(slot: &KeySlot) -> impl Serialize {
    let (hw_backed, dpapi) = match &slot.params {
        SlotParams::Hello {
            hw_backed, dpapi, ..
        } => (Some(*hw_backed), Some(*dpapi)),
        SlotParams::Passphrase { .. } => (None, None),
    };
    SlotSummary {
        id: slot.id,
        label: slot.label.clone(),
        kind: slot.kind().as_str(),
        hw_backed,
        dpapi,
    }
}

pub fn run(ctx: &Ctx, args: &InitArgs) -> Result<()> {
    if ctx.vault.exists() {
        return Err(Error::AlreadyExists(format!(
            "vault file {} (remove it or use --vault to choose another path)",
            ctx.vault.path.display()
        )));
    }
    let vault_id = new_vault_id();
    let dek = random_key();
    let uctx = ctx.unlock_ctx(vault_id, "initialize vault");
    let argon2 = Ctx::argon2_params(args.argon2_test_params);
    let mut slots: Vec<KeySlot> = Vec::new();
    let mut next_id: u8 = 1;

    // 1. Windows Hello slot (unless --no-hello / unavailable off-Windows).
    let mut hello_enrolled = false;
    if !args.no_hello {
        let backend = ctx.hello_backend(true, !args.no_dpapi);
        match backend.availability() {
            Availability::Available => {
                let envelope = wcm_hello::system_envelope(!args.no_dpapi);
                let slot = seal_slot(
                    next_id,
                    LABEL_HELLO,
                    backend.as_ref(),
                    envelope.as_ref(),
                    &uctx,
                    &dek,
                )?;
                if let SlotParams::Hello {
                    hw_backed: false, ..
                } = &slot.params
                {
                    ctx.out
                        .warn("the Windows Hello key is not hardware (TPM) backed on this machine");
                }
                slots.push(slot);
                next_id += 1;
                hello_enrolled = true;
            }
            Availability::Unsupported(reason) if !cfg!(windows) => {
                ctx.out.notice(&format!(
                    "note: {reason}; creating a vault without a Hello slot"
                ));
            }
            other => {
                return Err(Error::AuthUnavailable(format!(
                    "Windows Hello slot cannot be created: {}; pass --no-hello to skip it",
                    describe(&other)
                )));
            }
        }
    }

    // 2. Mandatory recovery slot.
    let recovery = RecoveryKey::generate();
    let rec_backend = PassphraseBackend::with_secret(recovery.as_secret(), argon2);
    slots.push(seal_slot(
        next_id,
        LABEL_RECOVERY,
        &rec_backend,
        &IdentityEnvelope,
        &uctx,
        &dek,
    )?);
    next_id += 1;

    // 3. Optional passphrase slot.
    if args.passphrase {
        let secret: SecretString = match passphrase_from_env()? {
            Some(s) => s,
            None => ctx.prompter.read_hidden_confirmed("New passphrase")?,
        };
        let pb = PassphraseBackend::with_secret(secret, argon2);
        slots.push(seal_slot(
            next_id,
            LABEL_PASSPHRASE,
            &pb,
            &IdentityEnvelope,
            &uctx,
            &dek,
        )?);
    }

    if !hello_enrolled && !args.passphrase {
        ctx.out.warn(
            "this vault can only be opened with the recovery key (no Hello or passphrase slot)",
        );
    }

    let now = now_rfc3339();
    let unlocked = ctx.vault.create(slots, dek, vault_id, &now)?;

    let report = InitReport {
        vault: ctx.vault.path.display().to_string(),
        vault_id: unlocked.header.vault_id_hex(),
        hello_enrolled,
        slots: unlocked
            .header
            .slots
            .iter()
            .map(|s| {
                let (hw_backed, dpapi) = match &s.params {
                    SlotParams::Hello {
                        hw_backed, dpapi, ..
                    } => (Some(*hw_backed), Some(*dpapi)),
                    SlotParams::Passphrase { .. } => (None, None),
                };
                SlotSummary {
                    id: s.id,
                    label: s.label.clone(),
                    kind: s.kind().as_str(),
                    hw_backed,
                    dpapi,
                }
            })
            .collect(),
        recovery_key: recovery.display(),
    };

    if ctx.out.json {
        return ctx.out.json(&report);
    }
    ctx.out.line(&format!("Created vault {}", report.vault))?;
    ctx.out.line("")?;
    ctx.out.line(
        "  RECOVERY KEY (shown once — store it somewhere safe, e.g. a password manager or paper):",
    )?;
    ctx.out.line("")?;
    ctx.out.line(&format!("      {}", report.recovery_key))?;
    ctx.out.line("")?;
    ctx.out.line(
        "  It is the only way to open the vault if Windows Hello is reset or on another machine.",
    )?;
    if !ctx.no_input && ctx.out.stdin_is_tty() {
        let ans = ctx
            .prompter
            .read_line("Type 'yes' to confirm you have stored the recovery key: ")?;
        if ans != "yes" {
            ctx.out.warn(
                "recovery key not confirmed; you can add another slot later with `wcm slot add`",
            );
        }
    }
    Ok(())
}

fn describe(a: &Availability) -> String {
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
