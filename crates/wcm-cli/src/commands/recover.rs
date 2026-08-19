//! `wcm recover` — the Windows Hello key is gone (PIN reset, TPM clear, new
//! machine): unlock with the recovery key (or a passphrase), drop every Hello
//! slot and seal a fresh one. With `--no-hello` (or where Hello is unavailable)
//! a passphrase slot labelled `passphrase` is (re)created instead; the new
//! passphrase comes from `WCM_NEW_PASSPHRASE`, else `WCM_PASSPHRASE`, else a prompt.

use serde::Serialize;
use wcm_core::slot::{Availability, KeySlot, SlotKind};
use wcm_core::vault::{Header, UnlockedVault};
use wcm_core::{Error, Result};

use crate::cli::RecoverArgs;
use crate::commands::init::{LABEL_HELLO, LABEL_PASSPHRASE, LABEL_RECOVERY};
use crate::commands::slot::{
    describe_availability, destroy_slot_state, new_passphrase_secret, seal_hello_slot,
    seal_passphrase_slot, SlotRow,
};
use crate::context::Ctx;

#[derive(Serialize)]
struct RecoverReport {
    removed_slots: Vec<String>,
    added_slot: SlotRow,
}

/// Which kind of slot `recover` will create.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Hello,
    Passphrase,
}

/// Slot tried first: `--slot`, else `recovery` when present.
fn preferred_label(ctx: &Ctx, header: &Header) -> Option<String> {
    if let Some(s) = &ctx.preferred_slot {
        return Some(s.clone());
    }
    header.slot(LABEL_RECOVERY).map(|s| s.label.clone())
}

/// Decides between a Hello and a passphrase slot (mirrors `wcm init`).
fn choose_target(ctx: &Ctx, args: &RecoverArgs) -> Result<Target> {
    if args.no_hello {
        return Ok(Target::Passphrase);
    }
    match ctx.hello_backend(true, !args.no_dpapi).availability() {
        Availability::Available => Ok(Target::Hello),
        Availability::Unsupported(reason) if !cfg!(windows) => {
            ctx.out.notice(&format!(
                "note: {reason}; re-creating a passphrase slot instead of a Windows Hello slot"
            ));
            Ok(Target::Passphrase)
        }
        other => Err(Error::AuthUnavailable(format!(
            "Windows Hello slot cannot be created: {}; pass --no-hello to create a passphrase slot instead",
            describe_availability(&other)
        ))),
    }
}

/// Slots to drop: every Hello slot, plus any slot carrying the label about to be (re)created.
fn partition_slots(slots: &[KeySlot], new_label: &str) -> (Vec<KeySlot>, Vec<KeySlot>) {
    slots
        .iter()
        .cloned()
        .partition(|s| s.kind() == SlotKind::Hello || s.label == new_label)
}

/// Lowest slot id not used by `slots`.
fn first_free_id(slots: &[KeySlot]) -> Result<u8> {
    (1..=u8::MAX)
        .find(|id| !slots.iter().any(|s| s.id == *id))
        .ok_or_else(|| Error::Invalid("no free slot id".into()))
}

pub fn run(ctx: &Ctx, args: &RecoverArgs) -> Result<()> {
    let header = ctx.vault.read_header()?;
    let target = choose_target(ctx, args)?;
    let new_label = match target {
        Target::Hello => LABEL_HELLO,
        Target::Passphrase => LABEL_PASSPHRASE,
    };

    let preferred = preferred_label(ctx, &header);
    let uctx = ctx.unlock_ctx(header.vault_id_arr(), "recover vault");
    let resolver = ctx.resolver();
    let mut v: UnlockedVault = ctx.vault.unlock(&resolver, &uctx, preferred.as_deref())?;

    let (removed, remaining) = partition_slots(&v.header.slots, new_label);
    // Best-effort cleanup of stale Hello credentials *before* enrolling the new
    // one (the credential name is derived from the vault id, so a new Hello slot
    // would otherwise share — and later lose — the credential).
    for s in &removed {
        destroy_slot_state(ctx, s, &remaining);
    }
    let next_id = first_free_id(&remaining)?;
    let added = match target {
        Target::Hello => seal_hello_slot(ctx, &v, next_id, new_label, !args.no_dpapi)?,
        Target::Passphrase => {
            let secret = new_passphrase_secret(ctx, "New passphrase")?;
            seal_passphrase_slot(ctx, &v, next_id, new_label, secret, args.argon2_test_params)?
        }
    };
    let report = RecoverReport {
        removed_slots: removed.iter().map(|s| s.label.clone()).collect(),
        added_slot: SlotRow::from_slot(&added),
    };
    let slots: Vec<KeySlot> = remaining
        .into_iter()
        .chain(std::iter::once(added))
        .collect();
    v = v.with_slots(slots);
    ctx.save(&mut v)?;

    if ctx.out.json {
        return ctx.out.json(&report);
    }
    if report.removed_slots.is_empty() {
        ctx.out.line("Removed key slots: (none)")?;
    } else {
        ctx.out.line(&format!(
            "Removed key slots: {}",
            report.removed_slots.join(", ")
        ))?;
    }
    ctx.out.line(&format!(
        "Added {} slot '{}' (id {})",
        report.added_slot.kind, report.added_slot.label, report.added_slot.id
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wcm_core::crypto::kdf::Argon2Params;
    use wcm_core::slot::SlotParams;

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

    fn hello_slot(id: u8, label: &str) -> KeySlot {
        KeySlot {
            id,
            label: label.into(),
            salt: vec![0; 32],
            nonce: vec![0; 24],
            ct: vec![0; 48],
            params: SlotParams::Hello {
                cred_name: "c".into(),
                challenge: vec![0; 32],
                spki_der: vec![],
                dpapi: false,
                hw_backed: false,
            },
        }
    }

    #[test]
    fn partition_drops_hello_and_same_label() {
        let slots = vec![
            hello_slot(1, "hello"),
            pass_slot(2, "recovery"),
            pass_slot(3, "passphrase"),
            hello_slot(4, "hello-2"),
        ];
        let (removed, remaining) = partition_slots(&slots, "passphrase");
        let r: Vec<&str> = removed.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(r, vec!["hello", "passphrase", "hello-2"]);
        let k: Vec<&str> = remaining.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(k, vec!["recovery"]);

        let (removed, remaining) = partition_slots(&slots, "hello");
        assert_eq!(removed.len(), 2);
        assert_eq!(remaining.len(), 2);
    }

    #[test]
    fn free_id_skips_used_ones() {
        assert_eq!(first_free_id(&[]).expect("id"), 1);
        assert_eq!(
            first_free_id(&[pass_slot(1, "a"), pass_slot(3, "b")]).expect("id"),
            2
        );
        assert_eq!(
            first_free_id(&[pass_slot(1, "a"), pass_slot(2, "b")]).expect("id"),
            3
        );
    }
}
