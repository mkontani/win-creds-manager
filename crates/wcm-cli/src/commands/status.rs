//! `wcm status` — vault facts readable without unlocking.

use serde::Serialize;
use wcm_core::slot::SlotParams;
use wcm_core::Result;

use crate::cli::StatusArgs;
use crate::context::Ctx;

#[derive(Serialize)]
struct SlotRow {
    id: u8,
    label: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hw_backed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dpapi: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cred_name: Option<String>,
}

#[derive(Serialize)]
struct StatusReport {
    vault: String,
    exists: bool,
    vault_id: String,
    created: String,
    generation: u64,
    size_bytes: u64,
    slots: Vec<SlotRow>,
    backup_exists: bool,
}

pub fn run(ctx: &Ctx, _args: &StatusArgs) -> Result<()> {
    let header = ctx.vault.read_header()?;
    let size = std::fs::metadata(&ctx.vault.path)
        .map(|m| m.len())
        .unwrap_or(0);
    let report = StatusReport {
        vault: ctx.vault.path.display().to_string(),
        exists: true,
        vault_id: header.vault_id_hex(),
        created: header.created.clone(),
        generation: header.generation,
        size_bytes: size,
        slots: header
            .slots
            .iter()
            .map(|s| {
                let (hw_backed, dpapi, cred_name) = match &s.params {
                    SlotParams::Hello {
                        hw_backed,
                        dpapi,
                        cred_name,
                        ..
                    } => (Some(*hw_backed), Some(*dpapi), Some(cred_name.clone())),
                    SlotParams::Passphrase { .. } => (None, None, None),
                };
                SlotRow {
                    id: s.id,
                    label: s.label.clone(),
                    kind: s.kind().as_str(),
                    hw_backed,
                    dpapi,
                    cred_name,
                }
            })
            .collect(),
        backup_exists: wcm_core::vault::file::backup_path(&ctx.vault.path).exists(),
    };
    if ctx.out.json {
        return ctx.out.json(&report);
    }
    ctx.out.line(&format!("vault:      {}", report.vault))?;
    ctx.out.line(&format!("vault id:   {}", report.vault_id))?;
    ctx.out.line(&format!("created:    {}", report.created))?;
    ctx.out
        .line(&format!("generation: {}", report.generation))?;
    ctx.out
        .line(&format!("size:       {} bytes", report.size_bytes))?;
    ctx.out.line("slots:")?;
    for s in &report.slots {
        let extra = match (s.hw_backed, s.dpapi) {
            (Some(hw), Some(dp)) => format!("  tpm={hw} dpapi={dp}"),
            _ => String::new(),
        };
        ctx.out
            .line(&format!("  [{}] {:<12} {}{}", s.id, s.label, s.kind, extra))?;
    }
    Ok(())
}
