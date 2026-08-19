//! Per-invocation context: vault path, backends, unlock/save helpers.

use std::path::PathBuf;

use wcm_core::crypto::kdf::Argon2Params;
use wcm_core::slot::passphrase::PassphraseBackend;
use wcm_core::slot::{
    Envelope, IdentityEnvelope, KeySlot, KeySlotBackend, SlotKind, UnlockContext,
};
use wcm_core::vault::{SlotResolver, UnlockedVault, Vault};
use wcm_core::{Error, Result};
use wcm_hello::{DpapiEnvelope, HelloOptions};

use crate::cli::Cli;
use crate::output::Output;
use crate::prompt::CliPrompter;

/// Environment variable overriding the default data directory (tests).
pub const DATA_DIR_ENV: &str = "WCM_DATA_DIR";

/// Everything a command needs.
pub struct Ctx {
    /// The vault file.
    pub vault: Vault,
    /// Output helpers.
    pub out: Output,
    /// Prompter.
    pub prompter: CliPrompter,
    /// `--slot`
    pub preferred_slot: Option<String>,
    /// `--no-input`
    pub no_input: bool,
}

impl Ctx {
    /// Builds the context from parsed arguments.
    pub fn from_cli(cli: &Cli) -> Result<Ctx> {
        let path = match &cli.vault {
            Some(p) => p.clone(),
            None => default_vault_path()?,
        };
        Ok(Ctx {
            vault: Vault::new(path),
            out: Output {
                json: cli.json,
                quiet: cli.quiet,
            },
            prompter: CliPrompter {
                no_input: cli.no_input,
                quiet: cli.quiet,
            },
            preferred_slot: cli.slot.clone(),
            no_input: cli.no_input,
        })
    }

    /// Unlock context for `vault_id`.
    pub fn unlock_ctx<'a>(&'a self, vault_id: [u8; 16], reason: &'a str) -> UnlockContext<'a> {
        UnlockContext {
            vault_id,
            reason,
            prompter: &self.prompter,
            allow_ui: !self.no_input,
        }
    }

    /// The Windows Hello backend for this machine.
    pub fn hello_backend(&self, allow_create: bool, dpapi: bool) -> Box<dyn KeySlotBackend> {
        wcm_hello::system_backend(HelloOptions {
            allow_create,
            dpapi,
            focus: true,
        })
    }

    /// A passphrase backend that prompts (or uses `WCM_PASSPHRASE`).
    pub fn passphrase_backend(&self, label: &str, params: Argon2Params) -> PassphraseBackend {
        let mut b = PassphraseBackend::prompting(label);
        b.params = params;
        b
    }

    /// Slot resolver covering Hello and passphrase slots.
    pub fn resolver(&self) -> CliResolver {
        CliResolver {
            hello: self.hello_backend(false, true),
            passphrase: self.passphrase_backend("Passphrase / recovery key", Argon2Params::DEFAULT),
            dpapi: DpapiEnvelope,
            identity: IdentityEnvelope,
        }
    }

    /// Unlocks the vault (one Hello prompt or passphrase prompt).
    pub fn unlock(&self, reason: &str) -> Result<UnlockedVault> {
        let header = self.vault.read_header()?;
        let ctx = self.unlock_ctx(header.vault_id_arr(), reason);
        let resolver = self.resolver();
        self.vault
            .unlock(&resolver, &ctx, self.preferred_slot.as_deref())
    }

    /// Saves the vault; maps concurrent modification to a friendly error.
    pub fn save(&self, v: &mut UnlockedVault) -> Result<()> {
        v.save(&self.vault)
    }

    /// Argon2 parameters honoring the hidden `--argon2-test-params` flag.
    pub fn argon2_params(test: bool) -> Argon2Params {
        if test {
            Argon2Params::FAST_TEST
        } else {
            Argon2Params::DEFAULT
        }
    }
}

/// Resolver used by the CLI for `Vault::unlock`.
pub struct CliResolver {
    hello: Box<dyn KeySlotBackend>,
    passphrase: PassphraseBackend,
    dpapi: DpapiEnvelope,
    identity: IdentityEnvelope,
}

impl SlotResolver for CliResolver {
    fn resolve(&self, slot: &KeySlot) -> Option<(&dyn KeySlotBackend, &dyn Envelope)> {
        match slot.kind() {
            SlotKind::Hello => {
                let dpapi = matches!(
                    slot.params,
                    wcm_core::slot::SlotParams::Hello { dpapi: true, .. }
                );
                let env: &dyn Envelope = if dpapi { &self.dpapi } else { &self.identity };
                Some((self.hello.as_ref(), env))
            }
            SlotKind::Passphrase => Some((&self.passphrase, &self.identity)),
        }
    }
}

/// Default vault path: `$WCM_DATA_DIR/vault.wcm` if set, else
/// `<data_local_dir>/wcm/vault.wcm` (`%LOCALAPPDATA%\wcm\vault.wcm` on Windows).
pub fn default_vault_path() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(DATA_DIR_ENV) {
        return Ok(PathBuf::from(dir).join("vault.wcm"));
    }
    let dirs = directories::BaseDirs::new()
        .ok_or_else(|| Error::Io("cannot determine the user data directory".into()))?;
    Ok(wcm_core::vault::default_vault_path(dirs.data_local_dir()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_honors_env() {
        // Tests in this crate run in parallel; use a unique var value and restore.
        let prev = std::env::var_os(DATA_DIR_ENV);
        std::env::set_var(DATA_DIR_ENV, "/tmp/wcm-test-dir");
        let p = default_vault_path().expect("path");
        assert_eq!(p, PathBuf::from("/tmp/wcm-test-dir/vault.wcm"));
        match prev {
            Some(v) => std::env::set_var(DATA_DIR_ENV, v),
            None => std::env::remove_var(DATA_DIR_ENV),
        }
    }

    #[test]
    fn argon2_params_selection() {
        assert_eq!(Ctx::argon2_params(true), Argon2Params::FAST_TEST);
        assert_eq!(Ctx::argon2_params(false), Argon2Params::DEFAULT);
    }
}
