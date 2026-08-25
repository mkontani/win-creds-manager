//! Per-invocation context: vault path, backends, unlock/save helpers.

use std::path::PathBuf;

use wcm_agent::Client;
use wcm_core::crypto::kdf::Argon2Params;
use wcm_core::slot::passphrase::PassphraseBackend;
use wcm_core::slot::{
    Envelope, IdentityEnvelope, KeySlot, KeySlotBackend, SlotKind, UnlockContext,
};
use wcm_core::vault::{Header, SlotResolver, UnlockedVault, Vault};
use wcm_core::{Error, Result};
use wcm_hello::{DpapiEnvelope, HelloOptions};

use crate::cli::Cli;
use crate::output::Output;
use crate::prompt::{passphrase_from_env, CliPrompter, PASSPHRASE_ENV};

/// Environment variable overriding the default data directory (tests).
pub const DATA_DIR_ENV: &str = "WCM_DATA_DIR";

/// Whether this invocation may use the session cache agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentUse {
    /// `--no-agent` / `WCM_NO_AGENT`: never talk to the agent.
    Disabled,
    /// Use the agent if one is running.
    Auto,
}

/// Environment variable disabling the agent (`1`, `true`, `yes`, `on`).
pub const NO_AGENT_ENV: &str = "WCM_NO_AGENT";

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
    /// `--no-agent`
    pub agent: AgentUse,
}

impl Ctx {
    /// Builds the context from parsed arguments.
    ///
    /// Emits the one-per-invocation `WCM_PASSPHRASE` warning.
    pub fn from_cli(cli: &Cli) -> Result<Ctx> {
        let path = match &cli.vault {
            Some(p) => p.clone(),
            None => default_vault_path()?,
        };
        let out = Output {
            json: cli.json,
            quiet: cli.quiet,
        };
        warn_env_passphrase(&out);
        Ok(Ctx {
            vault: Vault::new(path),
            out,
            prompter: CliPrompter {
                no_input: cli.no_input,
                quiet: cli.quiet,
            },
            preferred_slot: cli.slot.clone(),
            no_input: cli.no_input,
            agent: agent_use(cli),
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
        // `WCM_PASSPHRASE` must work even with `--no-input` (automation, tests);
        // a malformed value is left to the prompt path, which reports the error.
        b.secret = passphrase_from_env().ok().flatten();
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

    /// The running agent, if any and if enabled for this invocation.
    fn agent_client(&self) -> Option<Client> {
        if self.agent == AgentUse::Disabled {
            return None;
        }
        Client::discover(&default_data_dir().ok()?)
    }

    /// Unlocks the vault: from the agent's cache when possible, else with one
    /// Hello / passphrase prompt (and the key is handed to the agent).
    pub fn unlock(&self, reason: &str) -> Result<UnlockedVault> {
        let header = self.vault.read_header()?;
        let vault_id = header.vault_id_arr();
        let agent = self.agent_client();
        if let Some(agent) = &agent {
            match self.unlock_via_agent(agent, &vault_id) {
                Ok(Some(v)) => return Ok(v),
                Ok(None) => {}
                Err(e) => self
                    .out
                    .notice(&format!("agent unavailable ({e}); unlocking without it")),
            }
        }
        let v = self.unlock_with_slots(&header, reason)?;
        if let Some(agent) = &agent {
            self.cache_key(agent, &vault_id, v.dek());
        }
        Ok(v)
    }

    /// `Ok(Some)` on a cache hit; `Ok(None)` on a miss (a stale key that no
    /// longer opens the vault is dropped from the agent first).
    fn unlock_via_agent(
        &self,
        agent: &Client,
        vault_id: &[u8; 16],
    ) -> Result<Option<UnlockedVault>> {
        let Some(dek) = agent.get(vault_id)? else {
            return Ok(None);
        };
        match self.vault.open_with_dek(dek) {
            Ok(v) => Ok(Some(v)),
            Err(Error::Integrity(_)) => {
                let _ = agent.lock(vault_id);
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Best effort: a failure only costs the next prompt.
    fn cache_key(&self, agent: &Client, vault_id: &[u8; 16], dek: &wcm_core::slot::Dek) {
        if let Err(e) = agent.put(vault_id, &self.vault.path.display().to_string(), dek) {
            self.out
                .notice(&format!("agent: could not cache the vault key ({e})"));
        }
    }

    /// Unlocks with the key slots (one Hello prompt or passphrase prompt).
    fn unlock_with_slots(&self, header: &Header, reason: &str) -> Result<UnlockedVault> {
        let ctx = self.unlock_ctx(header.vault_id_arr(), reason);
        let mut resolver = self.resolver();
        // `WCM_PASSPHRASE` must work even with --no-input (allow_ui=false skips the prompter).
        resolver.passphrase.secret = passphrase_from_env()?;
        if self.preferred_slot.is_none() && resolver.passphrase.secret.is_some() {
            // An env-supplied passphrase may belong to any passphrase slot (recovery key or
            // passphrase): try each one first, treating a wrong passphrase as "not this slot".
            let mut last: Option<Error> = None;
            for slot in header
                .slots
                .iter()
                .filter(|s| s.kind() == SlotKind::Passphrase)
            {
                match self.vault.unlock(&resolver, &ctx, Some(&slot.label)) {
                    Err(e @ Error::Integrity(_)) => last = Some(e),
                    other => return other,
                }
            }
            if let Some(e) = last {
                return Err(e);
            }
        }
        self.vault
            .unlock(&resolver, &ctx, self.preferred_slot.as_deref())
    }

    /// Saves the vault; maps concurrent modification to a friendly error.
    pub fn save(&self, v: &mut UnlockedVault) -> Result<()> {
        v.save(&self.vault)
    }

    /// Saves the vault and removes `<vault>.bak`.
    ///
    /// The atomic write keeps the previous generation as `.bak`; after a key
    /// change (`rekey`, `recover`, `slot rm`) that copy still opens with key
    /// material the user just revoked, so those commands drop it.
    pub fn save_dropping_backup(&self, v: &mut UnlockedVault) -> Result<()> {
        self.save(v)?;
        // The key just changed (rekey) or was proven again (recover / slot rm):
        // refresh the agent's copy so the next command does not prompt.
        if let Some(agent) = self.agent_client() {
            self.cache_key(&agent, &v.header.vault_id_arr(), v.dek());
        }
        let bak = wcm_core::vault::file::backup_path(&self.vault.path);
        match std::fs::remove_file(&bak) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => self.out.notice(&format!(
                "note: could not remove the stale backup {}: {e}",
                bak.display()
            )),
        }
        Ok(())
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

/// Warns once per invocation when the passphrase comes from the environment.
///
/// `WCM_PASSPHRASE` bypasses every prompt, so an exported variable silently
/// turns an interactive vault into an unattended one. Suppressed by `--quiet`.
fn warn_env_passphrase(out: &Output) {
    let set = std::env::var_os(PASSPHRASE_ENV).is_some_and(|v| !v.is_empty());
    if set && !out.quiet {
        out.warn(&format!(
            "{PASSPHRASE_ENV} is set; passphrase prompts are bypassed"
        ));
    }
}

/// Data directory: `$WCM_DATA_DIR` if set, else `<data_local_dir>/wcm`
/// (`%LOCALAPPDATA%\wcm` on Windows). Holds the default vault and `agent.json`.
pub fn default_data_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(DATA_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    let dirs = directories::BaseDirs::new()
        .ok_or_else(|| Error::Io("cannot determine the user data directory".into()))?;
    Ok(dirs.data_local_dir().join("wcm"))
}

/// Default vault path: `<data dir>/vault.wcm`.
pub fn default_vault_path() -> Result<PathBuf> {
    Ok(default_data_dir()?.join("vault.wcm"))
}

/// `--no-agent` or a truthy `WCM_NO_AGENT` disables the agent.
fn agent_use(cli: &Cli) -> AgentUse {
    let env_disabled = std::env::var(NO_AGENT_ENV)
        .map(|v| crate::wsl_core::is_truthy(&v))
        .unwrap_or(false);
    if cli.no_agent || env_disabled {
        AgentUse::Disabled
    } else {
        AgentUse::Auto
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn agent_use_honors_flag_and_env() {
        let cli = Cli::parse_from(["wcm", "--no-agent", "status"]);
        assert_eq!(agent_use(&cli), AgentUse::Disabled);
        let cli = Cli::parse_from(["wcm", "status"]);
        // Only meaningful when the variable is not set in the test environment.
        if std::env::var_os(NO_AGENT_ENV).is_none() {
            assert_eq!(agent_use(&cli), AgentUse::Auto);
        }
    }

    #[test]
    fn default_path_honors_env() {
        // Tests in this crate run in parallel; use a unique var value and restore.
        let prev = std::env::var_os(DATA_DIR_ENV);
        std::env::set_var(DATA_DIR_ENV, "/tmp/wcm-test-dir");
        let p = default_vault_path().expect("path");
        assert_eq!(p, PathBuf::from("/tmp/wcm-test-dir/vault.wcm"));
        assert_eq!(
            default_data_dir().expect("dir"),
            PathBuf::from("/tmp/wcm-test-dir")
        );
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
