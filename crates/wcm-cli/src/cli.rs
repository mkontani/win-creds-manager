//! Command-line definitions (clap derive). This file is the contract between
//! `main.rs` and the `commands::*` modules: every subcommand's arguments live here.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum, ValueHint};

/// wcm — Windows Hello protected credential manager (usable from WSL).
#[derive(Parser, Debug)]
#[command(name = "wcm", version, about, long_about = None, propagate_version = true)]
pub struct Cli {
    /// Path of the vault file (default: %LOCALAPPDATA%\wcm\vault.wcm or $XDG_DATA_HOME/wcm/vault.wcm).
    #[arg(long, global = true, env = "WCM_VAULT", value_hint = ValueHint::FilePath)]
    pub vault: Option<PathBuf>,

    /// Machine-readable JSON output (errors go to stderr as JSON too).
    #[arg(long, global = true)]
    pub json: bool,

    /// Unlock with this key slot first (e.g. `recovery`, `passphrase`, `hello`).
    #[arg(long, global = true, value_name = "LABEL")]
    pub slot: Option<String>,

    /// Never prompt interactively (fail instead).
    #[arg(long, global = true)]
    pub no_input: bool,

    /// Do not use a running `wcm agent` for this invocation (no cache read or write; also `WCM_NO_AGENT=1`).
    #[arg(long, global = true)]
    pub no_agent: bool,

    /// Suppress informational messages on stderr.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Print the table of exit codes and exit.
    #[arg(long = "exit-codes")]
    pub exit_codes: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// All subcommands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a new vault (Windows Hello slot + mandatory recovery key).
    Init(InitArgs),
    /// Add a new item.
    Add(AddArgs),
    /// Set (upsert) one field of an existing item.
    Set(SetArgs),
    /// Print a secret field of one or more items.
    Get(GetArgs),
    /// Show an item's metadata and fields (secrets masked).
    Show(ShowArgs),
    /// List items.
    #[command(alias = "list")]
    Ls(LsArgs),
    /// Remove items.
    #[command(alias = "remove")]
    Rm(RmArgs),
    /// Rename an item.
    #[command(alias = "rename")]
    Mv(MvArgs),
    /// Generate a password or passphrase without storing it.
    #[command(alias = "gen")]
    Generate(GenerateArgs),
    /// SSH key helpers (add to agent, print public key, remove from agent).
    Ssh(SshArgs),
    /// Run a command with secrets injected as environment variables.
    Run(RunArgs),
    /// Export the vault (encrypted with a passphrase, or plaintext JSON).
    Export(ExportArgs),
    /// Import items from an export file.
    Import(ImportArgs),
    /// Re-create the Windows Hello slot using the recovery key / passphrase.
    Recover(RecoverArgs),
    /// Rotate the data encryption key (re-wraps every slot).
    Rekey(RekeyArgs),
    /// Manage key slots.
    Slot(SlotArgs),
    /// Show vault status (no unlock).
    Status(StatusArgs),
    /// Diagnose the environment (Hello, WSL, paths).
    Doctor(DoctorArgs),
    /// Session cache: keep the vault key in memory so a burst of commands needs one Hello prompt.
    Agent(AgentArgs),
    /// Internal: clear the clipboard after a timeout if it still holds the copied secret.
    #[command(hide = true)]
    Unclip(UnclipArgs),
    /// Generate shell completions.
    Completions(CompletionsArgs),
    /// Print version information.
    Version,
}

/// Item kinds accepted on the command line.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum KindArg {
    Password,
    Login,
    Token,
    SshKey,
    File,
    Note,
}

impl From<KindArg> for wcm_core::item::ItemKind {
    fn from(k: KindArg) -> Self {
        use wcm_core::item::ItemKind as K;
        match k {
            KindArg::Password => K::Password,
            KindArg::Login => K::Login,
            KindArg::Token => K::Token,
            KindArg::SshKey => K::SshKey,
            KindArg::File => K::File,
            KindArg::Note => K::Note,
        }
    }
}

/// `wcm init`
#[derive(Args, Debug)]
pub struct InitArgs {
    /// Also add a passphrase slot (prompted, or `WCM_PASSPHRASE`).
    #[arg(long)]
    pub passphrase: bool,
    /// Do not create a Windows Hello slot (non-Windows / testing).
    #[arg(long)]
    pub no_hello: bool,
    /// Do not wrap the Hello slot with DPAPI.
    #[arg(long)]
    pub no_dpapi: bool,
    /// Use tiny Argon2 parameters (tests only; weakens passphrase slots).
    #[arg(long, hide = true)]
    pub argon2_test_params: bool,
}

/// Secret source flags shared by `add` and `set`.
#[derive(Args, Debug, Clone)]
pub struct SecretSource {
    /// Read the secret from stdin (all bytes; one trailing newline stripped for text kinds).
    #[arg(long, conflicts_with_all = ["file", "generate", "value"])]
    pub stdin: bool,
    /// Read the secret from a file (binary-safe).
    #[arg(long, value_hint = ValueHint::FilePath, conflicts_with_all = ["generate", "value"])]
    pub file: Option<PathBuf>,
    /// Generate a password (optionally with a length).
    #[arg(long, value_name = "LEN", num_args = 0..=1, default_missing_value = "24", conflicts_with = "value")]
    pub generate: Option<usize>,
    /// Generate a passphrase of N words instead of characters (with --generate).
    #[arg(long, value_name = "N", requires = "generate")]
    pub words: Option<usize>,
    /// Exclude symbols from generated passwords.
    #[arg(long, requires = "generate")]
    pub no_symbols: bool,
    /// Pass the secret value directly (visible in process listings; prefer --stdin).
    #[arg(long, hide = true)]
    pub value: Option<String>,
}

/// `wcm add <name>`
#[derive(Args, Debug)]
pub struct AddArgs {
    /// Item name (e.g. `github/token`).
    pub name: String,
    /// Item kind (auto-detected: --file → file, OpenSSH key → ssh-key, else password).
    #[arg(long, value_enum)]
    pub kind: Option<KindArg>,
    #[command(flatten)]
    pub secret: SecretSource,
    /// Additional non-secret field `key=value` (repeatable), e.g. `--field username=alice`.
    #[arg(long = "field", value_name = "KEY=VALUE")]
    pub fields: Vec<String>,
    /// Free-form notes.
    #[arg(long)]
    pub notes: Option<String>,
    /// Tag (repeatable).
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
    /// Overwrite an existing item with the same name.
    #[arg(short, long)]
    pub force: bool,
    /// Also copy the (generated) secret to the clipboard.
    #[arg(long)]
    pub clip: bool,
}

/// `wcm set <name> <field>`
#[derive(Args, Debug)]
pub struct SetArgs {
    /// Item name.
    pub name: String,
    /// Field name to set (e.g. `password`, `username`, `url`).
    pub field: String,
    #[command(flatten)]
    pub secret: SecretSource,
    /// Mark the field as non-secret (shown by `show` without --reveal).
    #[arg(long)]
    pub public: bool,
    /// Remove the field instead of setting it.
    #[arg(long, conflicts_with_all = ["stdin", "file", "generate", "value"])]
    pub delete: bool,
}

/// `wcm get <name>...`
#[derive(Args, Debug)]
pub struct GetArgs {
    /// Item name(s).
    #[arg(required = true)]
    pub names: Vec<String>,
    /// Field to print (default: the kind's primary secret field).
    #[arg(long)]
    pub field: Option<String>,
    /// Write bytes exactly as stored (no trailing newline).
    #[arg(long)]
    pub raw: bool,
    /// Do not append a newline.
    #[arg(short = 'n', long)]
    pub no_newline: bool,
    /// Copy to the clipboard instead of printing.
    #[arg(long, conflicts_with = "out_file")]
    pub clip: bool,
    /// Seconds before the clipboard is cleared (with --clip).
    #[arg(long, default_value = "45", env = "WCM_CLIP_TIME")]
    pub clip_timeout: u64,
    /// Write the value to this file instead of stdout (required for binary values on a TTY).
    #[arg(long, value_hint = ValueHint::FilePath)]
    pub out_file: Option<PathBuf>,
}

/// `wcm show <name>`
#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Item name.
    pub name: String,
    /// Reveal secret fields.
    #[arg(long)]
    pub reveal: bool,
}

/// `wcm ls [PREFIX]`
#[derive(Args, Debug)]
pub struct LsArgs {
    /// Only items whose name starts with this prefix.
    pub prefix: Option<String>,
    /// Filter by kind.
    #[arg(long, value_enum)]
    pub kind: Option<KindArg>,
    /// Filter by tag.
    #[arg(long)]
    pub tag: Option<String>,
    /// Long format (kind, updated, tags).
    #[arg(short, long)]
    pub long: bool,
}

/// `wcm rm <name>...`
#[derive(Args, Debug)]
pub struct RmArgs {
    /// Item name(s).
    #[arg(required = true)]
    pub names: Vec<String>,
    /// Do not ask for confirmation.
    #[arg(short, long)]
    pub force: bool,
}

/// `wcm mv <old> <new>`
#[derive(Args, Debug)]
pub struct MvArgs {
    /// Current name.
    pub old: String,
    /// New name.
    pub new: String,
    /// Overwrite if the new name exists.
    #[arg(short, long)]
    pub force: bool,
}

/// `wcm generate [LEN]`
#[derive(Args, Debug)]
pub struct GenerateArgs {
    /// Password length.
    #[arg(default_value = "24")]
    pub length: usize,
    /// Exclude symbols.
    #[arg(long)]
    pub no_symbols: bool,
    /// Generate a passphrase of N words instead.
    #[arg(long, value_name = "N")]
    pub words: Option<usize>,
    /// Word separator for passphrases.
    #[arg(long, default_value = "-")]
    pub sep: String,
    /// Copy to clipboard instead of printing.
    #[arg(long)]
    pub clip: bool,
    /// Seconds before the clipboard is cleared (with --clip).
    #[arg(long, default_value = "45", env = "WCM_CLIP_TIME")]
    pub clip_timeout: u64,
}

/// `wcm ssh <subcommand>`
#[derive(Args, Debug)]
pub struct SshArgs {
    #[command(subcommand)]
    pub command: SshCommand,
}

/// SSH helper subcommands.
#[derive(Subcommand, Debug)]
pub enum SshCommand {
    /// Load the private key into ssh-agent (`ssh-add -`).
    Add(SshAddArgs),
    /// Print the public key (authorized_keys line).
    Pubkey(SshNameArgs),
    /// Remove the key from ssh-agent (`ssh-add -d -`).
    Remove(SshNameArgs),
}

/// `wcm ssh add <name>`
#[derive(Args, Debug)]
pub struct SshAddArgs {
    /// Item name (kind ssh-key).
    pub name: String,
    /// Key lifetime passed as `ssh-add -t` (ignored by the Windows ssh-agent service).
    #[arg(short = 't', long)]
    pub lifetime: Option<String>,
    /// Path of the `ssh-add` executable (default: from PATH).
    #[arg(long, env = "WCM_SSH_ADD", value_hint = ValueHint::FilePath)]
    pub ssh_add: Option<PathBuf>,
}

/// `wcm ssh pubkey|remove <name>`
#[derive(Args, Debug)]
pub struct SshNameArgs {
    /// Item name (kind ssh-key).
    pub name: String,
    /// Path of the `ssh-add` executable (default: from PATH).
    #[arg(long, env = "WCM_SSH_ADD", value_hint = ValueHint::FilePath)]
    pub ssh_add: Option<PathBuf>,
}

/// `wcm run --env VAR=name[/field]... -- cmd args`
#[derive(Args, Debug)]
pub struct RunArgs {
    /// Map an environment variable to an item (and optional field): `VAR=name` or `VAR=name/field`.
    #[arg(long = "env", value_name = "VAR=NAME[/FIELD]")]
    pub env: Vec<String>,
    /// Read mappings from a file with lines `VAR=wcm://name[/field]` (other lines are passed verbatim).
    #[arg(long, value_hint = ValueHint::FilePath)]
    pub env_file: Option<PathBuf>,
    /// Command and arguments to run.
    #[arg(required = true, last = true)]
    pub cmd: Vec<String>,
}

/// `wcm export`
#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Output file (default: `wcm-export-<date>.wcm`, or stdout for `--plaintext`).
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    pub out: Option<PathBuf>,
    /// Write plaintext JSON instead of an encrypted vault file. Requires --i-know.
    #[arg(long)]
    pub plaintext: bool,
    /// Acknowledge that plaintext export writes secrets unencrypted.
    #[arg(long = "i-know", requires = "plaintext")]
    pub i_know: bool,
    /// Use tiny Argon2 parameters for the export passphrase (tests only).
    #[arg(long, hide = true)]
    pub argon2_test_params: bool,
}

/// `wcm import <file>`
#[derive(Args, Debug)]
pub struct ImportArgs {
    /// Export file (`.wcm` encrypted or `.json` plaintext).
    #[arg(value_hint = ValueHint::FilePath)]
    pub file: PathBuf,
    /// Overwrite existing items with the same name.
    #[arg(long, conflicts_with = "replace")]
    pub overwrite: bool,
    /// Remove all existing items first (destructive; requires -f or a confirmation).
    #[arg(long)]
    pub replace: bool,
    /// Do not ask for confirmation (required by --replace with --no-input).
    #[arg(short, long)]
    pub force: bool,
}

/// `wcm recover`
#[derive(Args, Debug)]
pub struct RecoverArgs {
    /// Do not wrap the new Hello slot with DPAPI.
    #[arg(long)]
    pub no_dpapi: bool,
    /// Re-create a passphrase slot instead of a Hello slot (non-Windows / testing).
    #[arg(long)]
    pub no_hello: bool,
    /// Use tiny Argon2 parameters (tests only).
    #[arg(long, hide = true)]
    pub argon2_test_params: bool,
}

/// `wcm rekey`
#[derive(Args, Debug)]
pub struct RekeyArgs {
    /// Use tiny Argon2 parameters for re-sealed passphrase slots (tests only).
    #[arg(long, hide = true)]
    pub argon2_test_params: bool,
}

/// `wcm slot <subcommand>`
#[derive(Args, Debug)]
pub struct SlotArgs {
    #[command(subcommand)]
    pub command: SlotCommand,
}

/// Key-slot subcommands.
#[derive(Subcommand, Debug)]
pub enum SlotCommand {
    /// List key slots (no unlock needed).
    Ls,
    /// Add a key slot.
    Add(SlotAddArgs),
    /// Remove a key slot by label (the last slot cannot be removed).
    Rm(SlotRmArgs),
}

/// `wcm slot add`
#[derive(Args, Debug)]
pub struct SlotAddArgs {
    /// Add a passphrase slot (prompted, or `WCM_PASSPHRASE`).
    #[arg(long, conflicts_with = "hello")]
    pub passphrase: bool,
    /// Add a Windows Hello slot.
    #[arg(long)]
    pub hello: bool,
    /// Label for the new slot (default: `passphrase` / `hello`).
    #[arg(long)]
    pub label: Option<String>,
    /// Do not wrap a new Hello slot with DPAPI.
    #[arg(long)]
    pub no_dpapi: bool,
    /// Use tiny Argon2 parameters (tests only).
    #[arg(long, hide = true)]
    pub argon2_test_params: bool,
}

/// `wcm slot rm <label>`
#[derive(Args, Debug)]
pub struct SlotRmArgs {
    /// Slot label.
    pub label: String,
    /// Do not ask for confirmation.
    #[arg(short, long)]
    pub force: bool,
}

/// `wcm agent <subcommand>`
#[derive(Args, Debug)]
pub struct AgentArgs {
    #[command(subcommand)]
    pub command: AgentCommand,
}

/// Session cache agent subcommands.
#[derive(Subcommand, Debug)]
pub enum AgentCommand {
    /// Start the agent in the background (use --foreground to keep it attached).
    Start(AgentStartArgs),
    /// Stop the agent (every cached key is forgotten).
    Stop,
    /// Forget every cached key but keep the agent running.
    Lock,
    /// Show whether the agent runs and which vault keys it holds.
    Status,
}

/// `wcm agent start`
#[derive(Args, Debug)]
pub struct AgentStartArgs {
    /// Forget a key this long after its last use (e.g. 90s, 10m, 1h30m).
    #[arg(long, default_value = "10m", value_name = "DURATION")]
    pub idle: String,
    /// Forget a key this long after it was cached, even while in use.
    #[arg(long, default_value = "1h", value_name = "DURATION")]
    pub ttl: String,
    /// Forget a key after it was handed out this many times.
    #[arg(long, value_name = "N")]
    pub max_uses: Option<u32>,
    /// Run in this process instead of detaching (the detached agent runs this).
    #[arg(long)]
    pub foreground: bool,
}

/// `wcm status`
#[derive(Args, Debug)]
pub struct StatusArgs {}

/// `wcm doctor`
#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Also enroll/sign/delete a temporary Windows Hello key (shows prompts).
    #[arg(long)]
    pub hello_selftest: bool,
}

/// `wcm unclip` (internal)
#[derive(Args, Debug)]
pub struct UnclipArgs {
    /// Seconds to wait before clearing.
    #[arg(long)]
    pub timeout: u64,
    /// SHA-256 (hex) of the clipboard content to clear.
    #[arg(long)]
    pub hash: String,
}

/// `wcm completions <shell>`
#[derive(Args, Debug)]
pub struct CompletionsArgs {
    /// Shell.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn clap_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_common_invocations() {
        let c = Cli::parse_from(["wcm", "--json", "get", "a", "b", "--field", "username"]);
        assert!(c.json);
        match c.command {
            Some(Command::Get(g)) => {
                assert_eq!(g.names, vec!["a", "b"]);
                assert_eq!(g.field.as_deref(), Some("username"));
            }
            _ => panic!("expected get"),
        }
        let c = Cli::parse_from([
            "wcm",
            "add",
            "x",
            "--generate",
            "--no-symbols",
            "--field",
            "url=https://e",
        ]);
        match c.command {
            Some(Command::Add(a)) => {
                assert_eq!(a.secret.generate, Some(24));
                assert!(a.secret.no_symbols);
                assert_eq!(a.fields, vec!["url=https://e"]);
            }
            _ => panic!("expected add"),
        }
        let c = Cli::parse_from(["wcm", "run", "--env", "A=x", "--", "sh", "-c", "echo"]);
        match c.command {
            Some(Command::Run(r)) => assert_eq!(r.cmd, vec!["sh", "-c", "echo"]),
            _ => panic!("expected run"),
        }
        let c = Cli::parse_from(["wcm", "--exit-codes"]);
        assert!(c.exit_codes && c.command.is_none());

        let c = Cli::parse_from(["wcm", "agent", "start", "--idle", "5m", "--max-uses", "3"]);
        match c.command {
            Some(Command::Agent(a)) => match a.command {
                AgentCommand::Start(s) => {
                    assert_eq!(s.idle, "5m");
                    assert_eq!(s.ttl, "1h");
                    assert_eq!(s.max_uses, Some(3));
                    assert!(!s.foreground);
                }
                other => panic!("expected agent start, got {other:?}"),
            },
            _ => panic!("expected agent"),
        }
    }

    #[test]
    fn conflicting_secret_sources_are_rejected() {
        assert!(Cli::try_parse_from(["wcm", "add", "x", "--stdin", "--generate"]).is_err());
        assert!(Cli::try_parse_from(["wcm", "export", "--i-know"]).is_err());
    }
}
