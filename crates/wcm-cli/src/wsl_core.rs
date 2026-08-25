//! Platform-independent logic of the WSL shim: detection, `wcm.exe` lookup,
//! argument translation, `ssh add/remove` argv parsing, WSLENV handling.
//!
//! Nothing in here touches the environment, the file system or processes —
//! callers (`wsl.rs`, Linux only) inject fakes, so every branch is unit-tested
//! on macOS/Windows too.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))] // consumed by `wsl.rs` (Linux only)

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Environment snapshot passed to the pure functions.
pub type Env = HashMap<String, String>;

/// Test hook: `WCM_FORCE_WSL=1` pretends we run under WSL2.
pub const ENV_FORCE_WSL: &str = "WCM_FORCE_WSL";
/// Explicit path of `wcm.exe` (highest priority).
pub const ENV_WINDOWS_EXE: &str = "WCM_WINDOWS_EXE";
/// `WCM_NO_WSL_PROXY=1` disables the proxy (run the Linux build natively).
pub const ENV_NO_PROXY: &str = "WCM_NO_WSL_PROXY";
/// Set on the child: marks an invocation that already went through the shim.
pub const ENV_LAUNCHED: &str = "WCM_LAUNCHED_FROM_WSL";
/// Set on the child: WSL flavour (`WSL1`/`WSL2`), shown by wcm.exe's `doctor`.
pub const ENV_WSL_KIND: &str = "WCM_WSL_KIND";
/// Set on the child: `wcm.exe` path as seen from WSL, shown by wcm.exe's `doctor`.
pub const ENV_WSL_EXE: &str = "WCM_WSL_EXE";
/// Vault path environment variable (translated into `--vault` for wcm.exe).
pub const ENV_VAULT: &str = "WCM_VAULT";
/// Set by WSL2 on interop-enabled sessions.
pub const ENV_WSL_INTEROP: &str = "WSL_INTEROP";
/// Windows binary name.
pub const WINDOWS_EXE_NAME: &str = "wcm.exe";
/// WSLENV entries the shim appends so wcm.exe sees them.
pub const WSLENV_EXTRA: &str = "WCM_LAUNCHED_FROM_WSL/w:WCM_WSL_KIND/w:WCM_WSL_EXE/w:\
                                WCM_PASSPHRASE/w:WCM_EXPORT_PASSPHRASE/w:WCM_NO_AGENT/w";
/// `errno` value of `Exec format error` (identical on every Linux architecture).
pub const ENOEXEC: i32 = 8;

/// Options whose value is a path that must be translated for wcm.exe.
const PATH_OPTS: &[&str] = &[
    "--vault",
    "--file",
    "--out-file",
    "--env-file",
    "-o",
    "--out",
];
/// Global options that take a (non-path) value; their value must not be mistaken
/// for a subcommand or positional.
const GLOBAL_VALUE_OPTS: &[&str] = &["--slot"];

/// WSL flavour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WslKind {
    Wsl1,
    Wsl2,
}

impl std::fmt::Display for WslKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            WslKind::Wsl1 => "WSL1",
            WslKind::Wsl2 => "WSL2",
        })
    }
}

/// Detects WSL from `/proc/version` and the environment.
pub fn detect(proc_version: &str, env: &Env) -> Option<WslKind> {
    if env.get(ENV_FORCE_WSL).is_some_and(|v| is_truthy(v)) {
        return Some(WslKind::Wsl2);
    }
    if env.contains_key(ENV_WSL_INTEROP) {
        return Some(WslKind::Wsl2);
    }
    let pv = proc_version.to_ascii_lowercase();
    if !pv.contains("microsoft") {
        return None;
    }
    if pv.contains("wsl2") || pv.contains("microsoft-standard") {
        Some(WslKind::Wsl2)
    } else {
        Some(WslKind::Wsl1)
    }
}

/// `1`, `true`, `yes` (case-insensitive) count as enabled.
pub fn is_truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Locates `wcm.exe`: `$WCM_WINDOWS_EXE` (if it exists) → `wcm.exe` in
/// `path_entries` → first existing `mnt_candidates` entry.
pub fn find_exe(
    env: &Env,
    path_entries: &[PathBuf],
    mnt_candidates: &[PathBuf],
    exists: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    if let Some(p) = env.get(ENV_WINDOWS_EXE).filter(|s| !s.is_empty()) {
        let p = PathBuf::from(p);
        if exists(&p) {
            return Some(p);
        }
    }
    path_entries
        .iter()
        .map(|dir| dir.join(WINDOWS_EXE_NAME))
        .chain(mnt_candidates.iter().cloned())
        .find(|p| exists(p))
}

/// Candidate `wcm.exe` locations under Windows user profile directories
/// (`/mnt/<drive>/Users/<name>`), in priority order.
pub fn candidate_paths(user_dirs: &[PathBuf]) -> Vec<PathBuf> {
    user_dirs
        .iter()
        .flat_map(|home| {
            [
                home.join("AppData/Local/Programs/wcm")
                    .join(WINDOWS_EXE_NAME),
                home.join(".cargo/bin").join(WINDOWS_EXE_NAME),
            ]
        })
        .collect()
}

/// `C:\...`, `\\server\share`, `\\wsl$\...` — already a Windows path.
pub fn looks_like_windows_path(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':') || s.starts_with("\\\\")
}

/// Translates the VALUE of path options (`--vault`, `--file`, `--out-file`,
/// `--env-file`, `-o`/`--out`) and the positional FILE of `import` with
/// `to_windows`. Supports `--opt value` and `--opt=value`. Everything after a
/// bare `--` and every other token is passed through untouched; values for
/// which `to_windows` returns `None` keep their original spelling.
pub fn translate_args(
    args: &[String],
    to_windows: &dyn Fn(&Path) -> Option<String>,
) -> Vec<String> {
    let tr = |v: &str| -> String {
        if v == "-" || v.is_empty() || looks_like_windows_path(v) {
            return v.to_string();
        }
        to_windows(Path::new(v)).unwrap_or_else(|| v.to_string())
    };
    let mut out = Vec::with_capacity(args.len() + 2);
    let mut subcommand: Option<String> = None;
    let mut import_file_seen = false;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            out.extend(args[i..].iter().cloned());
            break;
        }
        if is_option(a) {
            if let Some((opt, val)) = a.split_once('=') {
                if PATH_OPTS.contains(&opt) {
                    out.push(format!("{opt}={}", tr(val)));
                } else {
                    out.push(a.clone());
                }
                i += 1;
                continue;
            }
            out.push(a.clone());
            let takes_value =
                PATH_OPTS.contains(&a.as_str()) || GLOBAL_VALUE_OPTS.contains(&a.as_str());
            if takes_value && i + 1 < args.len() {
                let v = &args[i + 1];
                if PATH_OPTS.contains(&a.as_str()) {
                    out.push(tr(v));
                } else {
                    out.push(v.clone());
                }
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        match subcommand.as_deref() {
            None => {
                subcommand = Some(a.clone());
                out.push(a.clone());
            }
            Some("import") if !import_file_seen => {
                import_file_seen = true;
                out.push(tr(a));
            }
            _ => out.push(a.clone()),
        }
        i += 1;
    }
    out
}

fn is_option(a: &str) -> bool {
    a.len() > 1 && a.starts_with('-')
}

/// Whether `--vault` (or `--vault=…`) is present before any `--`.
pub fn has_vault_arg(args: &[String]) -> bool {
    args.iter()
        .take_while(|a| *a != "--")
        .any(|a| a == "--vault" || a.starts_with("--vault="))
}

/// Full argv for wcm.exe: translated `args`, plus `--vault <translated $WCM_VAULT>`
/// prepended when the variable is set and no `--vault` was given (Windows
/// processes do not inherit the Linux environment).
pub fn build_windows_args(
    args: &[String],
    env: &Env,
    to_windows: &dyn Fn(&Path) -> Option<String>,
) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len() + 2);
    if !has_vault_arg(args) {
        if let Some(v) = env.get(ENV_VAULT).filter(|v| !v.is_empty()) {
            let translated = if looks_like_windows_path(v) {
                v.clone()
            } else {
                to_windows(Path::new(v)).unwrap_or_else(|| v.clone())
            };
            out.push("--vault".to_string());
            out.push(translated);
        }
    }
    out.extend(translate_args(args, to_windows));
    out
}

/// Appends the shim's entries to an existing `WSLENV` value.
pub fn extend_wslenv(existing: Option<&str>) -> String {
    match existing.map(str::trim).filter(|s| !s.is_empty()) {
        Some(e) if e.split(':').any(|x| x == "WCM_LAUNCHED_FROM_WSL/w") => e.to_string(),
        Some(e) => format!("{e}:{WSLENV_EXTRA}"),
        None => WSLENV_EXTRA.to_string(),
    }
}

/// WSL context the shim exports to its wcm.exe child (see [`WSLENV_EXTRA`]).
#[cfg_attr(target_os = "linux", allow(dead_code))] // read by `doctor` on the wcm.exe side
pub struct ShimWslContext {
    pub kind: Option<String>,
    pub windows_exe: Option<String>,
}

/// `Some` when this process was proxied from WSL by the shim — the wcm.exe
/// side of the boundary; `None` for a plain Windows run.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub fn shim_wsl_context(env: &Env) -> Option<ShimWslContext> {
    env.contains_key(ENV_LAUNCHED).then(|| ShimWslContext {
        kind: env.get(ENV_WSL_KIND).filter(|v| !v.is_empty()).cloned(),
        windows_exe: env.get(ENV_WSL_EXE).filter(|v| !v.is_empty()).cloned(),
    })
}

/// `--json` given (before any `--`)?
pub fn wants_json(args: &[String]) -> bool {
    args.iter()
        .take_while(|a| *a != "--")
        .any(|a| a == "--json")
}

/// Joins a Windows directory and a file name with a single backslash.
pub fn join_windows(parent: &str, name: &str) -> String {
    let p = parent.trim_end_matches(['\\', '/']);
    if p.is_empty() {
        name.to_string()
    } else {
        format!("{p}\\{name}")
    }
}

/// Rough classification of an executable by its leading bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExeKind {
    /// Windows PE (`MZ`) — needs binfmt_misc interop.
    Pe,
    /// Native ELF.
    Elf,
    /// `#!` script.
    Script,
    /// Anything else (the kernel would answer `ENOEXEC`).
    Unknown,
}

/// Classifies `magic` (the first bytes of a file).
pub fn exe_kind(magic: &[u8]) -> ExeKind {
    if magic.starts_with(b"MZ") {
        ExeKind::Pe
    } else if magic.starts_with(b"\x7fELF") {
        ExeKind::Elf
    } else if magic.starts_with(b"#!") {
        ExeKind::Script
    } else {
        ExeKind::Unknown
    }
}

/// Parses `/proc/sys/fs/binfmt_misc/WSLInterop` (first line is `enabled` / `disabled`).
pub fn interop_enabled(binfmt_status: &str) -> bool {
    binfmt_status.lines().next().map(str::trim) == Some("enabled")
}

/// `ssh add` / `ssh remove` must talk to the *Linux* ssh-agent, so they are not exec'd.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshAgentOp {
    Add,
    Remove,
}

/// A parsed `wcm [globals] ssh add|remove <name> [-t L] [--ssh-add P]` invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshAction {
    pub op: SshAgentOp,
    pub name: String,
    /// `-t/--lifetime` (add only).
    pub lifetime: Option<String>,
    /// `--ssh-add PATH` override.
    pub ssh_add: Option<String>,
    /// Global options to forward to wcm.exe (`--vault X`, `--slot X`, `--no-input`, `-q`); never `--json`.
    pub globals: Vec<String>,
    /// `--json` was requested.
    pub json: bool,
    /// `-q/--quiet` was requested.
    pub quiet: bool,
}

impl SshAction {
    /// Arguments for wcm.exe that produce the key material on stdout.
    pub fn exe_args(&self) -> Vec<String> {
        let mut v = self.globals.clone();
        match self.op {
            SshAgentOp::Add => v.extend(
                ["get", &self.name, "--field", "private_key", "--raw"]
                    .iter()
                    .map(|s| s.to_string()),
            ),
            SshAgentOp::Remove => {
                v.extend(["ssh", "pubkey", &self.name].iter().map(|s| s.to_string()))
            }
        }
        v
    }

    /// Arguments for the Linux `ssh-add` (key on stdin).
    pub fn ssh_add_args(&self) -> Vec<String> {
        let mut v = Vec::new();
        match self.op {
            SshAgentOp::Add => {
                if let Some(t) = &self.lifetime {
                    v.push("-t".to_string());
                    v.push(t.clone());
                }
            }
            SshAgentOp::Remove => v.push("-d".to_string()),
        }
        v.push("-".to_string());
        v
    }
}

/// Recognizes `ssh add <name>` / `ssh remove <name>` (with global options anywhere).
/// Returns `None` for anything else — including `--help`, missing name or
/// unknown options — so wcm.exe produces the usage error / help itself.
pub fn parse_ssh_action(args: &[String]) -> Option<SshAction> {
    let mut globals = Vec::new();
    let mut positionals: Vec<&str> = Vec::new();
    let mut lifetime = None;
    let mut ssh_add = None;
    let mut json = false;
    let mut quiet = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            return None;
        }
        if !is_option(a) {
            positionals.push(a);
            i += 1;
            continue;
        }
        let (opt, inline) = match a.split_once('=') {
            Some((o, v)) => (o, Some(v.to_string())),
            None => (a, None),
        };
        let mut take_value = || -> Option<String> {
            if let Some(v) = &inline {
                return Some(v.clone());
            }
            let v = args.get(i + 1)?.clone();
            i += 1;
            Some(v)
        };
        match opt {
            "--json" if inline.is_none() => json = true,
            "-q" | "--quiet" if inline.is_none() => {
                quiet = true;
                globals.push("-q".to_string());
            }
            "--no-input" | "--no-agent" if inline.is_none() => globals.push(a.to_string()),
            "--vault" | "--slot" => {
                let v = take_value()?;
                globals.push(opt.to_string());
                globals.push(v);
            }
            "-t" | "--lifetime" => lifetime = Some(take_value()?),
            "--ssh-add" => ssh_add = Some(take_value()?),
            _ => return None,
        }
        i += 1;
    }
    let [cmd, sub, name] = positionals.as_slice() else {
        return None;
    };
    if *cmd != "ssh" {
        return None;
    }
    let op = match *sub {
        "add" => SshAgentOp::Add,
        "remove" => SshAgentOp::Remove,
        _ => return None,
    };
    if op == SshAgentOp::Remove && lifetime.is_some() {
        return None;
    }
    Some(SshAction {
        op,
        name: (*name).to_string(),
        lifetime,
        ssh_add,
        globals,
        json,
        quiet,
    })
}

/// Maps a child's exit status to our exit code (signals → 130 for SIGINT, else 1).
pub fn exit_code_from(code: Option<i32>, signal: Option<i32>) -> u8 {
    match (code, signal) {
        (Some(c), _) => u8::try_from(c).unwrap_or(1),
        (None, Some(2)) => wcm_core::error::EXIT_INTERRUPTED,
        (None, _) => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn fake_to_windows(p: &Path) -> Option<String> {
        let s = p.to_string_lossy();
        if s.contains("untranslatable") {
            None
        } else {
            Some(format!("W:{}", s.replace('/', "\\")))
        }
    }

    #[test]
    fn detect_force_hook() {
        assert_eq!(
            detect("Linux version 6.1.0 (gcc)", &env(&[("WCM_FORCE_WSL", "1")])),
            Some(WslKind::Wsl2)
        );
        assert_eq!(
            detect("Linux version 6.1.0 (gcc)", &env(&[("WCM_FORCE_WSL", "0")])),
            None
        );
    }

    #[test]
    fn detect_wsl_interop_env() {
        assert_eq!(
            detect(
                "Linux version 6.1.0",
                &env(&[("WSL_INTEROP", "/run/WSL/1_interop")])
            ),
            Some(WslKind::Wsl2)
        );
    }

    #[test]
    fn detect_proc_version() {
        let e = env(&[]);
        assert_eq!(
            detect(
                "Linux version 5.15.90.1-microsoft-standard-WSL2 (oe-user@oe-host)",
                &e
            ),
            Some(WslKind::Wsl2)
        );
        assert_eq!(
            detect(
                "Linux version 4.19.128-microsoft-standard (oe-user@oe-host)",
                &e
            ),
            Some(WslKind::Wsl2)
        );
        assert_eq!(
            detect(
                "Linux version 4.4.0-19041-Microsoft (Microsoft@Microsoft.com)",
                &e
            ),
            Some(WslKind::Wsl1)
        );
        assert_eq!(
            detect("Linux version 6.8.0-generic (buildd@lcy02)", &e),
            None
        );
        assert_eq!(detect("", &e), None);
        assert_eq!(WslKind::Wsl1.to_string(), "WSL1");
        assert_eq!(WslKind::Wsl2.to_string(), "WSL2");
    }

    #[test]
    fn find_exe_prefers_env_then_path_then_candidates() {
        let existing = [
            PathBuf::from("/custom/wcm.exe"),
            PathBuf::from("/mnt/c/bin/wcm.exe"),
            PathBuf::from("/mnt/c/Users/bob/.cargo/bin/wcm.exe"),
        ];
        let exists = |p: &Path| existing.iter().any(|e| e == p);
        let path_entries = [PathBuf::from("/usr/bin"), PathBuf::from("/mnt/c/bin")];
        let cands = candidate_paths(&[
            PathBuf::from("/mnt/c/Users/alice"),
            PathBuf::from("/mnt/c/Users/bob"),
        ]);
        assert_eq!(
            cands,
            vec![
                PathBuf::from("/mnt/c/Users/alice/AppData/Local/Programs/wcm/wcm.exe"),
                PathBuf::from("/mnt/c/Users/alice/.cargo/bin/wcm.exe"),
                PathBuf::from("/mnt/c/Users/bob/AppData/Local/Programs/wcm/wcm.exe"),
                PathBuf::from("/mnt/c/Users/bob/.cargo/bin/wcm.exe"),
            ]
        );
        // env wins
        assert_eq!(
            find_exe(
                &env(&[("WCM_WINDOWS_EXE", "/custom/wcm.exe")]),
                &path_entries,
                &cands,
                &exists
            ),
            Some(PathBuf::from("/custom/wcm.exe"))
        );
        // env set but missing → fall through to PATH
        assert_eq!(
            find_exe(
                &env(&[("WCM_WINDOWS_EXE", "/nonexistent")]),
                &path_entries,
                &cands,
                &exists
            ),
            Some(PathBuf::from("/mnt/c/bin/wcm.exe"))
        );
        // PATH
        assert_eq!(
            find_exe(&env(&[]), &path_entries, &cands, &exists),
            Some(PathBuf::from("/mnt/c/bin/wcm.exe"))
        );
        // candidates
        assert_eq!(
            find_exe(&env(&[]), &[PathBuf::from("/usr/bin")], &cands, &exists),
            Some(PathBuf::from("/mnt/c/Users/bob/.cargo/bin/wcm.exe"))
        );
        // nothing
        assert_eq!(find_exe(&env(&[]), &[], &[], &exists), None);
        assert_eq!(
            find_exe(&env(&[("WCM_WINDOWS_EXE", "")]), &[], &[], &exists),
            None
        );
    }

    #[test]
    fn translate_path_options_both_forms() {
        let a = args(&[
            "--vault",
            "/home/u/v.wcm",
            "add",
            "x",
            "--file=/tmp/secret.bin",
            "--field",
            "url=https://e/x",
            "--tag",
            "t",
        ]);
        let t = translate_args(&a, &fake_to_windows);
        assert_eq!(
            t,
            args(&[
                "--vault",
                "W:\\home\\u\\v.wcm",
                "add",
                "x",
                "--file=W:\\tmp\\secret.bin",
                "--field",
                "url=https://e/x",
                "--tag",
                "t",
            ])
        );
        let a = args(&["get", "x", "--out-file", "/o/f", "-n"]);
        assert_eq!(
            translate_args(&a, &fake_to_windows),
            args(&["get", "x", "--out-file", "W:\\o\\f", "-n"])
        );
        let a = args(&["export", "-o", "/e.wcm"]);
        assert_eq!(
            translate_args(&a, &fake_to_windows),
            args(&["export", "-o", "W:\\e.wcm"])
        );
        let a = args(&["export", "--out=/e.wcm", "--plaintext", "--i-know"]);
        assert_eq!(
            translate_args(&a, &fake_to_windows),
            args(&["export", "--out=W:\\e.wcm", "--plaintext", "--i-know"])
        );
        let a = args(&[
            "run",
            "--env-file",
            "/r/.env",
            "--env",
            "A=x",
            "--",
            "sh",
            "-c",
            "cat /etc/passwd",
        ]);
        assert_eq!(
            translate_args(&a, &fake_to_windows),
            args(&[
                "run",
                "--env-file",
                "W:\\r\\.env",
                "--env",
                "A=x",
                "--",
                "sh",
                "-c",
                "cat /etc/passwd"
            ])
        );
    }

    #[test]
    fn translate_import_positional_and_skips_global_values() {
        let a = args(&["--slot", "recovery", "import", "--replace", "/x/export.wcm"]);
        assert_eq!(
            translate_args(&a, &fake_to_windows),
            args(&[
                "--slot",
                "recovery",
                "import",
                "--replace",
                "W:\\x\\export.wcm"
            ])
        );
        // a slot label that looks like a subcommand must not confuse the parser
        let a = args(&["--slot=import", "ls", "prefix"]);
        assert_eq!(translate_args(&a, &fake_to_windows), a);
        // only the first positional of import is the FILE
        let a = args(&["import", "/a", "/b"]);
        assert_eq!(
            translate_args(&a, &fake_to_windows),
            args(&["import", "W:\\a", "/b"])
        );
    }

    #[test]
    fn translate_leaves_non_path_things_alone() {
        let a = args(&[
            "ssh",
            "add",
            "key",
            "--ssh-add",
            "/usr/bin/ssh-add",
            "-t",
            "1h",
        ]);
        assert_eq!(translate_args(&a, &fake_to_windows), a);
        let a = args(&["get", "x", "--out-file", "-"]);
        assert_eq!(translate_args(&a, &fake_to_windows), a);
        let a = args(&["--vault", "C:\\Users\\u\\vault.wcm", "ls"]);
        assert_eq!(translate_args(&a, &fake_to_windows), a);
        let a = args(&["--vault", "\\\\wsl$\\Ubuntu\\home\\u\\v.wcm", "ls"]);
        assert_eq!(translate_args(&a, &fake_to_windows), a);
        // untranslatable → original kept
        let a = args(&["--vault", "/untranslatable/v", "ls"]);
        assert_eq!(translate_args(&a, &fake_to_windows), a);
        // option at the very end without a value
        let a = args(&["get", "x", "--out-file"]);
        assert_eq!(translate_args(&a, &fake_to_windows), a);
        let a: Vec<String> = vec![];
        assert!(translate_args(&a, &fake_to_windows).is_empty());
    }

    #[test]
    fn build_windows_args_injects_vault_from_env() {
        let e = env(&[("WCM_VAULT", "/home/u/.local/share/wcm/vault.wcm")]);
        assert_eq!(
            build_windows_args(&args(&["--json", "ls"]), &e, &fake_to_windows),
            args(&[
                "--vault",
                "W:\\home\\u\\.local\\share\\wcm\\vault.wcm",
                "--json",
                "ls"
            ])
        );
        // explicit --vault wins
        assert_eq!(
            build_windows_args(&args(&["--vault", "/v", "ls"]), &e, &fake_to_windows),
            args(&["--vault", "W:\\v", "ls"])
        );
        assert_eq!(
            build_windows_args(&args(&["ls", "--vault=/v"]), &e, &fake_to_windows),
            args(&["ls", "--vault=W:\\v"])
        );
        // no env → nothing injected
        assert_eq!(
            build_windows_args(&args(&["ls"]), &env(&[]), &fake_to_windows),
            args(&["ls"])
        );
        // Windows-style value passes through; untranslatable keeps original
        let e = env(&[("WCM_VAULT", "D:\\v.wcm")]);
        assert_eq!(
            build_windows_args(&args(&["ls"]), &e, &fake_to_windows),
            args(&["--vault", "D:\\v.wcm", "ls"])
        );
        let e = env(&[("WCM_VAULT", "/untranslatable")]);
        assert_eq!(
            build_windows_args(&args(&["ls"]), &e, &fake_to_windows),
            args(&["--vault", "/untranslatable", "ls"])
        );
        // --vault after `--` does not count
        let e = env(&[("WCM_VAULT", "/v")]);
        assert_eq!(
            build_windows_args(
                &args(&["run", "--", "x", "--vault", "y"]),
                &e,
                &fake_to_windows
            ),
            args(&["--vault", "W:\\v", "run", "--", "x", "--vault", "y"])
        );
    }

    #[test]
    fn wslenv_is_extended_once() {
        assert_eq!(extend_wslenv(None), WSLENV_EXTRA);
        assert_eq!(extend_wslenv(Some("")), WSLENV_EXTRA);
        assert_eq!(
            extend_wslenv(Some("FOO/p:BAR")),
            format!("FOO/p:BAR:{WSLENV_EXTRA}")
        );
        let once = extend_wslenv(Some("X"));
        assert_eq!(extend_wslenv(Some(&once)), once);
    }

    #[test]
    fn wslenv_extra_carries_shim_context() {
        for entry in ["WCM_LAUNCHED_FROM_WSL/w", "WCM_WSL_KIND/w", "WCM_WSL_EXE/w"] {
            assert!(
                WSLENV_EXTRA.split(':').any(|x| x == entry),
                "{entry} missing from WSLENV_EXTRA"
            );
        }
    }

    #[test]
    fn wslenv_extra_carries_no_agent() {
        assert!(
            WSLENV_EXTRA.split(':').any(|x| x == "WCM_NO_AGENT/w"),
            "WCM_NO_AGENT/w missing from WSLENV_EXTRA"
        );
    }

    #[test]
    fn shim_wsl_context_reads_proxied_env() {
        // Plain (non-proxied) run: no context.
        assert!(shim_wsl_context(&env(&[])).is_none());
        // Proxied run: the shim exported kind and exe path through WSLENV.
        let ctx = shim_wsl_context(&env(&[
            ("WCM_LAUNCHED_FROM_WSL", "1"),
            ("WCM_WSL_KIND", "WSL2"),
            ("WCM_WSL_EXE", "/mnt/c/Users/u/wcm.exe"),
        ]))
        .expect("proxied run must yield a context");
        assert_eq!(ctx.kind.as_deref(), Some("WSL2"));
        assert_eq!(ctx.windows_exe.as_deref(), Some("/mnt/c/Users/u/wcm.exe"));
        // Launched flag alone: detected, but details unknown (empty values dropped).
        let ctx = shim_wsl_context(&env(&[
            ("WCM_LAUNCHED_FROM_WSL", "1"),
            ("WCM_WSL_KIND", ""),
        ]))
        .expect("proxied run must yield a context");
        assert!(ctx.kind.is_none());
        assert!(ctx.windows_exe.is_none());
    }

    #[test]
    fn ssh_action_parsing() {
        let a = args(&[
            "--vault",
            "W:\\v",
            "ssh",
            "add",
            "mykey",
            "-t",
            "1h",
            "--no-input",
        ]);
        let act = parse_ssh_action(&a).expect("add");
        assert_eq!(act.op, SshAgentOp::Add);
        assert_eq!(act.name, "mykey");
        assert_eq!(act.lifetime.as_deref(), Some("1h"));
        assert_eq!(act.globals, args(&["--vault", "W:\\v", "--no-input"]));
        assert!(!act.json && !act.quiet);
        assert_eq!(
            act.exe_args(),
            args(&[
                "--vault",
                "W:\\v",
                "--no-input",
                "get",
                "mykey",
                "--field",
                "private_key",
                "--raw"
            ])
        );
        assert_eq!(act.ssh_add_args(), args(&["-t", "1h", "-"]));

        let a = args(&[
            "--json",
            "-q",
            "ssh",
            "remove",
            "k",
            "--ssh-add=/opt/ssh-add",
            "--slot=recovery",
        ]);
        let act = parse_ssh_action(&a).expect("remove");
        assert_eq!(act.op, SshAgentOp::Remove);
        assert!(act.json && act.quiet);
        assert_eq!(act.ssh_add.as_deref(), Some("/opt/ssh-add"));
        assert_eq!(act.globals, args(&["-q", "--slot", "recovery"]));
        assert_eq!(
            act.exe_args(),
            args(&["-q", "--slot", "recovery", "ssh", "pubkey", "k"])
        );
        assert_eq!(act.ssh_add_args(), args(&["-d", "-"]));

        let a = args(&["ssh", "add", "k", "--lifetime=30m"]);
        assert_eq!(
            parse_ssh_action(&a).expect("add").lifetime.as_deref(),
            Some("30m")
        );
    }

    #[test]
    fn ssh_action_forwards_no_agent() {
        let a = args(&["--no-agent", "ssh", "add", "k"]);
        let act = parse_ssh_action(&a).expect("add");
        assert_eq!(act.globals, args(&["--no-agent"]));
    }

    #[test]
    fn ssh_action_rejects_everything_else() {
        for case in [
            vec!["ssh", "pubkey", "k"],
            vec!["ssh", "add"],
            vec!["ssh", "add", "k", "extra"],
            vec!["ssh", "add", "k", "--help"],
            vec!["ssh", "add", "-h"],
            vec!["ssh", "remove", "k", "-t", "1h"],
            vec!["ssh", "add", "k", "-t"],
            vec!["ssh", "add", "k", "--json=1"],
            vec!["get", "k"],
            vec!["run", "--", "ssh", "add", "k"],
            vec!["--version"],
            vec![],
        ] {
            assert_eq!(parse_ssh_action(&args(&case)), None, "{case:?}");
        }
    }

    #[test]
    fn exe_kind_and_interop_status() {
        assert_eq!(exe_kind(b"MZ\x90\x00"), ExeKind::Pe);
        assert_eq!(exe_kind(b"\x7fELF\x02"), ExeKind::Elf);
        assert_eq!(exe_kind(b"#!/bin/sh\n"), ExeKind::Script);
        assert_eq!(exe_kind(b"hello"), ExeKind::Unknown);
        assert_eq!(exe_kind(b""), ExeKind::Unknown);
        assert!(interop_enabled("enabled\ninterpreter /init\nflags: PF\n"));
        assert!(!interop_enabled("disabled\ninterpreter /init\n"));
        assert!(!interop_enabled(""));
    }

    #[test]
    fn misc_helpers() {
        assert!(looks_like_windows_path("C:\\x"));
        assert!(looks_like_windows_path("c:/x"));
        assert!(looks_like_windows_path("\\\\wsl$\\Ubuntu\\home"));
        assert!(!looks_like_windows_path("/mnt/c/x"));
        assert!(!looks_like_windows_path("relative/c:"));
        assert_eq!(
            join_windows("C:\\Users\\u\\", "f.wcm"),
            "C:\\Users\\u\\f.wcm"
        );
        assert_eq!(join_windows("C:\\Users\\u", "f.wcm"), "C:\\Users\\u\\f.wcm");
        assert_eq!(join_windows("", "f"), "f");
        assert!(wants_json(&args(&["--json", "ls"])));
        assert!(!wants_json(&args(&["run", "--", "--json"])));
        assert!(has_vault_arg(&args(&["x", "--vault=1"])));
        assert!(!has_vault_arg(&args(&["x", "--", "--vault"])));
        assert!(is_truthy("TRUE") && is_truthy(" 1 ") && !is_truthy("no") && !is_truthy(""));
        assert_eq!(exit_code_from(Some(3), None), 3);
        assert_eq!(exit_code_from(Some(300), None), 1);
        assert_eq!(exit_code_from(None, Some(2)), 130);
        assert_eq!(exit_code_from(None, Some(9)), 1);
        assert_eq!(exit_code_from(None, None), 1);
    }
}
