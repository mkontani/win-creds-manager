//! WSL shim (Linux only): detects WSL, locates `wcm.exe` and hands the whole
//! invocation to it through the interop layer (binfmt_misc → `/init`). The
//! Windows binary owns the vault, the crypto and the Windows Hello prompt; the
//! Linux build is only a launcher. All decision logic is in [`crate::wsl_core`]
//! (pure, unit-tested everywhere); this file does the I/O.
//!
//! `ssh add` / `ssh remove` are the one exception: the key must land in the
//! *Linux* ssh-agent, so wcm.exe is spawned to produce the key material and
//! the bytes are piped into the local `ssh-add`.

use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use wcm_core::error::{EXIT_WSL_EXE_NOT_FOUND, EXIT_WSL_INTEROP_BROKEN};
use zeroize::Zeroizing;

pub use crate::wsl_core::WslKind;
use crate::wsl_core::{
    self, Env, ExeKind, SshAction, SshAgentOp, ENV_LAUNCHED, ENV_NO_PROXY, ENV_WINDOWS_EXE,
    ENV_WSL_EXE, ENV_WSL_KIND, WINDOWS_EXE_NAME,
};

const PROC_VERSION: &str = "/proc/version";
const BINFMT_DIR: &str = "/proc/sys/fs/binfmt_misc";
const BINFMT_INTEROP_ENTRIES: &[&str] = &["WSLInterop", "WSLInterop-late"];
const MNT_ROOT: &str = "/mnt";
const SSH_ADD_ENV: &str = "WCM_SSH_ADD";
/// `wcm_core::Error::Helper` exit code (ssh-add failures).
const EXIT_HELPER: u8 = 11;

/// Diagnostic info for `wcm doctor`.
pub struct WslInfo {
    pub kind: Option<WslKind>,
    pub windows_exe: Option<PathBuf>,
}

/// Detects WSL and locates `wcm.exe` (without executing anything).
pub fn info() -> WslInfo {
    let env = env_map();
    let kind = wsl_core::detect(&proc_version(), &env);
    let windows_exe = kind.and_then(|_| locate_exe(&env));
    WslInfo { kind, windows_exe }
}

/// If running under WSL, execs `wcm.exe` with the same arguments and returns its exit code.
/// Returns `None` when not under WSL (or when proxying is disabled), so the caller continues natively.
pub fn maybe_proxy() -> Option<u8> {
    let env = env_map();
    if env
        .get(ENV_NO_PROXY)
        .is_some_and(|v| wsl_core::is_truthy(v))
    {
        return None;
    }
    // The child of a proxied invocation must run natively (never recurse).
    if env.contains_key(ENV_LAUNCHED) {
        return None;
    }
    let kind = wsl_core::detect(&proc_version(), &env)?;

    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let json = wsl_core::wants_json(&args);

    let Some(exe) = locate_exe(&env) else {
        report_not_found(&env, json);
        return Some(EXIT_WSL_EXE_NOT_FOUND);
    };
    if let Err(code) = preflight(&exe, json) {
        return Some(code);
    }
    let wargs = wsl_core::build_windows_args(&args, &env, &to_windows_path);
    if let Some(action) = wsl_core::parse_ssh_action(&wargs) {
        return Some(run_ssh_action(&exe, &action, &env, kind));
    }
    let err = command(&exe, &env, kind).args(&wargs).exec();
    Some(report_exec_error(&exe, &err, json))
}

// ---------------------------------------------------------------- environment

fn env_map() -> Env {
    std::env::vars_os()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect()
}

fn proc_version() -> String {
    std::fs::read_to_string(PROC_VERSION).unwrap_or_default()
}

/// `wcm.exe` lookup: `$WCM_WINDOWS_EXE` → PATH → `/mnt/*/Users/*/…`.
fn locate_exe(env: &Env) -> Option<PathBuf> {
    let path_entries: Vec<PathBuf> = env
        .get("PATH")
        .map(|p| std::env::split_paths(p).collect())
        .unwrap_or_default();
    let candidates = wsl_core::candidate_paths(&windows_user_dirs());
    wsl_core::find_exe(env, &path_entries, &candidates, &|p| p.is_file())
}

/// `/mnt/<drive>/Users/<name>` directories, sorted for determinism.
fn windows_user_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for drive in sorted_subdirs(Path::new(MNT_ROOT)) {
        out.extend(sorted_subdirs(&drive.join("Users")));
    }
    out
}

fn sorted_subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    v.sort();
    v
}

/// A `Command` for `wcm.exe` with the shim environment applied.
fn command(exe: &Path, env: &Env, kind: WslKind) -> Command {
    let mut c = Command::new(exe);
    c.env(ENV_LAUNCHED, "1");
    c.env(ENV_WSL_KIND, kind.to_string());
    c.env(ENV_WSL_EXE, exe.as_os_str());
    c.env(
        "WSLENV",
        wsl_core::extend_wslenv(env.get("WSLENV").map(String::as_str)),
    );
    c
}

// ------------------------------------------------------------ path translation

/// Linux path → Windows path via `wslpath -w` (absolute first). For paths that
/// do not exist yet (output files) the parent is translated and the file name
/// appended. `None` when translation is impossible (caller keeps the original).
fn to_windows_path(p: &Path) -> Option<String> {
    let abs = std::path::absolute(p).ok()?;
    if let Some(w) = wslpath_w(&abs) {
        return Some(w);
    }
    let parent = abs.parent()?;
    let name = abs.file_name()?.to_str()?;
    let parent_w = wslpath_w(parent)?;
    Some(wsl_core::join_windows(&parent_w, name))
}

fn wslpath_w(p: &Path) -> Option<String> {
    let out = Command::new("wslpath")
        .arg("-w")
        .arg(p)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim_end_matches(['\r', '\n']);
    (!s.is_empty()).then(|| s.to_string())
}

// ---------------------------------------------------------------- pre-flight

/// Refuses early (exit 126) when the target can obviously not be launched:
/// a PE binary while binfmt_misc interop is off, or a file of unknown format
/// (the kernel would answer `ENOEXEC`, which `execvp` masks with a `/bin/sh` fallback).
fn preflight(exe: &Path, json: bool) -> Result<(), u8> {
    let Some(magic) = read_magic(exe) else {
        return Ok(()); // let exec() produce the OS error
    };
    match wsl_core::exe_kind(&magic) {
        ExeKind::Elf | ExeKind::Script => Ok(()),
        ExeKind::Pe => {
            if interop_status() == Some(false) {
                report_interop_broken(json);
                return Err(EXIT_WSL_INTEROP_BROKEN);
            }
            Ok(())
        }
        ExeKind::Unknown => {
            report(
                json,
                "WSL_INTEROP_BROKEN",
                &format!(
                    "cannot execute {}: unrecognized executable format (expected a Windows {WINDOWS_EXE_NAME})",
                    exe.display()
                ),
                &format!("point {ENV_WINDOWS_EXE} at the Windows build of wcm, or unset it"),
                EXIT_WSL_INTEROP_BROKEN,
            );
            Err(EXIT_WSL_INTEROP_BROKEN)
        }
    }
}

fn read_magic(exe: &Path) -> Option<[u8; 4]> {
    let mut f = std::fs::File::open(exe).ok()?;
    let mut buf = [0u8; 4];
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => return None,
        }
    }
    Some(buf)
}

/// `Some(true)` if a WSLInterop binfmt entry is enabled, `Some(false)` if
/// binfmt_misc is mounted but the entry is missing/disabled, `None` when
/// binfmt_misc is not visible at all (cannot tell).
fn interop_status() -> Option<bool> {
    let dir = Path::new(BINFMT_DIR);
    if !dir.join("status").exists() {
        return None;
    }
    Some(BINFMT_INTEROP_ENTRIES.iter().any(|name| {
        std::fs::read_to_string(dir.join(name))
            .map(|s| wsl_core::interop_enabled(&s))
            .unwrap_or(false)
    }))
}

// ---------------------------------------------------------- ssh add / remove

/// Spawns wcm.exe to obtain the key material and pipes it into the Linux `ssh-add`.
fn run_ssh_action(exe: &Path, action: &SshAction, env: &Env, kind: WslKind) -> u8 {
    let out = match command(exe, env, kind)
        .args(action.exe_args())
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
    {
        Ok(o) => o,
        Err(e) => return report_exec_error(exe, &e, action.json),
    };
    if !out.status.success() {
        // wcm.exe already printed its error; propagate its code.
        return wsl_core::exit_code_from(out.status.code(), out.status.signal());
    }
    let key = Zeroizing::new(out.stdout);
    if key.iter().all(u8::is_ascii_whitespace) {
        report(
            action.json,
            "HELPER",
            "wcm.exe returned no key material",
            "check the item with `wcm show <name>`",
            EXIT_HELPER,
        );
        return EXIT_HELPER;
    }
    let Some(ssh_add) = find_ssh_add(action.ssh_add.as_deref(), env) else {
        report(
            action.json,
            "HELPER",
            "ssh-add not found in WSL",
            "install openssh-client or pass --ssh-add PATH",
            EXIT_HELPER,
        );
        return EXIT_HELPER;
    };
    match pipe_into_ssh_add(&ssh_add, &action.ssh_add_args(), &key) {
        Ok(()) => {}
        Err(msg) => {
            report(
                action.json,
                "HELPER",
                &msg,
                "is the WSL ssh-agent running (SSH_AUTH_SOCK)?",
                EXIT_HELPER,
            );
            return EXIT_HELPER;
        }
    }
    let verb = match action.op {
        SshAgentOp::Add => "added to",
        SshAgentOp::Remove => "removed from",
    };
    if action.json {
        let v = serde_json::json!({
            "name": action.name,
            "action": match action.op { SshAgentOp::Add => "add", SshAgentOp::Remove => "remove" },
            "agent": "wsl",
            "ssh_add": ssh_add.display().to_string(),
        });
        println!("{v}");
    } else if !action.quiet {
        eprintln!("ssh key '{}' {verb} the WSL ssh-agent", action.name);
    }
    0
}

/// `--ssh-add PATH` → `$WCM_SSH_ADD` → `ssh-add` on PATH.
fn find_ssh_add(explicit: Option<&str>, env: &Env) -> Option<PathBuf> {
    if let Some(p) = explicit.or(env.get(SSH_ADD_ENV).map(String::as_str)) {
        return Some(PathBuf::from(p));
    }
    let path = env.get("PATH")?;
    std::env::split_paths(path)
        .map(|d| d.join("ssh-add"))
        .find(|p| p.is_file())
}

fn pipe_into_ssh_add(ssh_add: &Path, args: &[String], key: &[u8]) -> Result<(), String> {
    // `wcm.exe get --raw` writes the key without a trailing newline; ssh-add
    // needs one or it reports "error in libcrypto" on an otherwise valid PEM.
    let key = crate::ssh::with_trailing_newline(key);
    let mut cmd = Command::new(ssh_add);
    crate::prompt::scrub_secret_env(&mut cmd);
    let mut child = cmd
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", ssh_add.display()))?;
    if let Some(mut stdin) = child.stdin.take() {
        // A short write/EPIPE means ssh-add bailed out; its exit status tells the story.
        let _ = stdin.write_all(&key).and_then(|_| stdin.flush());
    }
    let status = child
        .wait()
        .map_err(|e| format!("waiting for ssh-add: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "ssh-add failed (exit {})",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into())
        ))
    }
}

// ------------------------------------------------------------------ reporting

fn report(json: bool, code: &str, message: &str, hint: &str, exit: u8) {
    if json {
        let v = serde_json::json!({
            "error": { "code": code, "message": message, "hint": hint, "exit": exit }
        });
        eprintln!("{v}");
    } else {
        eprintln!("error: {message}");
        eprintln!("hint: {hint}");
    }
}

fn report_not_found(env: &Env, json: bool) {
    let mut hint = format!(
        "looked at ${ENV_WINDOWS_EXE}, `{WINDOWS_EXE_NAME}` on PATH and \
         /mnt/*/Users/*/{{AppData/Local/Programs/wcm,.cargo/bin}}/{WINDOWS_EXE_NAME}; see docs/WSL.md"
    );
    if let Some(p) = env.get(ENV_WINDOWS_EXE).filter(|p| !p.is_empty()) {
        hint = format!("{ENV_WINDOWS_EXE}={p} does not exist; {hint}");
    }
    report(
        json,
        "WSL_EXE_NOT_FOUND",
        &format!(
            "{WINDOWS_EXE_NAME} not found from WSL (set {ENV_WINDOWS_EXE} or install wcm on Windows)"
        ),
        &hint,
        EXIT_WSL_EXE_NOT_FOUND,
    );
}

fn report_interop_broken(json: bool) {
    report(
        json,
        "WSL_INTEROP_BROKEN",
        "WSL interop cannot launch Windows executables (Exec format error)",
        "check `cat /proc/sys/fs/binfmt_misc/WSLInterop` (should say `enabled`); set \
         `[interop] enabled=true` in /etc/wsl.conf and run `wsl --shutdown`; if systemd-binfmt \
         removed the entry, `systemctl mask systemd-binfmt.service` — see docs/WSL.md",
        EXIT_WSL_INTEROP_BROKEN,
    );
}

fn report_exec_error(exe: &Path, err: &std::io::Error, json: bool) -> u8 {
    if err.raw_os_error() == Some(wsl_core::ENOEXEC) {
        report_interop_broken(json);
    } else {
        report(
            json,
            "WSL_INTEROP_BROKEN",
            &format!("cannot execute {}: {err}", exe.display()),
            &format!("check the file permissions or set {ENV_WINDOWS_EXE}"),
            EXIT_WSL_INTEROP_BROKEN,
        );
    }
    EXIT_WSL_INTEROP_BROKEN
}
