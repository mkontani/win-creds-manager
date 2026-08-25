//! WSL shim integration tests (Linux only). `WCM_FORCE_WSL=1` makes the Linux
//! build believe it runs under WSL; `WCM_WINDOWS_EXE` points at a stand-in for
//! `wcm.exe` (the native binary itself, or a shell script that records what it
//! was called with).
#![cfg(target_os = "linux")]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use common::{json, json_err, TestVault};
use predicates::prelude::*;
use tempfile::TempDir;

/// A `wcm` command that believes it runs under WSL. PATH is an empty directory
/// so no real `wcm.exe` / `wslpath` / `ssh-add` can interfere.
fn proxy_cmd(dir: &Path) -> Command {
    let mut c = Command::cargo_bin("wcm").expect("wcm binary");
    c.env_clear();
    let empty_path = dir.join("empty-path");
    std::fs::create_dir_all(&empty_path).expect("mkdir");
    c.env("PATH", &empty_path);
    c.env("HOME", dir);
    c.env("WCM_FORCE_WSL", "1");
    c
}

fn native_wcm() -> PathBuf {
    assert_cmd::cargo::cargo_bin("wcm")
}

fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).expect("write script");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    p
}

/// Stand-in for wcm.exe: records argv + environment in `$FAKE_OUT/exe.args`,
/// answers `get` with a fake private key and `ssh pubkey` with a public key line.
fn fake_exe(dir: &Path) -> PathBuf {
    write_script(
        dir,
        "fake-wcm.exe",
        r#"#!/bin/sh
printf 'ARGS:%s\n' "$*" > "$FAKE_OUT/exe.args"
printf 'LAUNCHED:%s\n' "$WCM_LAUNCHED_FROM_WSL" >> "$FAKE_OUT/exe.args"
printf 'KIND:%s\n' "$WCM_WSL_KIND" >> "$FAKE_OUT/exe.args"
printf 'EXE:%s\n' "$WCM_WSL_EXE" >> "$FAKE_OUT/exe.args"
printf 'WSLENV:%s\n' "$WSLENV" >> "$FAKE_OUT/exe.args"
printf 'PASS:%s\n' "$WCM_PASSPHRASE" >> "$FAKE_OUT/exe.args"
if [ -n "$FAKE_EXE_RC" ]; then echo "fake failure" >&2; exit "$FAKE_EXE_RC"; fi
case " $* " in
  *" get "*) printf 'FAKE-PRIVATE-KEY' ;;
  *" pubkey "*) printf 'ssh-ed25519 AAAAC3 comment\n' ;;
  *) printf 'ARGS:%s\n' "$*" ;;
esac
"#,
    )
}

/// Stand-in for the Linux ssh-add: records argv and stdin.
fn fake_ssh_add(dir: &Path) -> PathBuf {
    write_script(
        dir,
        "fake-ssh-add",
        r#"#!/bin/sh
printf 'ARGS:%s\n' "$*" > "$FAKE_OUT/ssh-add.args"
/bin/cat > "$FAKE_OUT/ssh-add.stdin"
exit "${FAKE_SSH_ADD_RC:-0}"
"#,
    )
}

fn read(dir: &Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

#[test]
fn proxy_execs_windows_exe_and_child_does_not_recurse() {
    let tmp = TempDir::new().expect("tmp");
    let out = proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", native_wcm())
        .args(["--json", "version"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let j = json(&out);
    assert_eq!(j["name"], "wcm");
    assert_eq!(j["target_os"], "linux");
}

#[test]
fn proxy_is_skipped_when_disabled_or_already_launched() {
    let tmp = TempDir::new().expect("tmp");
    for (k, v) in [("WCM_NO_WSL_PROXY", "1"), ("WCM_LAUNCHED_FROM_WSL", "1")] {
        proxy_cmd(tmp.path())
            .env("WCM_WINDOWS_EXE", "/nonexistent/wcm.exe")
            .env(k, v)
            .arg("version")
            .assert()
            .success()
            .stdout(predicate::str::starts_with("wcm 0."));
    }
    // WCM_FORCE_WSL=0 is not WSL either (plain Linux CI has no /proc/version marker).
    let mut c = proxy_cmd(tmp.path());
    c.env("WCM_FORCE_WSL", "0")
        .env("WCM_WINDOWS_EXE", "/nonexistent/wcm.exe")
        .arg("version");
    let out = c.output().expect("run");
    if std::fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("microsoft")
    {
        // real WSL host: the shim is active regardless of the hook
        assert!(out.status.code() == Some(127) || out.status.success());
    } else {
        assert!(out.status.success());
    }
}

#[test]
fn missing_windows_exe_is_127() {
    let tmp = TempDir::new().expect("tmp");
    proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", "/nonexistent/wcm.exe")
        .arg("version")
        .assert()
        .code(127)
        .stderr(predicate::str::contains(
            "error: wcm.exe not found from WSL",
        ))
        .stderr(predicate::str::contains(
            "WCM_WINDOWS_EXE=/nonexistent/wcm.exe does not exist",
        ));
    let out = proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", "/nonexistent/wcm.exe")
        .args(["--json", "version"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(127));
    let e = json_err(&out);
    assert_eq!(e["error"]["code"], "WSL_EXE_NOT_FOUND");
    assert_eq!(e["error"]["exit"], 127);
    assert!(e["error"]["hint"]
        .as_str()
        .expect("hint")
        .contains("docs/WSL.md"));
}

#[test]
fn windows_exe_found_on_path() {
    let tmp = TempDir::new().expect("tmp");
    let bin = tmp.path().join("winbin");
    std::fs::create_dir_all(&bin).expect("mkdir");
    std::fs::copy(native_wcm(), bin.join("wcm.exe")).expect("copy");
    proxy_cmd(tmp.path())
        .env("PATH", &bin)
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("wcm 0."));
}

#[test]
fn non_executable_format_is_126() {
    let tmp = TempDir::new().expect("tmp");
    let txt = write_script(tmp.path(), "not-an-exe", "hello there\n");
    proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", &txt)
        .arg("version")
        .assert()
        .code(126)
        .stderr(predicate::str::contains("unrecognized executable format"));
    let out = proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", &txt)
        .args(["--json", "version"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(126));
    assert_eq!(json_err(&out)["error"]["code"], "WSL_INTEROP_BROKEN");
}

#[test]
fn unreadable_exe_is_126_with_os_error() {
    let tmp = TempDir::new().expect("tmp");
    let dir = tmp.path().join("a-directory");
    std::fs::create_dir_all(&dir).expect("mkdir");
    // find_exe requires a file; a directory is not found → 127. A file without
    // the exec bit is found, survives pre-flight (ELF) and fails in exec → 126.
    let noexec = tmp.path().join("noexec-wcm.exe");
    std::fs::copy(native_wcm(), &noexec).expect("copy");
    std::fs::set_permissions(&noexec, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", &noexec)
        .arg("version")
        .assert()
        .code(126)
        .stderr(predicate::str::contains("cannot execute"))
        .stderr(predicate::str::contains("ermission denied"));
}

#[test]
fn args_env_and_exit_code_are_forwarded() {
    let tmp = TempDir::new().expect("tmp");
    let exe = fake_exe(tmp.path());
    let vault = tmp.path().join("vault.wcm");
    let out = proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", &exe)
        .env("FAKE_OUT", tmp.path())
        .env("FAKE_EXE_RC", "7")
        .env("WCM_VAULT", &vault)
        .env("WCM_PASSPHRASE", "pw")
        .env("WSLENV", "FOO/p")
        .args(["--json", "ls", "--kind", "password"])
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(7),
        "exit code of wcm.exe must be propagated"
    );
    let rec = read(tmp.path(), "exe.args");
    // no wslpath on PATH → the Linux spelling is kept, but --vault is injected from WCM_VAULT
    assert!(
        rec.contains(&format!(
            "ARGS:--vault {} --json ls --kind password\n",
            vault.display()
        )),
        "{rec}"
    );
    assert!(rec.contains("LAUNCHED:1\n"), "{rec}");
    assert!(rec.contains("KIND:WSL2\n"), "{rec}");
    assert!(rec.contains(&format!("EXE:{}\n", exe.display())), "{rec}");
    assert!(
        rec.contains(
            "WSLENV:FOO/p:WCM_LAUNCHED_FROM_WSL/w:WCM_WSL_KIND/w:WCM_WSL_EXE/w:\
             WCM_PASSPHRASE/w:WCM_EXPORT_PASSPHRASE/w:WCM_NO_AGENT/w\n"
        ),
        "{rec}"
    );
    assert!(rec.contains("PASS:pw\n"), "{rec}");
}

#[test]
fn explicit_vault_is_not_duplicated_and_paths_after_double_dash_are_untouched() {
    let tmp = TempDir::new().expect("tmp");
    let exe = fake_exe(tmp.path());
    proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", &exe)
        .env("FAKE_OUT", tmp.path())
        .env("WCM_VAULT", "/ignored/vault.wcm")
        .args([
            "run",
            "--vault=/v.wcm",
            "--env",
            "A=x",
            "--",
            "cat",
            "--vault",
            "/etc/passwd",
        ])
        .assert()
        .success();
    let rec = read(tmp.path(), "exe.args");
    assert!(
        rec.starts_with("ARGS:run --vault=/v.wcm --env A=x -- cat --vault /etc/passwd\n"),
        "{rec}"
    );
}

#[test]
fn ssh_add_pipes_private_key_into_linux_ssh_add() {
    let tmp = TempDir::new().expect("tmp");
    let exe = fake_exe(tmp.path());
    let ssh_add = fake_ssh_add(tmp.path());
    proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", &exe)
        .env("FAKE_OUT", tmp.path())
        .env("WCM_VAULT", "/v/vault.wcm")
        .args(["ssh", "add", "mykey", "-t", "1h", "--ssh-add"])
        .arg(&ssh_add)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "ssh key 'mykey' added to the WSL ssh-agent",
        ));
    assert!(read(tmp.path(), "exe.args")
        .starts_with("ARGS:--vault /v/vault.wcm get mykey --field private_key --raw\n"),);
    assert_eq!(read(tmp.path(), "ssh-add.args"), "ARGS:-t 1h -\n");
    // `get --raw` writes no trailing newline; the shim must add exactly one.
    assert_eq!(read(tmp.path(), "ssh-add.stdin"), "FAKE-PRIVATE-KEY\n");
}

#[test]
fn ssh_remove_pipes_public_key_into_ssh_add_d() {
    let tmp = TempDir::new().expect("tmp");
    let exe = fake_exe(tmp.path());
    let ssh_add = fake_ssh_add(tmp.path());
    // ssh-add located through WCM_SSH_ADD this time, output as JSON
    let out = proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", &exe)
        .env("FAKE_OUT", tmp.path())
        .env("WCM_SSH_ADD", &ssh_add)
        .args(["--json", "ssh", "remove", "mykey"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let j = json(&out);
    assert_eq!(j["action"], "remove");
    assert_eq!(j["name"], "mykey");
    assert_eq!(j["agent"], "wsl");
    assert!(read(tmp.path(), "exe.args").starts_with("ARGS:ssh pubkey mykey\n"));
    assert_eq!(read(tmp.path(), "ssh-add.args"), "ARGS:-d -\n");
    assert_eq!(
        read(tmp.path(), "ssh-add.stdin"),
        "ssh-ed25519 AAAAC3 comment\n"
    );
}

#[test]
fn ssh_add_error_paths() {
    let tmp = TempDir::new().expect("tmp");
    let exe = fake_exe(tmp.path());
    let ssh_add = fake_ssh_add(tmp.path());
    // wcm.exe fails → its exit code
    proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", &exe)
        .env("FAKE_OUT", tmp.path())
        .env("FAKE_EXE_RC", "3")
        .env("WCM_SSH_ADD", &ssh_add)
        .args(["ssh", "add", "missing"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("fake failure"));
    // ssh-add fails → 11
    proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", &exe)
        .env("FAKE_OUT", tmp.path())
        .env("FAKE_SSH_ADD_RC", "1")
        .env("WCM_SSH_ADD", &ssh_add)
        .args(["ssh", "add", "mykey"])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("ssh-add failed (exit 1)"));
    // ssh-add missing → 11 (none on the empty PATH)
    let out = proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", &exe)
        .env("FAKE_OUT", tmp.path())
        .args(["--json", "ssh", "add", "mykey"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(11));
    let e = json_err(&out);
    assert_eq!(e["error"]["code"], "HELPER");
    assert_eq!(e["error"]["exit"], 11);
    // explicit but unusable ssh-add → 11
    proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", &exe)
        .env("FAKE_OUT", tmp.path())
        .args(["ssh", "add", "mykey", "--ssh-add", "/nonexistent/ssh-add"])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("cannot run /nonexistent/ssh-add"));
    // `ssh pubkey` is a plain proxy call (no ssh-add involved)
    proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", &exe)
        .env("FAKE_OUT", tmp.path())
        .args(["ssh", "pubkey", "mykey"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ssh-ed25519 AAAAC3 comment"));
    assert!(read(tmp.path(), "ssh-add.args").contains("ARGS:-")); // unchanged from the "ssh-add fails" run above
}

#[test]
fn ssh_add_with_empty_key_material_is_11() {
    let tmp = TempDir::new().expect("tmp");
    let exe = write_script(tmp.path(), "empty-wcm.exe", "#!/bin/sh\nprintf '\\n'\n");
    let ssh_add = fake_ssh_add(tmp.path());
    proxy_cmd(tmp.path())
        .env("WCM_WINDOWS_EXE", &exe)
        .env("FAKE_OUT", tmp.path())
        .env("WCM_SSH_ADD", &ssh_add)
        .args(["ssh", "add", "k"])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("no key material"));
}

#[test]
fn doctor_reports_wsl_detection_and_exe() {
    let (v, _) = TestVault::initialized();
    let out = v
        .cmd()
        .env("WCM_FORCE_WSL", "1")
        .env("WCM_WINDOWS_EXE", native_wcm())
        .args(["--json", "doctor"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let d = json(&out);
    assert_eq!(d["wsl"]["detected"], true);
    assert_eq!(d["wsl"]["kind"], "WSL2");
    assert_eq!(d["wsl"]["windows_exe"], native_wcm().display().to_string());
    v.cmd()
        .env("WCM_FORCE_WSL", "1")
        .env("WCM_WINDOWS_EXE", "/nonexistent/wcm.exe")
        .env("PATH", v.dir.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "wsl:           WSL2 (wcm.exe: not found)",
        ));
}
