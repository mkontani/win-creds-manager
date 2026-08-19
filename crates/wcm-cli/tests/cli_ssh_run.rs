//! Integration tests for `wcm ssh add|pubkey|remove` and `wcm run`.
//!
//! Items are created directly through the `wcm-core` API (see `common`), so these
//! tests do not depend on `wcm add`.

mod common;

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use common::{gen_ssh_key, json, json_err, ssh_item, text_item, write_file, TestVault};
use predicates::prelude::*;
use wcm_core::item::{Field, Item, ItemKind};

/// A `wcm` command that unlocks through the passphrase slot.
///
/// `init` stores the recovery slot first; `Vault::unlock` aborts on the first
/// wrong passphrase, so commands that unlock must name the passphrase slot.
fn wcm(v: &TestVault) -> Command {
    let mut c = v.cmd();
    c.args(["--slot", common::PASSPHRASE_SLOT]);
    c
}

/// Fake `ssh-add` that records its arguments and stdin (unix only).
#[cfg(unix)]
struct FakeSshAdd {
    script: PathBuf,
    dir: PathBuf,
}

#[cfg(unix)]
impl FakeSshAdd {
    fn install(dir: &Path) -> FakeSshAdd {
        use std::os::unix::fs::PermissionsExt;
        let d = dir.display();
        let body = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$@\" >> \"{d}/args.txt\"\n\
             cat > \"{d}/stdin.bin\"\n\
             if [ -e \"{d}/fail\" ]; then echo \"agent refused operation\" >&2; exit 1; fi\n\
             echo \"Identity added: (stdin) (test@wcm)\" >&2\n"
        );
        let script = write_file(dir, "fake-ssh-add", body.as_bytes());
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake ssh-add");
        FakeSshAdd {
            script,
            dir: dir.to_path_buf(),
        }
    }

    fn args(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.join("args.txt"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn stdin(&self) -> Vec<u8> {
        std::fs::read(self.dir.join("stdin.bin")).unwrap_or_default()
    }

    fn make_fail(&self) {
        write_file(&self.dir, "fail", b"");
    }
}

fn non_ssh_item(name: &str) -> Item {
    text_item(
        name,
        ItemKind::Login,
        &[("password", "hunter2"), ("username", "alice")],
        &["password"],
    )
}

// ---------------------------------------------------------------------------
// ssh add
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn ssh_add_pipes_key_to_ssh_add_with_lifetime() {
    let (v, _) = TestVault::initialized();
    let key = gen_ssh_key("test@wcm", None);
    // Store the key *without* a trailing newline: wcm must add one for OpenSSH.
    let pem_no_nl = key.private_pem.trim_end_matches('\n').to_string();
    let item = text_item(
        "ssh/work",
        ItemKind::SshKey,
        &[
            ("private_key", pem_no_nl.as_str()),
            ("public_key", key.public_key.as_str()),
            ("fingerprint", key.fingerprint.as_str()),
        ],
        &["private_key"],
    );
    v.insert_items(vec![item]);
    let fake = FakeSshAdd::install(v.dir.path());

    let out = wcm(&v)
        .args(["--json", "ssh", "add", "ssh/work", "-t", "1h", "--ssh-add"])
        .arg(&fake.script)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let j = json(&out);
    assert_eq!(j["name"], "ssh/work");
    assert_eq!(j["fingerprint"], key.fingerprint);
    assert_eq!(j["ssh_add"], fake.script.display().to_string());

    assert_eq!(fake.args(), vec!["-t", "1h", "-"]);
    assert_eq!(fake.stdin(), key.private_pem.as_bytes());
    // The secret must never be echoed to stdout/stderr.
    assert!(!String::from_utf8_lossy(&out.stdout).contains("PRIVATE KEY"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("PRIVATE KEY"));
}

#[cfg(unix)]
#[test]
fn ssh_add_human_output_and_env_ssh_add_path() {
    let (v, _) = TestVault::initialized();
    let key = gen_ssh_key("c@h", None);
    v.insert_items(vec![ssh_item("k", &key)]);
    let fake = FakeSshAdd::install(v.dir.path());

    wcm(&v)
        .env("WCM_SSH_ADD", &fake.script)
        .args(["ssh", "add", "k"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(format!(
            "Added k ({}) to ssh-agent",
            key.fingerprint
        )));
    // Without -t only "-" is passed; the stored PEM already ends with "\n".
    assert_eq!(fake.args(), vec!["-"]);
    assert_eq!(fake.stdin(), key.private_pem.as_bytes());
}

#[cfg(unix)]
#[test]
fn ssh_add_warns_about_encrypted_key() {
    let (v, _) = TestVault::initialized();
    let key = gen_ssh_key("enc@wcm", Some("key-pass"));
    v.insert_items(vec![ssh_item("enc", &key)]);
    let fake = FakeSshAdd::install(v.dir.path());

    wcm(&v)
        .args(["ssh", "add", "enc", "--ssh-add"])
        .arg(&fake.script)
        .assert()
        .success()
        .stderr(predicate::str::contains("passphrase"));
    assert_eq!(fake.stdin(), key.private_pem.as_bytes());
}

#[cfg(unix)]
#[test]
fn ssh_add_reports_helper_failure_with_stderr() {
    let (v, _) = TestVault::initialized();
    let key = gen_ssh_key("c@h", None);
    v.insert_items(vec![ssh_item("k", &key)]);
    let fake = FakeSshAdd::install(v.dir.path());
    fake.make_fail();

    let out = wcm(&v)
        .args(["--json", "ssh", "add", "k", "--ssh-add"])
        .arg(&fake.script)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(11));
    let e = json_err(&out);
    assert_eq!(e["error"]["code"], "HELPER");
    assert!(e["error"]["message"]
        .as_str()
        .expect("message")
        .contains("agent refused operation"));
}

#[test]
fn ssh_add_rejects_non_ssh_item_and_missing_item() {
    let (v, _) = TestVault::initialized();
    v.insert_items(vec![non_ssh_item("login")]);

    let out = wcm(&v)
        .args([
            "--json",
            "ssh",
            "add",
            "login",
            "--ssh-add",
            "/nonexistent/ssh-add",
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(json_err(&out)["error"]["code"], "INVALID_INPUT");
    wcm(&v)
        .args(["ssh", "add", "login", "--ssh-add", "/nonexistent/ssh-add"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not an ssh-key"));

    wcm(&v)
        .args(["ssh", "add", "nope", "--ssh-add", "/nonexistent/ssh-add"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn ssh_add_without_private_key_field_is_not_found() {
    let (v, _) = TestVault::initialized();
    let key = gen_ssh_key("c@h", None);
    let item = text_item(
        "pubonly",
        ItemKind::SshKey,
        &[("public_key", key.public_key.as_str())],
        &[],
    );
    v.insert_items(vec![item]);
    let out = wcm(&v)
        .args([
            "--json",
            "ssh",
            "add",
            "pubonly",
            "--ssh-add",
            "/nonexistent/ssh-add",
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
    assert!(json_err(&out)["error"]["message"]
        .as_str()
        .expect("message")
        .contains("private_key"));
}

#[test]
fn ssh_add_missing_ssh_add_is_helper_error() {
    let (v, _) = TestVault::initialized();
    let key = gen_ssh_key("c@h", None);
    v.insert_items(vec![ssh_item("k", &key)]);

    // Explicit path that does not exist → spawn failure.
    let out = wcm(&v)
        .args([
            "--json",
            "ssh",
            "add",
            "k",
            "--ssh-add",
            "/nonexistent/ssh-add",
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(11));
    assert_eq!(json_err(&out)["error"]["code"], "HELPER");

    // Nothing on PATH.
    let out = wcm(&v)
        .env("PATH", "")
        .args(["--json", "ssh", "add", "k"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(11));
    assert!(json_err(&out)["error"]["message"]
        .as_str()
        .expect("message")
        .contains("ssh-add not found"));
}

#[test]
fn ssh_commands_require_initialized_vault() {
    let v = TestVault::new();
    v.cmd().args(["ssh", "pubkey", "k"]).assert().code(5);
    v.cmd()
        .args(["run", "--env", "A=k", "--", "true"])
        .assert()
        .code(5);
}

// ---------------------------------------------------------------------------
// ssh pubkey
// ---------------------------------------------------------------------------

#[test]
fn ssh_pubkey_prints_authorized_keys_line() {
    let (v, _) = TestVault::initialized();
    let key = gen_ssh_key("me@box", None);
    v.insert_items(vec![ssh_item("k", &key)]);

    wcm(&v)
        .args(["ssh", "pubkey", "k"])
        .assert()
        .success()
        .stdout(format!("{}\n", key.public_key));

    let out = wcm(&v)
        .args(["--json", "ssh", "pubkey", "k"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let j = json(&out);
    assert_eq!(j["name"], "k");
    assert_eq!(j["public_key"], key.public_key);
    assert_eq!(j["fingerprint"], key.fingerprint);
}

#[test]
fn ssh_pubkey_derives_public_key_when_field_missing() {
    let (v, _) = TestVault::initialized();
    let key = gen_ssh_key("derived@wcm", None);
    let item = text_item(
        "k",
        ItemKind::SshKey,
        &[("private_key", key.private_pem.as_str())],
        &["private_key"],
    );
    v.insert_items(vec![item]);

    let out = wcm(&v)
        .args(["--json", "ssh", "pubkey", "k"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let j = json(&out);
    assert_eq!(j["public_key"], key.public_key);
    assert_eq!(j["fingerprint"], key.fingerprint);
}

#[test]
fn ssh_pubkey_handles_binary_private_key_field() {
    let (v, _) = TestVault::initialized();
    let key = gen_ssh_key("bin@wcm", None);
    let now = wcm_core::vault::now_rfc3339();
    let item = Item::new("k", ItemKind::SshKey, &now).with_field(
        "private_key",
        Field::secret_bytes(key.private_pem.clone().into_bytes()),
    );
    v.insert_items(vec![item]);

    wcm(&v)
        .args(["ssh", "pubkey", "k"])
        .assert()
        .success()
        .stdout(format!("{}\n", key.public_key));
}

#[test]
fn ssh_pubkey_errors() {
    let (v, _) = TestVault::initialized();
    let now = wcm_core::vault::now_rfc3339();
    v.insert_items(vec![
        non_ssh_item("login"),
        Item::new("empty", ItemKind::SshKey, &now),
        text_item(
            "garbage",
            ItemKind::SshKey,
            &[("private_key", "not a key")],
            &["private_key"],
        ),
    ]);

    wcm(&v).args(["ssh", "pubkey", "nope"]).assert().code(3);
    wcm(&v).args(["ssh", "pubkey", "login"]).assert().code(2);
    // No public_key and no private_key to derive it from.
    let out = wcm(&v)
        .args(["--json", "ssh", "pubkey", "empty"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
    assert!(json_err(&out)["error"]["message"]
        .as_str()
        .expect("message")
        .contains("public_key"));
    // Unparsable private key.
    wcm(&v)
        .args(["ssh", "pubkey", "garbage"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("OpenSSH"));
}

// ---------------------------------------------------------------------------
// ssh remove
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn ssh_remove_passes_pubkey_to_ssh_add_d() {
    let (v, _) = TestVault::initialized();
    let key = gen_ssh_key("rm@wcm", None);
    v.insert_items(vec![ssh_item("k", &key)]);
    let fake = FakeSshAdd::install(v.dir.path());

    let out = wcm(&v)
        .args(["--json", "ssh", "remove", "k", "--ssh-add"])
        .arg(&fake.script)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let j = json(&out);
    assert_eq!(j["name"], "k");
    assert_eq!(j["removed"], true);
    assert_eq!(fake.args(), vec!["-d", "-"]);
    assert_eq!(fake.stdin(), format!("{}\n", key.public_key).as_bytes());

    wcm(&v)
        .args(["ssh", "remove", "k", "--ssh-add"])
        .arg(&fake.script)
        .assert()
        .success()
        .stderr(predicate::str::contains("Removed k"));
}

#[cfg(unix)]
#[test]
fn ssh_remove_failure_and_errors() {
    let (v, _) = TestVault::initialized();
    let key = gen_ssh_key("rm@wcm", None);
    v.insert_items(vec![ssh_item("k", &key), non_ssh_item("login")]);
    let fake = FakeSshAdd::install(v.dir.path());
    fake.make_fail();

    wcm(&v)
        .args(["ssh", "remove", "k", "--ssh-add"])
        .arg(&fake.script)
        .assert()
        .code(11)
        .stderr(predicate::str::contains("agent refused operation"));
    wcm(&v)
        .args(["ssh", "remove", "login", "--ssh-add"])
        .arg(&fake.script)
        .assert()
        .code(2);
    wcm(&v)
        .args(["ssh", "remove", "nope", "--ssh-add"])
        .arg(&fake.script)
        .assert()
        .code(3);
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn run_injects_secrets_as_env_vars() {
    let (v, _) = TestVault::initialized();
    v.insert_items(vec![
        non_ssh_item("login"),
        text_item(
            "github/token",
            ItemKind::Token,
            &[("token", "ghp_x")],
            &["token"],
        ),
    ]);

    let out = wcm(&v)
        .args([
            "run",
            "--env",
            "A=login",
            "--env",
            "B=login/username",
            "--env",
            "C=github/token",
            "--",
            "sh",
            "-c",
            "printf '%s|%s|%s' \"$A\" \"$B\" \"$C\"",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hunter2|alice|ghp_x");
    // --json has no special output: stdout is exactly the child's output.
    let out = wcm(&v)
        .args([
            "--json",
            "run",
            "--env",
            "A=login",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$A\"",
        ])
        .output()
        .expect("run");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hunter2");
}

#[cfg(unix)]
#[test]
fn run_passes_child_exit_code_through() {
    let (v, _) = TestVault::initialized();
    v.insert_items(vec![non_ssh_item("login")]);
    wcm(&v)
        .args(["run", "--env", "A=login", "--", "sh", "-c", "exit 7"])
        .assert()
        .code(7);
    // A command without any secret mapping runs without unlocking the vault
    // (no prompt for nothing): it works even with an unusable passphrase.
    wcm(&v)
        .env("WCM_PASSPHRASE", "wrong")
        .args(["run", "--", "sh", "-c", "exit 0"])
        .assert()
        .success();
    // Large exit codes are passed through unchanged.
    wcm(&v)
        .args(["run", "--env", "A=login", "--", "sh", "-c", "exit 200"])
        .assert()
        .code(200);
}

#[cfg(unix)]
#[test]
fn run_signal_killed_child_exits_130() {
    let (v, _) = TestVault::initialized();
    v.insert_items(vec![non_ssh_item("login")]);
    wcm(&v)
        .args(["run", "--env", "A=login", "--", "sh", "-c", "kill -9 $$"])
        .assert()
        .code(130);
}

#[test]
fn run_missing_item_or_field_is_not_found() {
    let (v, _) = TestVault::initialized();
    v.insert_items(vec![non_ssh_item("login")]);
    let out = wcm(&v)
        .args(["--json", "run", "--env", "A=nope", "--", "true"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(json_err(&out)["error"]["code"], "NOT_FOUND");

    let out = wcm(&v)
        .args(["--json", "run", "--env", "A=login/nofield", "--", "true"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
    assert!(json_err(&out)["error"]["message"]
        .as_str()
        .expect("message")
        .contains("nofield"));
}

#[test]
fn run_bad_mapping_is_invalid() {
    let (v, _) = TestVault::initialized();
    v.insert_items(vec![non_ssh_item("login")]);
    for bad in [
        "noequals",
        "1BAD=login",
        "A-B=login",
        "=login",
        "A=",
        "A=/x",
    ] {
        let out = wcm(&v)
            .args(["--json", "run", "--env", bad, "--", "true"])
            .output()
            .expect("run");
        assert_eq!(out.status.code(), Some(2), "mapping {bad:?}");
        assert_eq!(json_err(&out)["error"]["code"], "INVALID_INPUT");
    }
}

#[test]
fn run_binary_value_is_invalid() {
    let (v, _) = TestVault::initialized();
    let now = wcm_core::vault::now_rfc3339();
    v.insert_items(vec![Item::new("blob", ItemKind::File, &now)
        .with_field("content", Field::secret_bytes(vec![0, 255, 1]))]);
    let out = wcm(&v)
        .args(["--json", "run", "--env", "A=blob", "--", "true"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(json_err(&out)["error"]["message"]
        .as_str()
        .expect("message")
        .contains("binary"));
}

#[test]
fn run_spawn_failure_is_helper_error() {
    let (v, _) = TestVault::initialized();
    v.insert_items(vec![non_ssh_item("login")]);
    let out = wcm(&v)
        .args([
            "--json",
            "run",
            "--env",
            "A=login",
            "--",
            "/nonexistent/definitely-not-a-command",
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(11));
    assert_eq!(json_err(&out)["error"]["code"], "HELPER");
}

#[cfg(unix)]
#[test]
fn run_env_file_mixes_secret_and_plain_lines() {
    let (v, _) = TestVault::initialized();
    v.insert_items(vec![non_ssh_item("login")]);
    let env_file = write_file(
        v.dir.path(),
        "app.env",
        b"# comment\n\nPASSWORD=wcm://login\nUSER=wcm://login/username\nPLAIN=hello world\r\nEMPTY=\n",
    );
    let out = wcm(&v)
        .args(["run", "--env-file"])
        .arg(&env_file)
        .args([
            "--",
            "sh",
            "-c",
            "printf '%s|%s|%s|%s' \"$PASSWORD\" \"$USER\" \"$PLAIN\" \"$EMPTY\"",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "hunter2|alice|hello world|"
    );
}

#[test]
fn run_env_file_errors() {
    let (v, _) = TestVault::initialized();
    v.insert_items(vec![non_ssh_item("login")]);
    // Missing file → io error.
    let out = wcm(&v)
        .args([
            "--json",
            "run",
            "--env-file",
            "/nonexistent/app.env",
            "--",
            "true",
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(10));
    // Malformed line → invalid.
    let bad = write_file(v.dir.path(), "bad.env", b"JUSTAKEY\n");
    let out = wcm(&v)
        .args(["--json", "run", "--env-file"])
        .arg(&bad)
        .args(["--", "true"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    // wcm:// line pointing at a missing item → not found.
    let missing = write_file(v.dir.path(), "missing.env", b"A=wcm://nope\n");
    let out = wcm(&v)
        .args(["--json", "run", "--env-file"])
        .arg(&missing)
        .args(["--", "true"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
}
