//! `wcm agent` — session cache integration (passphrase slots; no Hello needed).
//!
//! Every test gets a private endpoint (`WCM_AGENT_ENDPOINT`) and state dir
//! (`WCM_DATA_DIR`) so tests can run in parallel; detached agents are stopped
//! by a guard even when an assertion fails.

mod common;

use std::process::{Child, Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use common::{json, TestVault, PASS};
use predicates::prelude::*;

/// Endpoint private to this vault's temp dir (pipe names are global on Windows).
fn endpoint_for(v: &TestVault) -> String {
    if cfg!(windows) {
        let unique = v
            .dir
            .path()
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("x")
            .replace('.', "");
        format!(r"\\.\pipe\wcm-test-{unique}")
    } else {
        v.dir.path().join("a.sock").display().to_string()
    }
}

/// `wcm` wired to this vault's agent endpoint and state dir.
fn cmd(v: &TestVault) -> Command {
    let mut c = v.cmd();
    c.env("WCM_DATA_DIR", v.dir.path());
    c.env("WCM_AGENT_ENDPOINT", endpoint_for(v));
    c
}

/// Same environment as [`cmd`] but a `std` command (needed to spawn a foreground agent).
fn std_cmd(v: &TestVault) -> StdCommand {
    let mut c = StdCommand::new(env!("CARGO_BIN_EXE_wcm"));
    c.env_clear();
    for key in ["PATH", "LLVM_PROFILE_FILE"] {
        if let Some(val) = std::env::var_os(key) {
            c.env(key, val);
        }
    }
    c.env("WCM_VAULT", v.path())
        .env("WCM_PASSPHRASE", PASS)
        .env("WCM_NO_WSL_PROXY", "1")
        .env("HOME", v.dir.path())
        .env("WCM_DATA_DIR", v.dir.path())
        .env("WCM_AGENT_ENDPOINT", endpoint_for(v));
    c
}

fn agent_status(v: &TestVault) -> serde_json::Value {
    json(
        &cmd(v)
            .args(["--json", "agent", "status"])
            .output()
            .expect("agent status"),
    )
}

/// Stops the detached agent when dropped (also on panic).
struct Agent<'a>(&'a TestVault);

impl Drop for Agent<'_> {
    fn drop(&mut self) {
        let _ = cmd(self.0).args(["agent", "stop"]).output();
    }
}

fn start_agent<'a>(v: &'a TestVault, extra: &[&str]) -> Agent<'a> {
    cmd(v)
        .args(["agent", "start"])
        .args(extra)
        .assert()
        .success()
        .stdout(predicate::str::contains("agent started (pid "));
    Agent(v)
}

/// Kills a foreground agent when dropped.
struct Foreground(Child);

impl Drop for Foreground {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_until_running(v: &TestVault) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while agent_status(v)["running"] != true {
        assert!(Instant::now() < deadline, "agent did not come up");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn state_file_exists(v: &TestVault) -> bool {
    v.dir.path().join("agent.json").exists()
}

#[test]
fn status_reports_not_running_without_an_agent() {
    let v = TestVault::new();
    let s = agent_status(&v);
    assert_eq!(s["running"], false);
    assert!(s["entries"].as_array().expect("entries").is_empty());
    cmd(&v)
        .args(["agent", "status"])
        .assert()
        .success()
        .stdout("agent:    not running\n");
}

#[test]
fn invalid_start_arguments_are_rejected_before_anything_starts() {
    let v = TestVault::new();
    for args in [
        ["--idle", "0"],
        ["--ttl", "abc"],
        ["--idle", "10"],
        ["--max-uses", "0"],
    ] {
        cmd(&v).args(["agent", "start"]).args(args).assert().code(2);
    }
    assert_eq!(agent_status(&v)["running"], false);
    assert!(!state_file_exists(&v));
}

#[test]
fn start_stop_and_lock_are_idempotent_and_clean_up() {
    let v = TestVault::new();
    let agent = start_agent(&v, &["--idle", "2m", "--ttl", "5m", "--max-uses", "7"]);
    let s = agent_status(&v);
    assert_eq!(s["running"], true);
    assert!(s["pid"].as_u64().expect("pid") > 0);
    assert_eq!(s["policy"]["idle_secs"], 120);
    assert_eq!(s["policy"]["ttl_secs"], 300);
    assert_eq!(s["policy"]["max_uses"], 7);
    assert!(state_file_exists(&v));

    cmd(&v)
        .args(["agent", "start"])
        .assert()
        .success()
        .stderr(predicate::str::contains("agent already running"));

    cmd(&v)
        .args(["agent", "lock"])
        .assert()
        .success()
        .stderr(predicate::str::contains("agent locked"));

    let out = cmd(&v)
        .args(["--json", "agent", "stop"])
        .output()
        .expect("stop");
    assert!(out.status.success());
    assert_eq!(json(&out)["was_running"], true);
    drop(agent);
    assert!(!state_file_exists(&v), "agent.json removed by stop");
    assert_eq!(agent_status(&v)["running"], false);

    cmd(&v)
        .args(["agent", "stop"])
        .assert()
        .success()
        .stderr(predicate::str::contains("agent is not running"));
    cmd(&v)
        .args(["agent", "lock"])
        .assert()
        .success()
        .stderr(predicate::str::contains("agent is not running"));
}

/// A `wcm` command in **default-endpoint** mode: only `WCM_DATA_DIR` is set, so
/// the agent binds `<tempdir>/run/agent.sock` (`env_clear` drops `XDG_RUNTIME_DIR`).
#[cfg(unix)]
fn default_cmd(v: &TestVault) -> Command {
    let mut c = v.cmd();
    c.env("WCM_DATA_DIR", v.dir.path());
    c
}

/// [`default_cmd`] as a `std` command (needed to spawn a foreground agent).
#[cfg(unix)]
fn default_std_cmd(v: &TestVault) -> StdCommand {
    let mut c = StdCommand::new(env!("CARGO_BIN_EXE_wcm"));
    c.env_clear();
    for key in ["PATH", "LLVM_PROFILE_FILE"] {
        if let Some(val) = std::env::var_os(key) {
            c.env(key, val);
        }
    }
    c.env("WCM_VAULT", v.path())
        .env("WCM_PASSPHRASE", PASS)
        .env("WCM_NO_WSL_PROXY", "1")
        .env("HOME", v.dir.path())
        .env("WCM_DATA_DIR", v.dir.path());
    c
}

/// An endpoint held by a live agent with no `agent.json` to find it by is a dead
/// end: nothing can discover or stop it, so `start` must say so instead of
/// spawning a child that can only fail to bind.
///
/// Unix only: on Windows the endpoint is a fresh random pipe name per start, so
/// the situation cannot arise without an explicit `WCM_AGENT_ENDPOINT`.
#[cfg(unix)]
#[test]
fn start_refuses_when_the_endpoint_is_taken_but_the_state_file_is_gone() {
    let v = TestVault::new();
    let child = default_std_cmd(&v)
        .args(["agent", "start", "--foreground"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn foreground agent");
    let _guard = Foreground(child);

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let out = default_cmd(&v)
            .args(["--json", "agent", "status"])
            .output()
            .expect("agent status");
        if json(&out)["running"] == true {
            break;
        }
        assert!(Instant::now() < deadline, "agent did not come up");
        std::thread::sleep(Duration::from_millis(50));
    }

    std::fs::remove_file(v.dir.path().join("agent.json")).expect("remove agent.json");
    default_cmd(&v)
        .args(["agent", "start"])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("state file"));
}

#[test]
fn foreground_agent_serves_status_until_killed() {
    let v = TestVault::new();
    let child = std_cmd(&v)
        .args(["agent", "start", "--foreground", "--idle", "1m"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn foreground agent");
    let _guard = Foreground(child);
    wait_until_running(&v);
    let s = agent_status(&v);
    assert_eq!(s["policy"]["idle_secs"], 60);
    assert!(state_file_exists(&v));
    cmd(&v).args(["agent", "stop"]).assert().success();
    assert_eq!(agent_status(&v)["running"], false);
}

/// Initialized vault with one password item `x` = `s3cret`.
fn vault_with_item() -> TestVault {
    let (v, _key) = TestVault::initialized();
    cmd(&v)
        .args(["add", "x", "--stdin"])
        .write_stdin("s3cret")
        .assert()
        .success();
    v
}

/// `wcm get x` without `WCM_PASSPHRASE`: only succeeds through the agent.
fn get_without_passphrase(v: &TestVault) -> Command {
    let mut c = cmd(v);
    c.env_remove("WCM_PASSPHRASE");
    c.args(["get", "x"]);
    c
}

#[test]
fn cached_key_serves_later_commands_without_the_passphrase() {
    let v = vault_with_item();
    get_without_passphrase(&v).assert().code(7);

    let _agent = start_agent(&v, &["--idle", "5m"]);
    cmd(&v)
        .args(["get", "x"])
        .assert()
        .success()
        .stdout("s3cret\n");
    get_without_passphrase(&v)
        .assert()
        .success()
        .stdout("s3cret\n");

    let s = agent_status(&v);
    let entries = s["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["uses"], 1);
    assert_eq!(
        entries[0]["path"],
        v.path().display().to_string(),
        "path is informational"
    );

    // Bypass: flag and environment variable.
    get_without_passphrase(&v)
        .arg("--no-agent")
        .assert()
        .code(7);
    get_without_passphrase(&v)
        .env("WCM_NO_AGENT", "1")
        .assert()
        .code(7);
    get_without_passphrase(&v)
        .env("WCM_NO_AGENT", "0")
        .assert()
        .success();

    cmd(&v).args(["agent", "lock"]).assert().success();
    get_without_passphrase(&v).assert().code(7);
}

#[test]
fn no_agent_never_caches() {
    let v = vault_with_item();
    let _agent = start_agent(&v, &[]);
    cmd(&v).args(["--no-agent", "get", "x"]).assert().success();
    assert!(agent_status(&v)["entries"]
        .as_array()
        .expect("entries")
        .is_empty());
    get_without_passphrase(&v).assert().code(7);
}

#[test]
fn rekey_refreshes_the_cached_key() {
    let v = vault_with_item();
    let _agent = start_agent(&v, &[]);
    cmd(&v).args(["get", "x"]).assert().success();
    cmd(&v)
        .args(["rekey", "--argon2-test-params"])
        .assert()
        .success();
    get_without_passphrase(&v)
        .assert()
        .success()
        .stdout("s3cret\n");
}

#[test]
fn stale_cached_key_heals_after_an_external_rekey() {
    let v = vault_with_item();
    let _agent = start_agent(&v, &[]);
    cmd(&v).args(["get", "x"]).assert().success();
    // Rotate the key behind the agent's back: the cache now holds a stale DEK.
    cmd(&v)
        .args(["--no-agent", "rekey", "--argon2-test-params"])
        .assert()
        .success();
    get_without_passphrase(&v).assert().code(7);
    // A normal unlock notices the stale key, falls back and re-caches.
    cmd(&v)
        .args(["get", "x"])
        .assert()
        .success()
        .stdout("s3cret\n");
    get_without_passphrase(&v)
        .assert()
        .success()
        .stdout("s3cret\n");
}

#[test]
fn stale_state_file_falls_back_to_a_normal_unlock() {
    let v = vault_with_item();
    let dead = if cfg!(windows) {
        format!(r"{}-dead", endpoint_for(&v))
    } else {
        v.dir.path().join("dead.sock").display().to_string()
    };
    let state = v.dir.path().join("agent.json");
    std::fs::write(
        &state,
        format!(
            r#"{{"endpoint":{},"pid":1,"started":"2026-08-25T00:00:00Z","version":"0.2.0"}}"#,
            serde_json::to_string(&dead).expect("json string")
        ),
    )
    .expect("write state");
    // No WCM_AGENT_ENDPOINT here: discovery must go through agent.json.
    let mut c = v.cmd();
    c.env("WCM_DATA_DIR", v.dir.path());
    c.args(["get", "x"]).assert().success().stdout("s3cret\n");
    assert!(!state.exists(), "stale agent.json removed");
}

#[test]
fn foreground_agent_with_max_uses_evicts_after_the_last_use() {
    let v = vault_with_item();
    let child = std_cmd(&v)
        .args(["agent", "start", "--foreground", "--max-uses", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn foreground agent");
    let _guard = Foreground(child);
    wait_until_running(&v);
    cmd(&v).args(["get", "x"]).assert().success();
    get_without_passphrase(&v).assert().success();
    get_without_passphrase(&v).assert().code(7);
    cmd(&v).args(["agent", "stop"]).assert().success();
}

#[test]
fn status_and_doctor_report_the_agent() {
    let v = vault_with_item();
    let before = json(&cmd(&v).args(["--json", "status"]).output().expect("status"));
    assert_eq!(before["agent"]["running"], false);
    assert_eq!(before["agent"]["cached"], false);
    let doctor = json(&cmd(&v).args(["--json", "doctor"]).output().expect("doctor"));
    assert_eq!(doctor["agent"]["running"], false);

    let _agent = start_agent(&v, &["--idle", "5m"]);
    let running = json(&cmd(&v).args(["--json", "status"]).output().expect("status"));
    assert_eq!(running["agent"]["running"], true);
    assert_eq!(running["agent"]["cached"], false);
    cmd(&v)
        .args(["status"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "agent:      running, not cached for this vault",
        ));

    cmd(&v).args(["get", "x"]).assert().success();
    let cached = json(&cmd(&v).args(["--json", "status"]).output().expect("status"));
    assert_eq!(cached["agent"]["cached"], true);
    assert_eq!(cached["agent"]["uses"], 0);
    assert!(cached["agent"]["expires_in_secs"].as_u64().expect("secs") <= 300);
    cmd(&v)
        .args(["status"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "agent:      running, cached for this vault (expires in ",
        ));

    let doctor = json(&cmd(&v).args(["--json", "doctor"]).output().expect("doctor"));
    assert_eq!(doctor["agent"]["running"], true);
    assert!(doctor["agent"]["pid"].as_u64().expect("pid") > 0);
    cmd(&v)
        .args(["doctor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("agent:         running (pid "));
}
