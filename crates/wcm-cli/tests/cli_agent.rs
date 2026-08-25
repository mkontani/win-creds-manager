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
