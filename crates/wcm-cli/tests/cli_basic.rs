mod common;

use common::{json, json_err, TestVault};
use predicates::prelude::*;

#[test]
fn version_and_exit_codes() {
    let v = TestVault::new();
    v.cmd()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("wcm 0."));
    let out = v.cmd().args(["--json", "version"]).output().expect("run");
    assert!(out.status.success());
    let j = json(&out);
    assert_eq!(j["name"], "wcm");
    assert_eq!(j["hello_compiled_in"], cfg!(windows));

    let out = v
        .cmd()
        .args(["--json", "--exit-codes"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let rows = json(&out);
    assert!(rows
        .as_array()
        .expect("array")
        .iter()
        .any(|r| r["exit"] == 3 && r["code"] == "NOT_FOUND"));
    v.cmd()
        .arg("--exit-codes")
        .assert()
        .success()
        .stdout(predicate::str::contains("AUTH_UNAVAILABLE"));
}

#[test]
fn no_command_is_usage_error() {
    let v = TestVault::new();
    v.cmd().assert().code(2);
    v.cmd().arg("--bogus-flag").assert().code(2);
    v.cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Windows Hello"));
}

#[test]
fn status_before_init_is_not_initialized() {
    let v = TestVault::new();
    let out = v.cmd().args(["--json", "status"]).output().expect("run");
    assert_eq!(out.status.code(), Some(5));
    let e = json_err(&out);
    assert_eq!(e["error"]["code"], "NOT_INITIALIZED");
    assert_eq!(e["error"]["exit"], 5);
    assert!(e["error"]["hint"]
        .as_str()
        .expect("hint")
        .contains("wcm init"));
    v.cmd()
        .arg("status")
        .assert()
        .code(5)
        .stderr(predicate::str::contains("error: vault not initialized"));
}

#[test]
fn init_creates_vault_with_recovery_and_passphrase_slots() {
    let v = TestVault::new();
    let out = v
        .cmd()
        .args([
            "--json",
            "init",
            "--no-hello",
            "--passphrase",
            "--argon2-test-params",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let j = json(&out);
    assert_eq!(j["hello_enrolled"], false);
    let key = j["recovery_key"].as_str().expect("key");
    assert!(key.starts_with("WCM1-"));
    let labels: Vec<&str> = j["slots"]
        .as_array()
        .expect("slots")
        .iter()
        .map(|s| s["label"].as_str().expect("l"))
        .collect();
    assert_eq!(labels, vec!["recovery", "passphrase"]);
    assert!(v.path().exists());

    // second init fails with ALREADY_EXISTS (4)
    let out = v
        .cmd()
        .args(["--json", "init", "--no-hello", "--passphrase"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(json_err(&out)["error"]["code"], "ALREADY_EXISTS");

    // status now works without unlocking
    let out = v.cmd().args(["--json", "status"]).output().expect("run");
    assert!(out.status.success());
    let s = json(&out);
    assert_eq!(s["generation"], 1);
    assert_eq!(s["slots"].as_array().expect("slots").len(), 2);
    assert_eq!(s["slots"][0]["kind"], "passphrase");
    v.cmd()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("recovery"));
}

#[test]
fn init_human_output_prints_recovery_key_once() {
    let v = TestVault::new();
    v.cmd()
        .args(["init", "--no-hello", "--passphrase", "--argon2-test-params"])
        .assert()
        .success()
        .stdout(predicate::str::contains("RECOVERY KEY"))
        .stdout(predicate::str::is_match(r"WCM1(-[A-Z2-7]{4}){8}").expect("re"));
}

#[test]
fn init_without_hello_or_passphrase_warns_but_succeeds() {
    let v = TestVault::new();
    v.cmd()
        .args(["init", "--no-hello", "--argon2-test-params"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "only be opened with the recovery key",
        ));
}

#[test]
fn init_on_non_windows_without_no_hello_falls_back_with_notice() {
    if cfg!(windows) {
        return;
    }
    let v = TestVault::new();
    v.cmd()
        .args(["init", "--passphrase", "--argon2-test-params"])
        .assert()
        .success()
        .stderr(predicate::str::contains("without a Hello slot"));
}

#[test]
fn doctor_reports_environment() {
    let (v, _) = TestVault::initialized();
    let out = v.cmd().args(["--json", "doctor"]).output().expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let d = json(&out);
    assert_eq!(d["vault_exists"], true);
    assert_eq!(d["vault_generation"], 1);
    assert_eq!(d["hello"]["compiled_in"], cfg!(windows));
    assert_eq!(d["passphrase_env_set"], true);
    assert!(d["problems"]
        .as_array()
        .expect("problems")
        .iter()
        .any(|p| p.as_str().expect("s").contains("WCM_PASSPHRASE")));
    v.cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("hello:"));
}

#[test]
fn completions_generate() {
    let v = TestVault::new();
    v.cmd()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("_wcm"));
    v.cmd()
        .args(["completions", "powershell"])
        .assert()
        .success()
        .stdout(predicate::str::contains("wcm"));
}
