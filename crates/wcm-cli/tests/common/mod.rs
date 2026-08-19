//! Shared helpers for CLI integration tests (passphrase backend, temp vault).
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use tempfile::TempDir;

/// Passphrase used by all tests (via `WCM_PASSPHRASE`).
pub const PASS: &str = "test-passphrase-123";

/// A temporary vault directory.
pub struct TestVault {
    pub dir: TempDir,
}

impl TestVault {
    /// Fresh, uninitialized vault location.
    pub fn new() -> TestVault {
        TestVault {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    /// Vault file path.
    pub fn path(&self) -> PathBuf {
        self.dir.path().join("vault.wcm")
    }

    /// A `wcm` command pre-configured for this vault with the test passphrase and no Hello.
    pub fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("wcm").expect("wcm binary");
        c.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            c.env("PATH", path);
        }
        // Keep coverage instrumentation working under `cargo llvm-cov`: the spawned
        // binary must know where to write its profile, otherwise it drops a
        // `default_*.profraw` in the crate dir that is never merged.
        if let Some(p) = std::env::var_os("LLVM_PROFILE_FILE") {
            c.env("LLVM_PROFILE_FILE", p);
        }
        c.env("WCM_VAULT", self.path());
        c.env("WCM_PASSPHRASE", PASS);
        c.env("WCM_NO_WSL_PROXY", "1");
        c.env("HOME", self.dir.path());
        c.arg("--no-input");
        c
    }

    /// Initializes the vault with a passphrase slot (fast Argon2) and returns the recovery key.
    pub fn init(&self) -> String {
        let out = self
            .cmd()
            .args([
                "--json",
                "init",
                "--no-hello",
                "--passphrase",
                "--argon2-test-params",
            ])
            .output()
            .expect("run init");
        assert!(
            out.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("init json");
        v["recovery_key"]
            .as_str()
            .expect("recovery_key")
            .to_string()
    }

    /// Initialized vault.
    pub fn initialized() -> (TestVault, String) {
        let v = TestVault::new();
        let key = v.init();
        (v, key)
    }
}

/// Parses stdout as JSON.
pub fn json(out: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid json ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

/// Parses the JSON error envelope from stderr.
pub fn json_err(out: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&out.stderr).unwrap_or_else(|e| {
        panic!(
            "invalid json error ({e}): {}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// Writes a file in the test dir.
pub fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).expect("write file");
    p
}
