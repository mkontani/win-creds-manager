//! Integration tests for `export`, `import`, `recover`, `rekey` and `slot`.
//!
//! Items are created through `wcm import` of a plaintext export document
//! built with the wcm-core API, and inspected through `wcm export --plaintext`.

mod common;

use std::path::{Path, PathBuf};

use common::{json, json_err, write_file, TestVault, PASS};
use predicates::prelude::*;
use wcm_core::export::PlainExport;
use wcm_core::item::{Field, FieldValue, Item, ItemKind};
use wcm_core::recovery_key::RecoveryKey;

const EXPORT_PASS: &str = "export-passphrase-xyz";
const NOW: &str = "2026-08-19T00:00:00Z";

fn password(name: &str, value: &str) -> Item {
    Item::new(name, ItemKind::Password, NOW).with_field("password", Field::secret_text(value))
}

fn plain_json(items: Vec<Item>) -> String {
    PlainExport {
        version: 1,
        exported: NOW.to_string(),
        items,
    }
    .to_json()
    .expect("json")
}

/// Writes `items` as a plaintext export file and imports it with `extra` flags.
fn import_items(v: &TestVault, file: &str, items: Vec<Item>, extra: &[&str]) -> serde_json::Value {
    let p = write_file(v.dir.path(), file, plain_json(items).as_bytes());
    let out = v
        .cmd()
        .args(["--json", "import"])
        .arg(&p)
        .args(extra)
        .output()
        .expect("run import");
    assert!(
        out.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    json(&out)
}

/// Dumps the vault as a plaintext export (stdout) and parses it.
fn dump(v: &TestVault, extra_env: &[(&str, &str)]) -> PlainExport {
    let mut c = v.cmd();
    for (k, val) in extra_env {
        c.env(k, val);
    }
    let out = c
        .args(["export", "--plaintext", "--i-know"])
        .output()
        .expect("run export");
    assert!(
        out.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    PlainExport::from_json(&String::from_utf8_lossy(&out.stdout)).expect("plain export")
}

fn names(e: &PlainExport) -> Vec<String> {
    let mut n: Vec<String> = e.items.iter().map(|i| i.name.clone()).collect();
    n.sort();
    n
}

fn secret_of(e: &PlainExport, name: &str) -> String {
    e.items
        .iter()
        .find(|i| i.name == name)
        .and_then(|i| i.primary())
        .and_then(|f| f.value.as_text())
        .expect("secret text")
        .to_string()
}

fn generation(v: &TestVault) -> u64 {
    let out = v.cmd().args(["--json", "status"]).output().expect("status");
    assert!(out.status.success());
    json(&out)["generation"].as_u64().expect("generation")
}

fn slot_labels(v: &TestVault) -> Vec<String> {
    let out = v
        .cmd()
        .args(["--json", "slot", "ls"])
        .output()
        .expect("slot ls");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    json(&out)
        .as_array()
        .expect("array")
        .iter()
        .map(|s| s["label"].as_str().expect("label").to_string())
        .collect()
}

// ---------------------------------------------------------------- export / import (plaintext)

#[test]
fn plaintext_export_requires_i_know() {
    let (v, _) = TestVault::initialized();
    let out = v
        .cmd()
        .args(["--json", "export", "--plaintext"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(json_err(&out)["error"]["code"], "INVALID_INPUT");
    // --i-know without --plaintext is rejected by clap (usage error).
    v.cmd().args(["export", "--i-know"]).assert().code(2);
}

#[test]
fn plaintext_import_export_roundtrip_with_binary_field() {
    let (v, _) = TestVault::initialized();
    let blob = vec![0u8, 255, 1, 2, 3];
    let items = vec![
        password("web/a", "secret-a"),
        Item::new("files/blob", ItemKind::File, NOW)
            .with_field("content", Field::secret_bytes(blob.clone()))
            .with_field("filename", Field::public_text("blob.bin"))
            .with_notes("binary")
            .with_tags(vec!["t1".into()]),
    ];
    let r = import_items(&v, "in.json", items, &[]);
    assert_eq!(r["added"], 2);
    assert_eq!(r["overwritten"], 0);
    assert_eq!(r["skipped"], 0);
    assert!(r["file"].as_str().expect("file").ends_with("in.json"));
    assert_eq!(generation(&v), 2);

    // Human output.
    let p = write_file(
        v.dir.path(),
        "in2.json",
        plain_json(vec![password("web/b", "b")]).as_bytes(),
    );
    v.cmd()
        .arg("import")
        .arg(&p)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Imported: added 1, overwritten 0, skipped 0",
        ));

    // Export to stdout: the document itself is printed, secrets included, with a warning.
    let out = v
        .cmd()
        .args(["export", "--plaintext", "--i-know"])
        .output()
        .expect("run");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("warning"));
    let e = PlainExport::from_json(&String::from_utf8_lossy(&out.stdout)).expect("parse");
    assert_eq!(names(&e), vec!["files/blob", "web/a", "web/b"]);
    assert_eq!(secret_of(&e, "web/a"), "secret-a");
    let blob_item = e
        .items
        .iter()
        .find(|i| i.name == "files/blob")
        .expect("blob item");
    assert_eq!(
        blob_item.fields["content"].value,
        FieldValue::Bytes(blob.clone())
    );
    assert!(blob_item.fields["content"].secret);
    assert!(!blob_item.fields["filename"].secret);
    assert_eq!(blob_item.notes, "binary");
    assert_eq!(blob_item.tags, vec!["t1"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"b64\""));

    // Export to a file: JSON report, refuse to overwrite.
    let target = v.dir.path().join("out.json");
    let out = v
        .cmd()
        .args(["--json", "export", "--plaintext", "--i-know", "-o"])
        .arg(&target)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = json(&out);
    assert_eq!(r["items"], 3);
    assert_eq!(r["encrypted"], false);
    assert_eq!(r["file"].as_str().expect("file"), target.to_string_lossy());
    let on_disk = PlainExport::from_json(&std::fs::read_to_string(&target).expect("read"))
        .expect("parse file");
    assert_eq!(on_disk.items.len(), 3);
    let out = v
        .cmd()
        .args(["--json", "export", "--plaintext", "--i-know", "-o"])
        .arg(&target)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(json_err(&out)["error"]["code"], "ALREADY_EXISTS");

    // Human report for file export.
    let target2 = v.dir.path().join("out2.json");
    v.cmd()
        .args(["export", "--plaintext", "--i-know", "-o"])
        .arg(&target2)
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported 3 items"))
        .stdout(predicate::str::contains("out2.json"));
}

#[test]
fn import_merge_overwrite_and_replace_modes() {
    let (v, _) = TestVault::initialized();
    let r = import_items(
        &v,
        "one.json",
        vec![password("a", "a1"), password("b", "b1")],
        &[],
    );
    assert_eq!(
        (r["added"].as_u64(), r["skipped"].as_u64()),
        (Some(2), Some(0))
    );

    // Default merge: existing names are skipped, new ones added.
    let r = import_items(
        &v,
        "two.json",
        vec![password("a", "a2"), password("c", "c2")],
        &[],
    );
    assert_eq!(r["added"], 1);
    assert_eq!(r["overwritten"], 0);
    assert_eq!(r["skipped"], 1);
    let e = dump(&v, &[]);
    assert_eq!(names(&e), vec!["a", "b", "c"]);
    assert_eq!(secret_of(&e, "a"), "a1");

    // --overwrite replaces same-name items.
    let r = import_items(
        &v,
        "three.json",
        vec![password("a", "a3"), password("d", "d3")],
        &["--overwrite"],
    );
    assert_eq!(r["added"], 1);
    assert_eq!(r["overwritten"], 1);
    assert_eq!(r["skipped"], 0);
    let e = dump(&v, &[]);
    assert_eq!(names(&e), vec!["a", "b", "c", "d"]);
    assert_eq!(secret_of(&e, "a"), "a3");

    // --replace drops everything first.
    let r = import_items(&v, "four.json", vec![password("z", "z4")], &["--replace"]);
    assert_eq!(r["added"], 1);
    assert_eq!(r["overwritten"], 0);
    assert_eq!(r["skipped"], 0);
    let e = dump(&v, &[]);
    assert_eq!(names(&e), vec!["z"]);

    // --overwrite and --replace conflict (clap usage error).
    let p = v.dir.path().join("four.json");
    v.cmd()
        .args(["import", "--overwrite", "--replace"])
        .arg(&p)
        .assert()
        .code(2);
}

#[test]
fn import_rejects_garbage_missing_file_and_uninitialized_vault() {
    let (v, _) = TestVault::initialized();
    let garbage = write_file(
        v.dir.path(),
        "garbage.bin",
        b"this is not an export\x00\x01",
    );
    let out = v
        .cmd()
        .args(["--json", "import"])
        .arg(&garbage)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(12));
    assert_eq!(json_err(&out)["error"]["code"], "FORMAT");

    // Valid JSON but not an export document.
    let not_export = write_file(v.dir.path(), "x.json", b"{\"hello\": \"world\"}");
    v.cmd().arg("import").arg(&not_export).assert().code(12);

    // Unsupported export version.
    let bad_version = write_file(
        v.dir.path(),
        "v9.json",
        b"{\"version\": 9, \"exported\": \"x\", \"items\": []}",
    );
    v.cmd().arg("import").arg(&bad_version).assert().code(12);

    // Missing file → i/o error.
    let out = v
        .cmd()
        .args(["--json", "import"])
        .arg(v.dir.path().join("nope.json"))
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(10));
    assert_eq!(json_err(&out)["error"]["code"], "IO");

    // Destination vault not initialized.
    let fresh = TestVault::new();
    let p = write_file(
        fresh.dir.path(),
        "ok.json",
        plain_json(vec![password("a", "a")]).as_bytes(),
    );
    fresh.cmd().arg("import").arg(&p).assert().code(5);
}

// ---------------------------------------------------------------- export / import (encrypted)

fn encrypted_export(v: &TestVault, target: &Path, pass: Option<&str>) -> std::process::Output {
    let mut c = v.cmd();
    if let Some(p) = pass {
        c.env("WCM_EXPORT_PASSPHRASE", p);
    }
    c.args(["--json", "export", "--argon2-test-params", "-o"])
        .arg(target)
        .output()
        .expect("run export")
}

#[test]
fn encrypted_export_creates_standalone_vault_and_imports_back() {
    let (v, _) = TestVault::initialized();
    import_items(
        &v,
        "in.json",
        vec![password("a", "a1"), password("b", "b1")],
        &[],
    );
    assert_eq!(generation(&v), 2);

    let target = v.dir.path().join("backup.wcm");
    let out = encrypted_export(&v, &target, Some(EXPORT_PASS));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = json(&out);
    assert_eq!(r["items"], 2);
    assert_eq!(r["encrypted"], true);
    assert_eq!(r["file"].as_str().expect("file"), target.to_string_lossy());
    assert!(target.exists());
    // No lock / backup litter next to the export file.
    assert!(!v.dir.path().join("backup.wcm.bak").exists());
    assert!(!v.dir.path().join("backup.wcm.lock").exists());
    // The source vault recorded last_export (generation bumped).
    assert_eq!(generation(&v), 3);

    // The export is a valid vault with a single passphrase slot labelled "export".
    let out = v
        .cmd()
        .args(["--json", "status", "--vault"])
        .arg(&target)
        .output()
        .expect("status");
    assert!(out.status.success());
    let s = json(&out);
    let slots = s["slots"].as_array().expect("slots");
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0]["label"], "export");
    assert_eq!(slots[0]["kind"], "passphrase");

    // Refuse to overwrite.
    let out = encrypted_export(&v, &target, Some(EXPORT_PASS));
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(json_err(&out)["error"]["code"], "ALREADY_EXISTS");

    // Without a passphrase source under --no-input → auth unavailable.
    let out = encrypted_export(&v, &v.dir.path().join("other.wcm"), None);
    assert_eq!(out.status.code(), Some(7));
    assert!(!v.dir.path().join("other.wcm").exists());

    // Import into a fresh vault.
    let (dst, _) = TestVault::initialized();
    let out = dst
        .cmd()
        .env("WCM_EXPORT_PASSPHRASE", EXPORT_PASS)
        .args(["--json", "import"])
        .arg(&target)
        .output()
        .expect("import");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = json(&out);
    assert_eq!(r["added"], 2);
    let e = dump(&dst, &[]);
    assert_eq!(names(&e), vec!["a", "b"]);
    assert_eq!(secret_of(&e, "b"), "b1");

    // Wrong export passphrase → integrity error (8).
    let (dst2, _) = TestVault::initialized();
    let out = dst2
        .cmd()
        .env("WCM_EXPORT_PASSPHRASE", "wrong")
        .args(["--json", "import"])
        .arg(&target)
        .output()
        .expect("import");
    assert_eq!(out.status.code(), Some(8));
    assert_eq!(json_err(&out)["error"]["code"], "INTEGRITY");

    // No export passphrase and --no-input → 7 (the vault's own WCM_PASSPHRASE is not used).
    let out = dst2
        .cmd()
        .args(["--json", "import"])
        .arg(&target)
        .output()
        .expect("import");
    assert_eq!(out.status.code(), Some(7));

    // Human output of an encrypted export.
    let target2 = v.dir.path().join("backup2.wcm");
    v.cmd()
        .env("WCM_EXPORT_PASSPHRASE", EXPORT_PASS)
        .args(["export", "--argon2-test-params", "-o"])
        .arg(&target2)
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported 2 items"))
        .stdout(predicate::str::contains("backup2.wcm"));
}

#[test]
fn encrypted_export_default_file_name_in_cwd() {
    let (v, _) = TestVault::initialized();
    let cwd = tempfile::tempdir().expect("cwd");
    let out = v
        .cmd()
        .current_dir(cwd.path())
        .env("WCM_EXPORT_PASSPHRASE", EXPORT_PASS)
        .args(["--json", "export", "--argon2-test-params"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let file = json(&out)["file"].as_str().expect("file").to_string();
    let re = regex_lite(&file);
    assert!(re, "unexpected default file name: {file}");
    let entries: Vec<PathBuf> = std::fs::read_dir(cwd.path())
        .expect("read_dir")
        .map(|e| e.expect("entry").path())
        .collect();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(
        entries[0].file_name().and_then(|n| n.to_str()),
        Some(file.as_str())
    );
}

/// `wcm-export-YYYYMMDD.wcm`
fn regex_lite(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("wcm-export-") else {
        return false;
    };
    let Some(date) = rest.strip_suffix(".wcm") else {
        return false;
    };
    date.len() == 8 && date.chars().all(|c| c.is_ascii_digit())
}

// ---------------------------------------------------------------- recover

#[test]
fn recover_no_hello_replaces_passphrase_slot_using_recovery_key() {
    let (v, key) = TestVault::initialized();
    import_items(&v, "in.json", vec![password("a", "a1")], &[]);

    // Wrong (but well-formed) recovery key → integrity error, nothing changed.
    let wrong_key = RecoveryKey::generate().display();
    let out = v
        .cmd()
        .env("WCM_PASSPHRASE", &wrong_key)
        .env("WCM_NEW_PASSPHRASE", "new-pass")
        .args(["--json", "recover", "--no-hello", "--argon2-test-params"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(8));
    assert_eq!(generation(&v), 2);

    // Recovery key (WCM_PASSPHRASE) unlocks; WCM_NEW_PASSPHRASE seals the new slot.
    let out = v
        .cmd()
        .env("WCM_PASSPHRASE", &key)
        .env("WCM_NEW_PASSPHRASE", "new-pass")
        .args(["--json", "recover", "--no-hello", "--argon2-test-params"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = json(&out);
    assert_eq!(r["removed_slots"], serde_json::json!(["passphrase"]));
    assert_eq!(r["added_slot"]["label"], "passphrase");
    assert_eq!(r["added_slot"]["kind"], "passphrase");
    assert_eq!(generation(&v), 3);
    assert_eq!(slot_labels(&v), vec!["recovery", "passphrase"]);

    // The old passphrase no longer opens the vault; the new one does.
    let out = v
        .cmd()
        .args(["export", "--plaintext", "--i-know"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(8));
    let e = dump(&v, &[("WCM_PASSPHRASE", "new-pass")]);
    assert_eq!(names(&e), vec!["a"]);

    // Human output mentions the new slot; --slot is honoured for the unlock.
    v.cmd()
        .env("WCM_PASSPHRASE", "new-pass")
        .env("WCM_NEW_PASSPHRASE", "newer-pass")
        .args([
            "--slot",
            "passphrase",
            "recover",
            "--no-hello",
            "--argon2-test-params",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("passphrase"));
    let e = dump(&v, &[("WCM_PASSPHRASE", "newer-pass")]);
    assert_eq!(names(&e), vec!["a"]);

    // Uninitialized vault → 5.
    let fresh = TestVault::new();
    fresh
        .cmd()
        .args(["recover", "--no-hello", "--argon2-test-params"])
        .assert()
        .code(5);
}

#[test]
fn recover_without_hello_off_windows_falls_back_to_passphrase() {
    if cfg!(windows) {
        return;
    }
    let (v, key) = TestVault::initialized();
    v.cmd()
        .env("WCM_PASSPHRASE", &key)
        .env("WCM_NEW_PASSPHRASE", "np")
        .args(["recover", "--argon2-test-params"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Hello"));
    assert_eq!(slot_labels(&v), vec!["recovery", "passphrase"]);
    let e = dump(&v, &[("WCM_PASSPHRASE", "np")]);
    assert!(e.items.is_empty());
}

// ---------------------------------------------------------------- rekey

#[test]
fn rekey_rotates_dek_and_recovery_key() {
    let (v, old_key) = TestVault::initialized();
    import_items(&v, "in.json", vec![password("a", "a1")], &[]);
    assert_eq!(generation(&v), 2);

    let out = v
        .cmd()
        .args(["--json", "rekey", "--argon2-test-params"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = json(&out);
    assert_eq!(r["slots"], serde_json::json!(["recovery", "passphrase"]));
    let new_key = r["recovery_key"]
        .as_str()
        .expect("recovery_key")
        .to_string();
    assert!(new_key.starts_with("WCM1-"));
    assert_ne!(new_key, old_key);
    assert_eq!(generation(&v), 3);
    assert_eq!(slot_labels(&v), vec!["recovery", "passphrase"]);

    // Existing passphrase (WCM_PASSPHRASE) still works and data is intact.
    let e = dump(&v, &[]);
    assert_eq!(secret_of(&e, "a"), "a1");

    // New recovery key opens the vault; the old one does not.
    let mut c = v.cmd();
    c.env("WCM_PASSPHRASE", &new_key);
    let out = c
        .args(["--slot", "recovery", "export", "--plaintext", "--i-know"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = v
        .cmd()
        .env("WCM_PASSPHRASE", &old_key)
        .args(["--slot", "recovery", "export", "--plaintext", "--i-know"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(8));

    // Human output prints the recovery key once.
    v.cmd()
        .args(["rekey", "--argon2-test-params"])
        .assert()
        .success()
        .stdout(predicate::str::contains("RECOVERY KEY"))
        .stdout(predicate::str::is_match(r"WCM1(-[A-Z2-7]{4}){8}").expect("re"));

    // Uninitialized → 5.
    TestVault::new().cmd().arg("rekey").assert().code(5);
}

// ---------------------------------------------------------------- slot

#[test]
fn slot_ls_add_rm_lifecycle() {
    let (v, _) = TestVault::initialized();

    // ls (no unlock): JSON + human table.
    let out = v
        .cmd()
        .env_remove("WCM_PASSPHRASE")
        .args(["--json", "slot", "ls"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let rows = json(&out);
    let rows = rows.as_array().expect("array");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["id"], 1);
    assert_eq!(rows[0]["label"], "recovery");
    assert_eq!(rows[0]["kind"], "passphrase");
    assert!(rows[0].get("hw_backed").is_none());
    v.cmd()
        .args(["slot", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains("recovery"))
        .stdout(predicate::str::contains("passphrase"));

    // add: neither flag → usage error.
    let out = v
        .cmd()
        .args(["--json", "slot", "add"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    // both flags conflict (clap).
    v.cmd()
        .args(["slot", "add", "--passphrase", "--hello"])
        .assert()
        .code(2);

    // add a passphrase slot with a custom label; secret from WCM_NEW_PASSPHRASE.
    let out = v
        .cmd()
        .env("WCM_NEW_PASSPHRASE", "second-pass")
        .args([
            "--json",
            "slot",
            "add",
            "--passphrase",
            "--label",
            "second",
            "--argon2-test-params",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = json(&out);
    assert_eq!(r["id"], 3);
    assert_eq!(r["label"], "second");
    assert_eq!(r["kind"], "passphrase");
    assert_eq!(slot_labels(&v), vec!["recovery", "passphrase", "second"]);
    // The new slot opens the vault. `--slot` pins the slot; without it an
    // env-supplied passphrase is tried against every passphrase slot, so it
    // still works — and a passphrase matching no slot is an integrity error.
    let out = v
        .cmd()
        .env("WCM_PASSPHRASE", "second-pass")
        .args(["--slot", "second", "export", "--plaintext", "--i-know"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let e = PlainExport::from_json(&String::from_utf8_lossy(&out.stdout)).expect("parse");
    assert!(e.items.is_empty());
    let out = v
        .cmd()
        .env("WCM_PASSPHRASE", "second-pass")
        .args(["export", "--plaintext", "--i-know"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = v
        .cmd()
        .env("WCM_PASSPHRASE", "matches-no-slot")
        .args(["export", "--plaintext", "--i-know"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(8));

    // Duplicate label → 4; default label "passphrase" also exists → 4.
    let out = v
        .cmd()
        .args([
            "--json",
            "slot",
            "add",
            "--passphrase",
            "--label",
            "second",
            "--argon2-test-params",
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(json_err(&out)["error"]["code"], "ALREADY_EXISTS");
    v.cmd()
        .args(["slot", "add", "--passphrase", "--argon2-test-params"])
        .assert()
        .code(4);

    // Hello slot cannot be added off-Windows.
    if !cfg!(windows) {
        let out = v
            .cmd()
            .args(["--json", "slot", "add", "--hello"])
            .output()
            .expect("run");
        assert_eq!(out.status.code(), Some(7));
        assert_eq!(slot_labels(&v).len(), 3);
    }

    // Human add output.
    v.cmd()
        .env("WCM_NEW_PASSPHRASE", "third-pass")
        .args([
            "slot",
            "add",
            "--passphrase",
            "--label",
            "third",
            "--argon2-test-params",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("third"));

    // rm without -f under --no-input → 2; unknown label → 2.
    let out = v
        .cmd()
        .args(["--json", "slot", "rm", "second"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(json_err(&out)["error"]["message"]
        .as_str()
        .expect("msg")
        .contains("-f"));
    assert_eq!(slot_labels(&v).len(), 4);
    v.cmd().args(["slot", "rm", "-f", "nope"]).assert().code(2);

    // rm -f removes.
    let out = v
        .cmd()
        .args(["--json", "slot", "rm", "-f", "second"])
        .output()
        .expect("run");
    assert!(out.status.success());
    assert_eq!(json(&out)["removed"], "second");
    assert_eq!(slot_labels(&v), vec!["recovery", "passphrase", "third"]);
    v.cmd()
        .args(["slot", "rm", "--force", "third"])
        .assert()
        .success()
        .stdout(predicate::str::contains("third"));

    // Removing the slot used for this unlock is fine as long as another remains...
    v.cmd()
        .args(["slot", "rm", "-f", "passphrase"])
        .assert()
        .success();
    assert_eq!(slot_labels(&v), vec!["recovery"]);
    // ...but the last slot is refused (before any unlock prompt).
    let out = v
        .cmd()
        .env("WCM_PASSPHRASE", PASS)
        .args(["--json", "slot", "rm", "-f", "recovery"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(json_err(&out)["error"]["message"]
        .as_str()
        .expect("msg")
        .contains("last"));
    assert_eq!(slot_labels(&v), vec!["recovery"]);
    // Unlock failure (no matching passphrase) surfaces when the removal is otherwise valid.
    let (v2, _) = TestVault::initialized();
    let out = v2
        .cmd()
        .env("WCM_PASSPHRASE", "not-the-passphrase")
        .args(["--json", "slot", "rm", "-f", "passphrase"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(8));
    assert_eq!(slot_labels(&v2), vec!["recovery", "passphrase"]);

    // Uninitialized vault.
    TestVault::new().cmd().args(["slot", "ls"]).assert().code(5);
}

// ------------------------------------------------- key material / .bak safety

/// Path of the previous-generation backup next to the vault.
fn backup_path(v: &TestVault) -> PathBuf {
    v.dir.path().join("vault.wcm.bak")
}

#[test]
fn key_rotating_commands_remove_the_stale_backup() {
    let (v, key) = TestVault::initialized();
    import_items(&v, "in.json", vec![password("a", "a1")], &[]);
    assert!(
        backup_path(&v).exists(),
        "an ordinary write keeps the previous generation in .bak"
    );

    // rekey: the .bak still opens with the OLD recovery key → it must go.
    let out = v
        .cmd()
        .args(["--json", "rekey", "--argon2-test-params"])
        .output()
        .expect("rekey");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let new_key = json(&out)["recovery_key"]
        .as_str()
        .expect("recovery_key")
        .to_string();
    assert!(!backup_path(&v).exists(), "rekey must drop the stale .bak");
    assert_ne!(new_key, key);

    // slot rm
    v.cmd()
        .env("WCM_NEW_PASSPHRASE", "second-pass")
        .args([
            "slot",
            "add",
            "--passphrase",
            "--label",
            "second",
            "--argon2-test-params",
        ])
        .assert()
        .success();
    assert!(backup_path(&v).exists());
    v.cmd()
        .args(["slot", "rm", "-f", "second"])
        .assert()
        .success();
    assert!(
        !backup_path(&v).exists(),
        "slot rm must drop the stale .bak"
    );

    // recover
    import_items(&v, "in2.json", vec![password("b", "b1")], &[]);
    assert!(backup_path(&v).exists());
    v.cmd()
        .env("WCM_PASSPHRASE", &new_key)
        .env("WCM_NEW_PASSPHRASE", "np")
        .args(["recover", "--no-hello", "--argon2-test-params"])
        .assert()
        .success();
    assert!(
        !backup_path(&v).exists(),
        "recover must drop the stale .bak"
    );
}

#[cfg(unix)]
#[test]
fn recover_that_cannot_save_leaves_the_vault_openable() {
    use std::os::unix::fs::PermissionsExt;

    let (v, key) = TestVault::initialized();
    import_items(&v, "in.json", vec![password("a", "a1")], &[]);
    let before = slot_labels(&v);

    // A read-only directory makes the atomic write (temp file) fail *after* the
    // new slot has been sealed — the point where the old key material must
    // still be intact.
    let dir = v.dir.path();
    let mode = std::fs::metadata(dir).expect("meta").permissions().mode();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).expect("chmod");
    let out = v
        .cmd()
        .env("WCM_PASSPHRASE", &key)
        .env("WCM_NEW_PASSPHRASE", "np")
        .args(["recover", "--no-hello", "--argon2-test-params"])
        .output()
        .expect("run recover");
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).expect("restore");

    assert!(
        !out.status.success(),
        "recover must fail when the vault cannot be written"
    );
    assert_eq!(slot_labels(&v), before, "the slots must be unchanged");
    let e = dump(&v, &[]);
    assert_eq!(names(&e), vec!["a"], "the vault still opens as before");
}
