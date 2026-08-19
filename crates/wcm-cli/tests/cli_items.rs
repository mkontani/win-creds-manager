//! Integration tests for the item commands: add / set / get / show / ls / rm / mv /
//! generate / unclip and the clipboard helper's disabled path.

mod common;

use std::process::Output;

use common::{json, json_err, write_file, TestVault};
use predicates::prelude::*;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// `wcm add <name> --stdin` with `secret` piped in.
fn add_stdin(v: &TestVault, name: &str, secret: &str, extra: &[&str]) -> Output {
    let out = v
        .cmd()
        .args(["add", name, "--stdin"])
        .args(extra)
        .write_stdin(secret)
        .output()
        .expect("run add");
    assert!(out.status.success(), "add {name} failed: {}", stderr(&out));
    out
}

fn get(v: &TestVault, args: &[&str]) -> Output {
    v.cmd().arg("get").args(args).output().expect("run get")
}

fn ed25519_pem(comment: &str) -> String {
    let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("keygen");
    key.set_comment(comment);
    key.to_openssh(LineEnding::LF).expect("pem").to_string()
}

// ---------------------------------------------------------------- add / get

#[test]
fn add_stdin_then_get_roundtrip_with_newline_handling() {
    let (v, _) = TestVault::initialized();
    let out = add_stdin(&v, "svc/pw", "hunter2\n", &[]);
    assert!(stderr(&out).contains("Added svc/pw (password)"));
    assert!(out.stdout.is_empty(), "add must not print the secret");

    // default: value + newline
    let out = get(&v, &["svc/pw"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"hunter2\n");

    // --raw and -n: no trailing newline
    assert_eq!(get(&v, &["svc/pw", "--raw"]).stdout, b"hunter2");
    assert_eq!(get(&v, &["svc/pw", "-n"]).stdout, b"hunter2");

    // only one trailing newline is stripped on add
    add_stdin(&v, "svc/two", "a\n\n", &[]);
    assert_eq!(get(&v, &["svc/two", "--raw"]).stdout, b"a\n");

    // --json get
    let out = v
        .cmd()
        .args(["--json", "get", "svc/pw"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let j = json(&out);
    assert_eq!(j[0]["name"], "svc/pw");
    assert_eq!(j[0]["field"], "password");
    assert_eq!(j[0]["value"], "hunter2");
    assert_eq!(j[0]["secret"], true);
}

#[test]
fn add_json_output_and_value_flag() {
    let (v, _) = TestVault::initialized();
    let out = v
        .cmd()
        .args([
            "--json", "add", "tok", "--value", "abc", "--kind", "token", "--notes", "n", "--tag",
            "b", "--tag", "a", "--tag", "a",
        ])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    let j = json(&out);
    assert_eq!(j["name"], "tok");
    assert_eq!(j["kind"], "token");
    assert_eq!(j["generated"], false);
    assert!(j.get("value").is_none());
    assert_eq!(j["fields"], serde_json::json!(["token"]));
    assert_eq!(get(&v, &["tok"]).stdout, b"abc\n");

    let out = v
        .cmd()
        .args(["--json", "show", "tok"])
        .output()
        .expect("run");
    let s = json(&out);
    assert_eq!(s["tags"], serde_json::json!(["a", "b"]));
    assert_eq!(s["notes"], "n");
}

#[test]
fn add_duplicate_is_exit_4_and_force_overwrites() {
    let (v, _) = TestVault::initialized();
    add_stdin(&v, "dup", "one", &[]);
    let out = v
        .cmd()
        .args(["--json", "add", "dup", "--stdin"])
        .write_stdin("two")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(4));
    let e = json_err(&out);
    assert_eq!(e["error"]["code"], "ALREADY_EXISTS");
    assert_eq!(e["error"]["exit"], 4);
    assert_eq!(get(&v, &["dup", "--raw"]).stdout, b"one");

    add_stdin(&v, "dup", "two", &["--force"]);
    assert_eq!(get(&v, &["dup", "--raw"]).stdout, b"two");
    // short flag too
    add_stdin(&v, "dup", "three", &["-f"]);
    assert_eq!(get(&v, &["dup", "--raw"]).stdout, b"three");
}

#[test]
fn add_invalid_name_is_exit_2() {
    let (v, _) = TestVault::initialized();
    let out = v
        .cmd()
        .args(["--json", "add", "--value", "x", "--", "-x"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert_eq!(json_err(&out)["error"]["code"], "INVALID_INPUT");
    v.cmd()
        .args(["add", "a//b", "--value", "x"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("error: invalid input"));
    // bad --field syntax
    v.cmd()
        .args(["add", "ok", "--value", "x", "--field", "nokv"])
        .assert()
        .code(2);
    // nothing was written
    v.cmd().args(["get", "ok"]).assert().code(3);
}

#[test]
fn add_before_init_is_not_initialized() {
    let v = TestVault::new();
    v.cmd().args(["add", "x", "--value", "y"]).assert().code(5);
}

#[test]
fn add_prompt_with_no_input_fails_auth_unavailable() {
    let (v, _) = TestVault::initialized();
    // no source flag → interactive prompt → --no-input refuses (7)
    v.cmd().args(["add", "x"]).assert().code(7);
}

#[test]
fn get_missing_item_and_field_are_exit_3() {
    let (v, _) = TestVault::initialized();
    let out = v
        .cmd()
        .args(["--json", "get", "nope"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
    let e = json_err(&out);
    assert_eq!(e["error"]["code"], "NOT_FOUND");
    assert_eq!(e["error"]["exit"], 3);
    assert!(e["error"]["hint"]
        .as_str()
        .expect("hint")
        .contains("wcm ls"));

    add_stdin(&v, "a", "va", &[]);
    // second name missing → nothing printed, exit 3
    let out = get(&v, &["a", "nope"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    // missing field
    let out = get(&v, &["a", "--field", "username"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(stderr(&out).contains("no field"));
}

#[test]
fn get_public_field_and_multiple_names() {
    let (v, _) = TestVault::initialized();
    add_stdin(
        &v,
        "a",
        "va",
        &["--kind", "login", "--field", "username=alice"],
    );
    add_stdin(&v, "b", "vb", &[]);
    assert_eq!(get(&v, &["a", "--field", "username"]).stdout, b"alice\n");
    assert_eq!(get(&v, &["a", "b"]).stdout, b"va\nvb\n");
    assert_eq!(get(&v, &["a", "b", "--raw"]).stdout, b"vavb");
    assert_eq!(get(&v, &["b", "a", "-n"]).stdout, b"vbva");

    let out = v
        .cmd()
        .args(["--json", "get", "a", "b", "--field", "username"])
        .output()
        .expect("run");
    // b has no username → NOT_FOUND before printing anything
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());

    let out = v
        .cmd()
        .args(["--json", "get", "a", "--field", "username"])
        .output()
        .expect("run");
    let j = json(&out);
    assert_eq!(j[0]["value"], "alice");
    assert_eq!(j[0]["secret"], false);
}

#[test]
fn get_clip_and_out_file_require_exactly_one_name() {
    let (v, _) = TestVault::initialized();
    add_stdin(&v, "a", "va", &[]);
    add_stdin(&v, "b", "vb", &[]);
    v.cmd()
        .args(["get", "a", "b", "--clip"])
        .env("WCM_CLIP_DISABLE", "1")
        .assert()
        .code(2);
    let f = v.dir.path().join("out.bin");
    v.cmd()
        .args(["get", "a", "b", "--out-file"])
        .arg(&f)
        .assert()
        .code(2);
    assert!(!f.exists());
}

#[test]
fn get_out_file_io_error_is_exit_10() {
    let (v, _) = TestVault::initialized();
    add_stdin(&v, "a", "va", &[]);
    v.cmd()
        .args(["get", "a", "--out-file"])
        .arg(v.dir.path().join("missing-dir").join("x"))
        .assert()
        .code(10);
}

#[test]
fn add_file_binary_roundtrip() {
    let (v, _) = TestVault::initialized();
    let blob: Vec<u8> = (0..=255u8).collect();
    let p = write_file(v.dir.path(), "blob.bin", &blob);

    let out = v
        .cmd()
        .args(["--json", "add", "files/blob", "--file"])
        .arg(&p)
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    let j = json(&out);
    assert_eq!(j["kind"], "file");
    let fields = j["fields"].as_array().expect("fields");
    assert!(fields.contains(&serde_json::json!("content")));
    assert!(fields.contains(&serde_json::json!("filename")));

    // filename is a public field with the basename
    assert_eq!(
        get(&v, &["files/blob", "--field", "filename", "--raw"]).stdout,
        b"blob.bin"
    );

    // --out-file roundtrip
    let outp = v.dir.path().join("restored.bin");
    let out = v
        .cmd()
        .args(["get", "files/blob", "--out-file"])
        .arg(&outp)
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
    assert_eq!(std::fs::read(&outp).expect("read"), blob);

    // to a pipe: raw bytes + newline unless --raw
    let mut expected = blob.clone();
    expected.push(b'\n');
    assert_eq!(get(&v, &["files/blob"]).stdout, expected);
    assert_eq!(get(&v, &["files/blob", "--raw"]).stdout, blob);

    // JSON uses the {"b64": ...} representation
    let out = v
        .cmd()
        .args(["--json", "get", "files/blob"])
        .output()
        .expect("run");
    let j = json(&out);
    assert!(j[0]["value"]["b64"].is_string());

    // show renders binary as "<N bytes>" and masks by default
    v.cmd()
        .args(["show", "files/blob"])
        .assert()
        .success()
        .stdout(predicate::str::contains("<256 bytes>"));
    let out = v
        .cmd()
        .args(["--json", "show", "files/blob", "--reveal"])
        .output()
        .expect("run");
    let s = json(&out);
    assert!(s["fields"]["content"]["value"]["b64"].is_string());
    assert_eq!(s["fields"]["content"]["secret"], true);
    assert_eq!(s["fields"]["filename"]["secret"], false);

    // --clip refuses binary
    let out = v
        .cmd()
        .args(["get", "files/blob", "--clip"])
        .env("WCM_CLIP_DISABLE", "1")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn add_kind_file_from_stdin_keeps_trailing_newline() {
    let (v, _) = TestVault::initialized();
    add_stdin(&v, "f", "abc\n", &["--kind", "file"]);
    assert_eq!(get(&v, &["f", "--raw"]).stdout, b"abc\n");
    let out = v
        .cmd()
        .args(["--json", "ls", "--kind", "file"])
        .output()
        .expect("run");
    let j = json(&out);
    assert_eq!(j[0]["name"], "f");
    assert_eq!(j[0]["kind"], "file");
}

#[test]
fn add_openssh_key_is_auto_detected() {
    let (v, _) = TestVault::initialized();
    let pem = ed25519_pem("tester@wcm");
    let p = write_file(v.dir.path(), "id_ed25519", pem.as_bytes());
    let out = v
        .cmd()
        .args(["--json", "add", "ssh/test", "--file"])
        .arg(&p)
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    let j = json(&out);
    assert_eq!(j["kind"], "ssh-key");
    let fields = j["fields"].as_array().expect("fields");
    for f in ["private_key", "public_key", "fingerprint", "algorithm"] {
        assert!(fields.contains(&serde_json::json!(f)), "missing {f}");
    }
    let fp = stdout(&get(&v, &["ssh/test", "--field", "fingerprint", "--raw"]));
    assert!(fp.starts_with("SHA256:"), "{fp}");
    let pk = stdout(&get(&v, &["ssh/test", "--field", "public_key", "--raw"]));
    assert!(pk.starts_with("ssh-ed25519 AAAA"));
    assert!(pk.ends_with("tester@wcm"));
    assert_eq!(get(&v, &["ssh/test", "--raw"]).stdout, pem.as_bytes());
    assert_eq!(
        get(&v, &["ssh/test", "--field", "algorithm", "--raw"]).stdout,
        b"ssh-ed25519"
    );

    // via stdin too (strip one newline still leaves a valid key)
    let out = v
        .cmd()
        .args(["--json", "add", "ssh/two", "--stdin"])
        .write_stdin(pem.clone())
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(json(&out)["kind"], "ssh-key");

    // explicit --kind ssh-key with garbage → invalid
    v.cmd()
        .args(["add", "ssh/bad", "--kind", "ssh-key", "--value", "garbage"])
        .assert()
        .code(2);
}

#[test]
fn add_generate_prints_password() {
    let (v, _) = TestVault::initialized();
    let out = v
        .cmd()
        .args(["add", "gen/a", "--generate", "32"])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    let pw = stdout(&out);
    let pw = pw.trim_end_matches('\n');
    assert_eq!(pw.chars().count(), 32);
    assert_eq!(get(&v, &["gen/a", "--raw"]).stdout, pw.as_bytes());

    let out = v
        .cmd()
        .args(["--json", "add", "gen/b", "--generate", "--words", "4"])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    let j = json(&out);
    assert_eq!(j["generated"], true);
    let val = j["value"].as_str().expect("value");
    assert_eq!(val.split('-').count(), 4, "value: {val:?}");
    assert_eq!(get(&v, &["gen/b", "--raw"]).stdout, val.as_bytes());

    let out = v
        .cmd()
        .args(["add", "gen/c", "--generate", "--no-symbols"])
        .output()
        .expect("run");
    let pw = stdout(&out);
    let pw = pw.trim_end_matches('\n');
    assert_eq!(pw.len(), 24);
    assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));

    // invalid length → 2
    v.cmd()
        .args(["add", "gen/d", "--generate", "2"])
        .assert()
        .code(2);
}

// ---------------------------------------------------------------- set

#[test]
fn set_field_public_and_delete() {
    let (v, _) = TestVault::initialized();
    add_stdin(&v, "login", "pw1", &["--kind", "login"]);

    let out = v
        .cmd()
        .args([
            "--json", "set", "login", "username", "--value", "bob", "--public",
        ])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    let j = json(&out);
    assert_eq!(j["name"], "login");
    assert_eq!(j["field"], "username");
    assert_eq!(j["action"], "set");

    let out = v
        .cmd()
        .args(["--json", "show", "login"])
        .output()
        .expect("run");
    let s = json(&out);
    assert_eq!(s["fields"]["username"]["value"], "bob");
    assert_eq!(s["fields"]["username"]["secret"], false);
    assert_eq!(s["fields"]["password"]["value"], "•••");

    // secret update via stdin (newline stripped)
    let out = v
        .cmd()
        .args(["set", "login", "password", "--stdin"])
        .write_stdin("pw2\n")
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("Set login.password"));
    assert_eq!(get(&v, &["login", "--raw"]).stdout, b"pw2");

    // generate into a field
    let out = v
        .cmd()
        .args(["set", "login", "password", "--generate", "16"])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(get(&v, &["login", "--raw"]).stdout.len(), 16);

    // delete
    let out = v
        .cmd()
        .args(["--json", "set", "login", "username", "--delete"])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(json(&out)["action"], "deleted");
    assert_eq!(
        get(&v, &["login", "--field", "username"]).status.code(),
        Some(3)
    );
    // delete again → 3
    v.cmd()
        .args(["set", "login", "username", "--delete"])
        .assert()
        .code(3);
    // missing item → 3
    v.cmd()
        .args(["set", "nope", "password", "--value", "x"])
        .assert()
        .code(3);
    // invalid field name → 2
    v.cmd()
        .args(["set", "login", "bad name", "--value", "x"])
        .assert()
        .code(2);
    // prompt under --no-input → 7
    v.cmd().args(["set", "login", "password"]).assert().code(7);
}

#[test]
fn set_file_stores_bytes() {
    let (v, _) = TestVault::initialized();
    add_stdin(&v, "x", "pw", &[]);
    let p = write_file(v.dir.path(), "b.bin", &[0u8, 255, 1]);
    v.cmd()
        .args(["set", "x", "blob", "--file"])
        .arg(&p)
        .assert()
        .success();
    assert_eq!(
        get(&v, &["x", "--field", "blob", "--raw"]).stdout,
        [0u8, 255, 1]
    );
}

// ---------------------------------------------------------------- show

#[test]
fn show_masks_secrets_unless_reveal() {
    let (v, _) = TestVault::initialized();
    add_stdin(
        &v,
        "site",
        "s3cret",
        &[
            "--kind",
            "login",
            "--field",
            "username=alice",
            "--tag",
            "t1",
            "--notes",
            "hello",
        ],
    );
    let out = v
        .cmd()
        .args(["--json", "show", "site"])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    let s = json(&out);
    assert_eq!(s["name"], "site");
    assert_eq!(s["kind"], "login");
    assert_eq!(s["fields"]["password"]["value"], "•••");
    assert_eq!(s["fields"]["password"]["secret"], true);
    assert_eq!(s["fields"]["username"]["value"], "alice");
    assert_eq!(s["tags"], serde_json::json!(["t1"]));
    assert_eq!(s["notes"], "hello");
    assert!(s["id"].as_str().expect("id").len() == 32);
    assert!(s["created"].as_str().is_some());
    assert!(s["updated"].as_str().is_some());
    assert!(!stdout(&out).contains("s3cret"));

    let out = v
        .cmd()
        .args(["--json", "show", "site", "--reveal"])
        .output()
        .expect("run");
    assert_eq!(json(&out)["fields"]["password"]["value"], "s3cret");

    // human
    let out = v.cmd().args(["show", "site"]).output().expect("run");
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("username"));
    assert!(text.contains("alice"));
    assert!(text.contains("••••••"));
    assert!(!text.contains("s3cret"));
    let out = v
        .cmd()
        .args(["show", "site", "--reveal"])
        .output()
        .expect("run");
    assert!(stdout(&out).contains("s3cret"));

    v.cmd().args(["show", "nope"]).assert().code(3);
}

// ---------------------------------------------------------------- ls

#[test]
fn ls_filters_and_formats() {
    let (v, _) = TestVault::initialized();
    // empty → no output, exit 0
    let out = v.cmd().arg("ls").output().expect("run");
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    let out = v.cmd().args(["--json", "ls"]).output().expect("run");
    assert_eq!(json(&out), serde_json::json!([]));

    add_stdin(
        &v,
        "git/a",
        "1",
        &["--tag", "work", "--field", "username=u"],
    );
    add_stdin(&v, "git/b", "2", &["--kind", "token"]);
    add_stdin(&v, "other", "3", &["--tag", "home"]);

    let out = v.cmd().arg("ls").output().expect("run");
    assert_eq!(stdout(&out), "git/a\ngit/b\nother\n");
    assert_eq!(
        stdout(&v.cmd().args(["ls", "git/"]).output().expect("run")),
        "git/a\ngit/b\n"
    );
    assert_eq!(
        stdout(
            &v.cmd()
                .args(["ls", "--kind", "token"])
                .output()
                .expect("run")
        ),
        "git/b\n"
    );
    assert_eq!(
        stdout(&v.cmd().args(["ls", "--tag", "home"]).output().expect("run")),
        "other\n"
    );
    assert_eq!(
        stdout(
            &v.cmd()
                .args(["list", "git/", "--tag", "home"])
                .output()
                .expect("run")
        ),
        ""
    );

    // long format
    let out = v.cmd().args(["ls", "-l"]).output().expect("run");
    let text = stdout(&out);
    assert!(text.contains("git/a"));
    assert!(text.contains("password"));
    assert!(text.contains("token"));
    assert!(text.contains("work"));
    assert!(text.contains("20")); // updated timestamp year

    // json
    let out = v
        .cmd()
        .args(["--json", "ls", "git/"])
        .output()
        .expect("run");
    let j = json(&out);
    assert_eq!(j.as_array().expect("arr").len(), 2);
    assert_eq!(j[0]["name"], "git/a");
    assert_eq!(j[0]["kind"], "password");
    assert_eq!(j[0]["tags"], serde_json::json!(["work"]));
    assert_eq!(j[0]["fields"], serde_json::json!(["username"]));
    assert!(j[0]["created"].is_string());
    assert!(j[0]["updated"].is_string());
    assert_eq!(j[1]["fields"], serde_json::json!([]));
}

// ---------------------------------------------------------------- rm / mv

#[test]
fn rm_requires_force_without_input_and_removes_many() {
    let (v, _) = TestVault::initialized();
    add_stdin(&v, "a", "1", &[]);
    add_stdin(&v, "b", "2", &[]);
    add_stdin(&v, "c", "3", &[]);

    let out = v.cmd().args(["--json", "rm", "a"]).output().expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(json_err(&out)["error"]["code"], "INVALID_INPUT");
    assert!(stderr(&out).contains("-f"));
    // still there
    assert!(get(&v, &["a"]).status.success());

    // missing one → 3, nothing removed
    v.cmd().args(["rm", "-f", "a", "zzz"]).assert().code(3);
    assert!(get(&v, &["a"]).status.success());

    let out = v
        .cmd()
        .args(["--json", "rm", "-f", "a", "b"])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(json(&out)["removed"], serde_json::json!(["a", "b"]));
    assert_eq!(stdout(&v.cmd().arg("ls").output().expect("run")), "c\n");

    v.cmd()
        .args(["remove", "--force", "c"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Removed c"));
    assert_eq!(stdout(&v.cmd().arg("ls").output().expect("run")), "");
}

#[test]
fn mv_renames_and_handles_conflicts() {
    let (v, _) = TestVault::initialized();
    add_stdin(&v, "a", "va", &[]);
    add_stdin(&v, "b", "vb", &[]);

    let out = v
        .cmd()
        .args(["--json", "mv", "a", "c"])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    let j = json(&out);
    assert_eq!(j["old"], "a");
    assert_eq!(j["new"], "c");
    assert_eq!(get(&v, &["a"]).status.code(), Some(3));
    assert_eq!(get(&v, &["c", "--raw"]).stdout, b"va");

    // conflict
    let out = v
        .cmd()
        .args(["--json", "mv", "c", "b"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(json_err(&out)["error"]["code"], "ALREADY_EXISTS");
    assert_eq!(get(&v, &["b", "--raw"]).stdout, b"vb");

    // -f overwrites
    v.cmd()
        .args(["mv", "c", "b", "-f"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Renamed c -> b"));
    assert_eq!(get(&v, &["b", "--raw"]).stdout, b"va");
    assert_eq!(stdout(&v.cmd().arg("ls").output().expect("run")), "b\n");

    // missing / invalid
    v.cmd().args(["rename", "nope", "x"]).assert().code(3);
    v.cmd().args(["mv", "b", "a//b"]).assert().code(2);
}

// ---------------------------------------------------------------- generate

#[test]
fn generate_without_vault() {
    let v = TestVault::new();
    let out = v.cmd().arg("generate").output().expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim_end_matches('\n').len(), 24);

    let out = v
        .cmd()
        .args(["gen", "40", "--no-symbols"])
        .output()
        .expect("run");
    let pw = stdout(&out);
    let pw = pw.trim_end_matches('\n');
    assert_eq!(pw.len(), 40);
    assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));

    let out = v
        .cmd()
        .args(["--json", "generate", "--words", "3", "--sep", " "])
        .output()
        .expect("run");
    let j = json(&out);
    let val = j["value"].as_str().expect("value");
    assert_eq!(val.split(' ').count(), 3);
    assert_eq!(
        j["length"].as_u64().expect("len") as usize,
        val.chars().count()
    );

    let out = v
        .cmd()
        .args(["--json", "generate", "12"])
        .output()
        .expect("run");
    let j = json(&out);
    assert_eq!(j["length"], 12);
    assert_eq!(j["value"].as_str().expect("v").len(), 12);

    v.cmd().args(["generate", "1"]).assert().code(2);
    v.cmd().args(["generate", "--words", "0"]).assert().code(2);
}

// ---------------------------------------------------------------- clip / unclip

#[test]
fn clip_disabled_env_is_helper_error() {
    let (v, _) = TestVault::initialized();
    add_stdin(&v, "a", "va", &[]);
    for args in [
        vec!["get", "a", "--clip"],
        vec!["generate", "--clip"],
        vec!["add", "b", "--generate", "--clip"],
    ] {
        let out = v
            .cmd()
            .arg("--json")
            .args(&args)
            .env("WCM_CLIP_DISABLE", "1")
            .output()
            .expect("run");
        assert_eq!(out.status.code(), Some(11), "{args:?}: {}", stderr(&out));
        let e = json_err(&out);
        assert_eq!(e["error"]["code"], "HELPER");
        assert!(e["error"]["message"]
            .as_str()
            .expect("msg")
            .contains("WCM_CLIP_DISABLE"));
        assert!(out.stdout.is_empty(), "{args:?} leaked to stdout");
    }
    // `add --generate --clip`: the item is saved before the clipboard step, so it exists
    assert!(get(&v, &["b"]).status.success());
}

#[test]
fn unclip_always_succeeds() {
    let v = TestVault::new();
    v.cmd()
        .args(["unclip", "--timeout", "0", "--hash", "deadbeef"])
        .assert()
        .success();
}
