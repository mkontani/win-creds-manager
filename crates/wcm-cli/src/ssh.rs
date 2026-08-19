//! `ssh-add` integration helpers.
//!
//! Keys are handed to `ssh-add -` through a pipe: the private key never touches
//! the file system and never goes through a shell.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use wcm_core::{Error, Result};
use zeroize::Zeroizing;

/// Locates `ssh-add` (explicit path, then PATH, then the Windows OpenSSH default).
pub fn find_ssh_add(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    let name = if cfg!(windows) {
        "ssh-add.exe"
    } else {
        "ssh-add"
    };
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let cand = dir.join(name);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    if cfg!(windows) {
        let p = PathBuf::from(r"C:\Windows\System32\OpenSSH\ssh-add.exe");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Loads a private key into the agent: `ssh-add [extra_args] -` with the key on stdin.
///
/// OpenSSH requires the PEM to be newline-terminated, so one `\n` is appended
/// when missing. `ssh-add`'s stderr is captured and included in
/// [`Error::Helper`] on failure; on success it is forwarded to our stderr
/// (it carries the "Identity added" confirmation).
pub fn ssh_add_stdin(ssh_add: &Path, extra_args: &[String], key_bytes: &[u8]) -> Result<()> {
    let input = with_trailing_newline(key_bytes);
    let mut args: Vec<String> = extra_args.to_vec();
    args.push("-".to_string());
    run_ssh_add(ssh_add, &args, &input)
}

/// Removes a key from the agent: `ssh-add -d -` with the public key line on stdin.
pub fn ssh_add_remove(ssh_add: &Path, pubkey_line: &str) -> Result<()> {
    let input = with_trailing_newline(pubkey_line.as_bytes());
    run_ssh_add(ssh_add, &["-d".to_string(), "-".to_string()], &input)
}

/// `bytes` plus exactly one trailing newline.
///
/// OpenSSH needs the PEM (and the `authorized_keys` line) newline-terminated;
/// `--stdin` strips one newline on input and `get --raw` writes none, so it has
/// to be put back here. Also used by the WSL shim ([`crate::wsl`]).
pub fn with_trailing_newline(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::with_capacity(bytes.len() + 1));
    v.extend_from_slice(bytes);
    if !v.ends_with(b"\n") {
        v.push(b'\n');
    }
    v
}

/// Spawns `ssh_add args...` (no shell), feeds `stdin_bytes`, waits.
fn run_ssh_add(ssh_add: &Path, args: &[String], stdin_bytes: &[u8]) -> Result<()> {
    let mut cmd = Command::new(ssh_add);
    crate::prompt::scrub_secret_env(&mut cmd);
    let mut child = cmd
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Helper(format!("cannot run {}: {e}", ssh_add.display())))?;

    // Write the key, then close stdin so ssh-add sees EOF. A write error
    // (e.g. EPIPE when ssh-add exits early) is reported only if the exit
    // status does not already explain the failure.
    let write_result = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(stdin_bytes).and_then(|_| stdin.flush()),
        None => Err(std::io::Error::other("stdin pipe unavailable")),
    };

    let output = child
        .wait_with_output()
        .map_err(|e| Error::Helper(format!("waiting for {}: {e}", ssh_add.display())))?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        let detail = if stderr.is_empty() {
            "no error output".to_string()
        } else {
            stderr
        };
        return Err(Error::Helper(format!(
            "{} exited with {}: {detail}",
            ssh_add.display(),
            describe_status(&output.status)
        )));
    }
    write_result.map_err(|e| {
        Error::Helper(format!(
            "writing to {} stdin failed: {e}",
            ssh_add.display()
        ))
    })?;
    // ssh-add reports "Identity added: ..." on stderr; pass it on.
    if !stderr.is_empty() {
        eprintln!("{stderr}");
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stdout.is_empty() {
        eprintln!("{stdout}");
    }
    Ok(())
}

fn describe_status(status: &std::process::ExitStatus) -> String {
    match status.code() {
        Some(c) => format!("status {c}"),
        None => "a signal".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_newline_added_once() {
        assert_eq!(&*with_trailing_newline(b"abc"), b"abc\n");
        assert_eq!(&*with_trailing_newline(b"abc\n"), b"abc\n");
        assert_eq!(&*with_trailing_newline(b""), b"\n");
    }

    #[test]
    fn explicit_path_wins() {
        let p = Path::new("/x/ssh-add");
        assert_eq!(find_ssh_add(Some(p)), Some(p.to_path_buf()));
    }

    #[test]
    fn nonexistent_binary_is_helper_error() {
        let err =
            ssh_add_stdin(Path::new("/nonexistent/ssh-add"), &[], b"key").expect_err("must fail");
        assert!(matches!(err, Error::Helper(_)), "{err:?}");
        let err = ssh_add_remove(Path::new("/nonexistent/ssh-add"), "ssh-ed25519 AAAA")
            .expect_err("must fail");
        assert!(matches!(err, Error::Helper(_)), "{err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn failing_helper_reports_stderr_and_status() {
        let dir = tempfile::tempdir().expect("tmp");
        let script = dir.path().join("fake");
        std::fs::write(
            &script,
            "#!/bin/sh\ncat >/dev/null\necho nope >&2\nexit 3\n",
        )
        .expect("write");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let err =
            ssh_add_stdin(&script, &["-t".into(), "1h".into()], b"key").expect_err("must fail");
        match err {
            Error::Helper(m) => {
                assert!(m.contains("nope"), "{m}");
                assert!(m.contains("status 3"), "{m}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn successful_helper_receives_input() {
        let dir = tempfile::tempdir().expect("tmp");
        let script = dir.path().join("fake");
        let out = dir.path().join("in.bin");
        std::fs::write(
            &script,
            format!("#!/bin/sh\ncat > '{}'\necho added >&2\n", out.display()),
        )
        .expect("write");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        ssh_add_remove(&script, "ssh-ed25519 AAAA c").expect("ok");
        assert_eq!(
            std::fs::read(&out).expect("read"),
            b"ssh-ed25519 AAAA c\n".to_vec()
        );
    }
}
