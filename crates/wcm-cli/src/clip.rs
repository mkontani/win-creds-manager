//! Clipboard helpers: copy text with arboard and schedule a detached
//! `wcm unclip --timeout N --hash H` that clears it again if it is still there.

use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};
use wcm_core::{Error, Result};

use crate::output::Output;

/// Environment variable that disables clipboard access entirely (tests / CI).
pub const DISABLE_ENV: &str = "WCM_CLIP_DISABLE";

/// Default seconds before the clipboard is cleared.
pub const DEFAULT_TIMEOUT_SECS: u64 = 45;

/// Environment variable overriding the clipboard timeout (also the clap default
/// for `--clip-timeout`; commands without that flag read it here).
pub const TIMEOUT_ENV: &str = "WCM_CLIP_TIME";

/// [`TIMEOUT_ENV`] when it holds a number, else [`DEFAULT_TIMEOUT_SECS`].
pub fn timeout_from_env() -> u64 {
    std::env::var(TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
}

/// Hex SHA-256 of `text` (used to recognise our own clipboard content later).
pub fn sha256_hex(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether the clipboard is disabled via [`DISABLE_ENV`].
pub fn disabled() -> bool {
    std::env::var(DISABLE_ENV).is_ok_and(|v| v == "1")
}

/// Copies `text` to the system clipboard and spawns `wcm unclip` to clear it
/// after `timeout_secs` (only if the clipboard still holds the same text).
pub fn copy_with_timeout(text: &str, timeout_secs: u64) -> Result<()> {
    if disabled() {
        return Err(Error::Helper(format!(
            "clipboard disabled by {DISABLE_ENV}"
        )));
    }
    set_clipboard_text(text)?;
    spawn_unclip(timeout_secs, &sha256_hex(text))
}

/// [`copy_with_timeout`] followed by the standard "copied" notice.
pub fn copy_and_notify(out: &Output, text: &str, timeout_secs: u64) -> Result<()> {
    copy_with_timeout(text, timeout_secs)?;
    out.notice(&format!("copied to clipboard (clears in {timeout_secs}s)"));
    Ok(())
}

/// Reads the clipboard text; `None` when unavailable or not text.
pub fn read_text() -> Option<String> {
    arboard::Clipboard::new().ok()?.get_text().ok()
}

/// Clears the clipboard (errors ignored: best effort).
pub fn clear() {
    if let Ok(mut cb) = arboard::Clipboard::new() {
        let _ = cb.clear();
    }
}

fn set_clipboard_text(text: &str) -> Result<()> {
    let mut cb = arboard::Clipboard::new()
        .map_err(|e| Error::Helper(format!("clipboard unavailable: {e}")))?;
    let set = cb.set();
    #[cfg(windows)]
    let set = {
        use arboard::SetExtWindows;
        set.exclude_from_monitoring()
    };
    set.text(text)
        .map_err(|e| Error::Helper(format!("clipboard write failed: {e}")))
}

fn spawn_unclip(timeout_secs: u64, hash: &str) -> Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::Helper(format!("cannot locate own executable: {e}")))?;
    let mut cmd = Command::new(exe);
    crate::prompt::scrub_secret_env(&mut cmd);
    cmd.args([
        "unclip",
        "--timeout",
        &timeout_secs.to_string(),
        "--hash",
        hash,
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    cmd.spawn()
        .map(|_| ())
        .map_err(|e| Error::Helper(format!("cannot start `wcm unclip`: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_stable() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_hex("").len(), 64);
        assert_ne!(sha256_hex("a"), sha256_hex("b"));
    }

    #[test]
    fn timeout_env_is_parsed_with_a_fallback() {
        // No other unit test in this crate touches WCM_CLIP_TIME.
        assert_eq!(timeout_from_env(), DEFAULT_TIMEOUT_SECS);
        std::env::set_var(TIMEOUT_ENV, " 7 ");
        assert_eq!(timeout_from_env(), 7);
        std::env::set_var(TIMEOUT_ENV, "not-a-number");
        assert_eq!(timeout_from_env(), DEFAULT_TIMEOUT_SECS);
        std::env::remove_var(TIMEOUT_ENV);
    }

    #[test]
    fn disabled_env_short_circuits() {
        // Other unit tests in this crate do not touch this variable.
        std::env::set_var(DISABLE_ENV, "1");
        assert!(disabled());
        let r = copy_with_timeout("secret", 1);
        assert!(matches!(r, Err(Error::Helper(m)) if m.contains(DISABLE_ENV)));
        std::env::remove_var(DISABLE_ENV);
    }
}
