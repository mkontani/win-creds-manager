//! Clipboard helpers (arboard) — TODO(agent): implement copy + detached `wcm unclip`.

use wcm_core::{Error, Result};

/// Copies `text` to the system clipboard and schedules `wcm unclip` after `timeout_secs`.
pub fn copy_with_timeout(_text: &str, _timeout_secs: u64) -> Result<()> {
    Err(Error::Helper(
        "clipboard support not implemented yet".into(),
    ))
}
