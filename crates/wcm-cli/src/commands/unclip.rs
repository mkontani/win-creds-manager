//! `wcm unclip` (internal) — wait, then clear the clipboard if it still holds
//! the text we copied earlier (identified by its SHA-256). Never fails.

use std::time::Duration;

use wcm_core::Result;

use crate::cli::UnclipArgs;
use crate::clip;
use crate::context::Ctx;

pub fn run(_ctx: &Ctx, args: &UnclipArgs) -> Result<()> {
    std::thread::sleep(Duration::from_secs(args.timeout));
    if should_clear(clip::read_text().as_deref(), &args.hash) {
        clip::clear();
    }
    Ok(())
}

/// Whether the clipboard text (if any) is the one we copied.
fn should_clear(current: Option<&str>, expected_hash: &str) -> bool {
    current.is_some_and(|t| clip::sha256_hex(t) == expected_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_only_matching_content() {
        let h = clip::sha256_hex("secret");
        assert!(should_clear(Some("secret"), &h));
        assert!(!should_clear(Some("other"), &h));
        assert!(!should_clear(None, &h));
    }
}
