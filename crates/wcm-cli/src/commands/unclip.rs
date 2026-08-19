//! `wcm unclip` — TODO(agent): implement per docs/superpowers/plans/2026-08-19-wcm-v1.md

use wcm_core::{Error, Result};

use crate::cli::UnclipArgs;
use crate::context::Ctx;

pub fn run(_ctx: &Ctx, _args: &UnclipArgs) -> Result<()> {
    Err(Error::Other("`wcm unclip` is not implemented yet".into()))
}
