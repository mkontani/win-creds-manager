//! `wcm ls` — TODO(agent): implement per docs/superpowers/plans/2026-08-19-wcm-v1.md

use wcm_core::{Error, Result};

use crate::cli::LsArgs;
use crate::context::Ctx;

pub fn run(_ctx: &Ctx, _args: &LsArgs) -> Result<()> {
    Err(Error::Other("`wcm ls` is not implemented yet".into()))
}
