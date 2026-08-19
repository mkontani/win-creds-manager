//! `wcm mv` — TODO(agent): implement per docs/superpowers/plans/2026-08-19-wcm-v1.md

use wcm_core::{Error, Result};

use crate::cli::MvArgs;
use crate::context::Ctx;

pub fn run(_ctx: &Ctx, _args: &MvArgs) -> Result<()> {
    Err(Error::Other("`wcm mv` is not implemented yet".into()))
}
