//! `wcm recover` — TODO(agent): implement per docs/superpowers/plans/2026-08-19-wcm-v1.md

use wcm_core::{Error, Result};

use crate::cli::RecoverArgs;
use crate::context::Ctx;

pub fn run(_ctx: &Ctx, _args: &RecoverArgs) -> Result<()> {
    Err(Error::Other("`wcm recover` is not implemented yet".into()))
}
