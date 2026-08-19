//! `wcm get` — TODO(agent): implement per docs/superpowers/plans/2026-08-19-wcm-v1.md

use wcm_core::{Error, Result};

use crate::cli::GetArgs;
use crate::context::Ctx;

pub fn run(_ctx: &Ctx, _args: &GetArgs) -> Result<()> {
    Err(Error::Other("`wcm get` is not implemented yet".into()))
}
