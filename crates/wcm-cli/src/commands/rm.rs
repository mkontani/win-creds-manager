//! `wcm rm` — TODO(agent): implement per docs/superpowers/plans/2026-08-19-wcm-v1.md

use wcm_core::{Error, Result};

use crate::cli::RmArgs;
use crate::context::Ctx;

pub fn run(_ctx: &Ctx, _args: &RmArgs) -> Result<()> {
    Err(Error::Other("`wcm rm` is not implemented yet".into()))
}
