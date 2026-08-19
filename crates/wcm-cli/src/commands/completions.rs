//! `wcm completions <shell>`

use clap::CommandFactory;
use wcm_core::Result;

use crate::cli::{Cli, CompletionsArgs};
use crate::context::Ctx;

pub fn run(_ctx: &Ctx, args: &CompletionsArgs) -> Result<()> {
    let mut cmd = Cli::command();
    clap_complete::generate(args.shell, &mut cmd, "wcm", &mut std::io::stdout());
    Ok(())
}
