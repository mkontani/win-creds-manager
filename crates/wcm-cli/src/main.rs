//! `wcm` — Windows Hello protected credential manager CLI.

mod cli;
mod clip;
mod commands;
mod context;
mod output;
mod prompt;
mod secrets;
mod ssh;
#[cfg(target_os = "linux")]
mod wsl;

use std::process::ExitCode;

use clap::Parser;
use wcm_core::Error;

use crate::cli::Cli;
use crate::context::Ctx;
use crate::output::Output;

fn main() -> ExitCode {
    // On WSL, hand the whole invocation to wcm.exe (Windows Hello lives there).
    #[cfg(target_os = "linux")]
    if let Some(code) = wsl::maybe_proxy() {
        return ExitCode::from(code);
    }

    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // clap prints its own message; --help/--version exit 0, usage errors exit 2.
            let _ = e.print();
            return ExitCode::from(if e.use_stderr() { 2 } else { 0 });
        }
    };

    let out = Output {
        json: cli.json,
        quiet: cli.quiet,
    };
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            out.error(&e);
            ExitCode::from(e.exit_code())
        }
    }
}

fn run(cli: &Cli) -> Result<(), Error> {
    if cli.exit_codes {
        return commands::exit_codes(&Output {
            json: cli.json,
            quiet: cli.quiet,
        });
    }
    let Some(command) = &cli.command else {
        return Err(Error::Invalid("no command given; try `wcm --help`".into()));
    };
    let ctx = Ctx::from_cli(cli)?;
    commands::dispatch(&ctx, command)
}
