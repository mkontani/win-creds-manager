//! Subcommand implementations. Each module exposes `run(ctx, args) -> Result<()>`.

pub mod add;
pub mod completions;
pub mod doctor;
pub mod export;
pub mod generate;
pub mod get;
pub mod import;
pub mod init;
pub mod ls;
pub mod mv;
pub mod recover;
pub mod rekey;
pub mod rm;
pub mod run;
pub mod set;
pub mod show;
pub mod slot;
pub mod ssh;
pub mod status;
pub mod unclip;

use serde::Serialize;
use wcm_core::{Error, Result};

use crate::cli::Command;
use crate::context::Ctx;
use crate::output::Output;

/// Routes a parsed command to its implementation.
pub fn dispatch(ctx: &Ctx, command: &Command) -> Result<()> {
    match command {
        Command::Init(a) => init::run(ctx, a),
        Command::Add(a) => add::run(ctx, a),
        Command::Set(a) => set::run(ctx, a),
        Command::Get(a) => get::run(ctx, a),
        Command::Show(a) => show::run(ctx, a),
        Command::Ls(a) => ls::run(ctx, a),
        Command::Rm(a) => rm::run(ctx, a),
        Command::Mv(a) => mv::run(ctx, a),
        Command::Generate(a) => generate::run(ctx, a),
        Command::Ssh(a) => ssh::run(ctx, a),
        Command::Run(a) => run::run(ctx, a),
        Command::Export(a) => export::run(ctx, a),
        Command::Import(a) => import::run(ctx, a),
        Command::Recover(a) => recover::run(ctx, a),
        Command::Rekey(a) => rekey::run(ctx, a),
        Command::Slot(a) => slot::run(ctx, a),
        Command::Status(a) => status::run(ctx, a),
        Command::Doctor(a) => doctor::run(ctx, a),
        Command::Unclip(a) => unclip::run(ctx, a),
        Command::Completions(a) => completions::run(ctx, a),
        Command::Version => version(&ctx.out),
    }
}

#[derive(Serialize)]
struct VersionInfo {
    name: &'static str,
    version: &'static str,
    target_os: &'static str,
    hello_compiled_in: bool,
}

/// `wcm version`
pub fn version(out: &Output) -> Result<()> {
    let v = VersionInfo {
        name: "wcm",
        version: env!("CARGO_PKG_VERSION"),
        target_os: std::env::consts::OS,
        hello_compiled_in: cfg!(windows),
    };
    if out.json {
        return out.json(&v);
    }
    out.line(&format!(
        "wcm {} ({}, hello={})",
        v.version, v.target_os, v.hello_compiled_in
    ))
}

#[derive(Serialize)]
struct ExitCodeRow {
    code: &'static str,
    exit: u8,
    description: &'static str,
}

/// `wcm --exit-codes`
pub fn exit_codes(out: &Output) -> Result<()> {
    let rows: Vec<ExitCodeRow> = Error::table()
        .into_iter()
        .map(|(code, exit, description)| ExitCodeRow {
            code,
            exit,
            description,
        })
        .collect();
    if out.json {
        return out.json(&rows);
    }
    for r in rows {
        out.line(&format!("{:>3}  {:<20} {}", r.exit, r.code, r.description))?;
    }
    Ok(())
}
