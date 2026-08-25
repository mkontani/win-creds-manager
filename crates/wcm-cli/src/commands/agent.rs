//! `wcm agent start|stop|lock|status` — the session cache agent.
//!
//! `start` detaches a `wcm agent start --foreground …` child (unless
//! `--foreground`) and waits until it answers. The agent itself lives in the
//! `wcm_agent` crate; this module only wires it to the CLI.

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use wcm_agent::duration::{format_duration, parse_duration};
use wcm_agent::endpoint::{resolve_endpoint, AgentState, StateFile};
use wcm_agent::{Cache, Client, EntryInfo, Policy, PolicyInfo, Server, ServerOptions};
use wcm_core::{Error, Result};

use crate::cli::{AgentArgs, AgentCommand, AgentStartArgs};
use crate::context::{default_data_dir, Ctx};

/// How long `agent start` waits for the detached child to answer.
const START_TIMEOUT: Duration = Duration::from_secs(3);
const START_POLL: Duration = Duration::from_millis(50);

pub fn run(ctx: &Ctx, args: &AgentArgs) -> Result<()> {
    match &args.command {
        AgentCommand::Start(a) => start(ctx, a),
        AgentCommand::Stop => stop(ctx),
        AgentCommand::Lock => lock(ctx),
        AgentCommand::Status => status(ctx),
    }
}

/// Policy from `--idle/--ttl/--max-uses`, validated before anything starts.
pub fn policy_from_args(args: &AgentStartArgs) -> Result<Policy> {
    let idle = parse_duration(&args.idle)?;
    let ttl = parse_duration(&args.ttl)?;
    if args.max_uses == Some(0) {
        return Err(Error::Invalid("--max-uses must be at least 1".into()));
    }
    Ok(Policy {
        idle,
        ttl,
        max_uses: args.max_uses,
    })
}

/// A running agent as seen by this process.
struct Running {
    pid: Option<u32>,
    endpoint: String,
}

/// The running agent, if one answers.
fn running(data_dir: &Path) -> Option<Running> {
    let client = Client::discover(data_dir)?;
    let pid = StateFile::in_dir(data_dir).read().map(|s| s.pid);
    Some(Running {
        pid,
        endpoint: client.endpoint().to_string(),
    })
}

#[derive(Serialize)]
struct StartReport {
    started: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    endpoint: String,
    idle_secs: u64,
    ttl_secs: u64,
    max_uses: Option<u32>,
}

fn start(ctx: &Ctx, args: &AgentStartArgs) -> Result<()> {
    let policy = policy_from_args(args)?;
    let data_dir = default_data_dir()?;
    if let Some(agent) = running(&data_dir) {
        return report_already_running(ctx, &agent, policy);
    }
    if args.foreground {
        return match serve(&data_dir, policy) {
            // Lost a race with another `start`: behave like "already running".
            Err(Error::AlreadyExists(_)) => match running(&data_dir) {
                Some(agent) => report_already_running(ctx, &agent, policy),
                None => Ok(()),
            },
            other => other,
        };
    }
    let pid = spawn_detached(args)?;
    let deadline = Instant::now() + START_TIMEOUT;
    let agent = loop {
        if let Some(agent) = running(&data_dir) {
            break agent;
        }
        if Instant::now() >= deadline {
            return Err(Error::Helper(format!(
                "agent (pid {pid}) did not answer within {}s",
                START_TIMEOUT.as_secs()
            )));
        }
        std::thread::sleep(START_POLL);
    };
    let report = StartReport {
        started: true,
        pid: agent.pid.or(Some(pid)),
        endpoint: agent.endpoint,
        idle_secs: policy.idle.as_secs(),
        ttl_secs: policy.ttl.as_secs(),
        max_uses: policy.max_uses,
    };
    if ctx.out.json {
        return ctx.out.json(&report);
    }
    ctx.out.line(&format!(
        "agent started (pid {}, idle {}, ttl {}{})",
        report.pid.unwrap_or(pid),
        format_duration(policy.idle),
        format_duration(policy.ttl),
        policy
            .max_uses
            .map(|n| format!(", max uses {n}"))
            .unwrap_or_default()
    ))
}

fn report_already_running(ctx: &Ctx, agent: &Running, requested: Policy) -> Result<()> {
    if ctx.out.json {
        return ctx.out.json(&StartReport {
            started: false,
            pid: agent.pid,
            endpoint: agent.endpoint.clone(),
            idle_secs: requested.idle.as_secs(),
            ttl_secs: requested.ttl.as_secs(),
            max_uses: requested.max_uses,
        });
    }
    ctx.out.notice(&format!(
        "agent already running{}; use `wcm agent stop` to change its policy",
        agent.pid.map(|p| format!(" (pid {p})")).unwrap_or_default()
    ));
    Ok(())
}

/// Runs the agent in this process until `wcm agent stop`.
fn serve(data_dir: &Path, policy: Policy) -> Result<()> {
    let endpoint = resolve_endpoint(data_dir)?;
    let server = Server::bind(
        endpoint,
        &ServerOptions {
            owner_sid: wcm_hello::session::current_user_sid(),
        },
    )?;
    let state_file = StateFile::in_dir(data_dir);
    state_file.write(&AgentState {
        endpoint: server.endpoint().to_string(),
        pid: std::process::id(),
        started: wcm_core::vault::now_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })?;
    let cache = Arc::new(Mutex::new(Cache::new(policy)));
    let result = server.serve(cache);
    let _ = state_file.remove();
    result
}

/// Starts `wcm agent start --foreground …` detached from this console/terminal.
fn spawn_detached(args: &AgentStartArgs) -> Result<u32> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::Helper(format!("agent: cannot locate the wcm executable: {e}")))?;
    let mut cmd = Command::new(exe);
    cmd.arg("agent")
        .arg("start")
        .arg("--foreground")
        .arg("--idle")
        .arg(&args.idle)
        .arg("--ttl")
        .arg(&args.ttl);
    if let Some(n) = args.max_uses {
        cmd.arg("--max-uses").arg(n.to_string());
    }
    // The child must not hold our stdio: under WSL interop the Linux shim
    // waits for those pipes to close before it returns.
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    crate::prompt::scrub_secret_env(&mut cmd);
    detach(&mut cmd);
    let child = cmd
        .spawn()
        .map_err(|e| Error::Helper(format!("agent: spawn: {e}")))?;
    Ok(child.id())
}

#[cfg(windows)]
fn detach(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
}

#[cfg(unix)]
fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
}

#[derive(Serialize)]
struct ActionReport {
    action: &'static str,
    was_running: bool,
}

fn stop(ctx: &Ctx) -> Result<()> {
    let data_dir = default_data_dir()?;
    let was_running = match Client::discover(&data_dir) {
        Some(client) => {
            client.stop()?;
            let _ = StateFile::in_dir(&data_dir).remove();
            true
        }
        None => false,
    };
    finish(ctx, "stop", was_running, "agent stopped")
}

fn lock(ctx: &Ctx) -> Result<()> {
    let data_dir = default_data_dir()?;
    let was_running = match Client::discover(&data_dir) {
        Some(client) => {
            client.lock_all()?;
            true
        }
        None => false,
    };
    finish(
        ctx,
        "lock",
        was_running,
        "agent locked (cached keys forgotten)",
    )
}

fn finish(ctx: &Ctx, action: &'static str, was_running: bool, done: &str) -> Result<()> {
    if ctx.out.json {
        return ctx.out.json(&ActionReport {
            action,
            was_running,
        });
    }
    ctx.out.notice(if was_running {
        done
    } else {
        "agent is not running"
    });
    Ok(())
}

/// Snapshot for `agent status`, `status` and `doctor` (never fails: an
/// unreachable agent is reported as not running).
#[derive(Serialize, Default)]
pub struct AgentStatusReport {
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyInfo>,
    pub entries: Vec<EntryInfo>,
}

pub fn agent_status() -> AgentStatusReport {
    let Ok(data_dir) = default_data_dir() else {
        return AgentStatusReport::default();
    };
    let Some(client) = Client::discover(&data_dir) else {
        return AgentStatusReport::default();
    };
    let Ok((policy, entries)) = client.status() else {
        return AgentStatusReport::default();
    };
    AgentStatusReport {
        running: true,
        pid: StateFile::in_dir(&data_dir).read().map(|s| s.pid),
        endpoint: Some(client.endpoint().to_string()),
        policy: Some(policy),
        entries,
    }
}

/// The agent as it concerns one vault (for `wcm status`).
#[derive(Serialize)]
pub struct AgentSummary {
    pub running: bool,
    pub cached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uses: Option<u32>,
}

pub fn agent_summary(vault_id_hex: &str) -> AgentSummary {
    let report = agent_status();
    let entry = report
        .entries
        .iter()
        .find(|e| e.vault_id_hex == vault_id_hex);
    AgentSummary {
        running: report.running,
        cached: entry.is_some(),
        expires_in_secs: entry.map(|e| e.expires_in_secs),
        uses: entry.map(|e| e.uses),
    }
}

impl AgentSummary {
    /// One-line human form.
    pub fn describe(&self) -> String {
        if !self.running {
            return "not running".into();
        }
        match (self.expires_in_secs, self.uses) {
            (Some(secs), Some(uses)) => format!(
                "running, cached for this vault (expires in {}, {uses} uses)",
                format_duration(Duration::from_secs(secs))
            ),
            _ => "running, not cached for this vault".into(),
        }
    }
}

fn status(ctx: &Ctx) -> Result<()> {
    let report = agent_status();
    if ctx.out.json {
        return ctx.out.json(&report);
    }
    if !report.running {
        return ctx.out.line("agent:    not running");
    }
    ctx.out.line(&format!(
        "agent:    running{}",
        report
            .pid
            .map(|p| format!(" (pid {p})"))
            .unwrap_or_default()
    ))?;
    ctx.out.line(&format!(
        "endpoint: {}",
        report.endpoint.as_deref().unwrap_or("?")
    ))?;
    if let Some(p) = &report.policy {
        ctx.out.line(&format!(
            "policy:   idle {}, ttl {}, max uses {}",
            format_duration(Duration::from_secs(p.idle_secs)),
            format_duration(Duration::from_secs(p.ttl_secs)),
            p.max_uses
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unlimited".into())
        ))?;
    }
    ctx.out
        .line(&format!("cached:   {} vault(s)", report.entries.len()))?;
    for e in &report.entries {
        let short: String = e.vault_id_hex.chars().take(8).collect();
        ctx.out.line(&format!(
            "  {short}  {}  age {}  idle {}  uses {}  expires in {}",
            e.path,
            format_duration(Duration::from_secs(e.age_secs)),
            format_duration(Duration::from_secs(e.idle_secs)),
            e.uses,
            format_duration(Duration::from_secs(e.expires_in_secs))
        ))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(idle: &str, ttl: &str, max_uses: Option<u32>) -> AgentStartArgs {
        AgentStartArgs {
            idle: idle.into(),
            ttl: ttl.into(),
            max_uses,
            foreground: false,
        }
    }

    #[test]
    fn policy_from_args_validates_everything() {
        let p = policy_from_args(&args("5m", "2h", Some(3))).expect("policy");
        assert_eq!(p.idle, Duration::from_secs(300));
        assert_eq!(p.ttl, Duration::from_secs(7200));
        assert_eq!(p.max_uses, Some(3));
        assert!(matches!(
            policy_from_args(&args("0", "1h", None)),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            policy_from_args(&args("1m", "x", None)),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            policy_from_args(&args("1m", "1h", Some(0))),
            Err(Error::Invalid(_))
        ));
    }
}
