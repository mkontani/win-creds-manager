//! `wcm doctor` — environment diagnostics (no unlock unless `--hello-selftest`).

use serde::Serialize;
use wcm_core::slot::{Availability, SlotParams};
use wcm_core::Result;

use crate::cli::DoctorArgs;
use crate::context::Ctx;

#[derive(Serialize)]
struct DoctorReport {
    version: &'static str,
    os: &'static str,
    arch: &'static str,
    exe: Option<String>,
    vault: String,
    vault_exists: bool,
    vault_generation: Option<u64>,
    vault_slots: Vec<String>,
    hello: wcm_hello::HelloInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    hello_selftest: Option<SelfTest>,
    wsl: WslReport,
    ssh_add: Option<String>,
    agent: crate::commands::agent::AgentStatusReport,
    passphrase_env_set: bool,
    problems: Vec<String>,
}

#[derive(Serialize)]
struct SelfTest {
    ok: bool,
    hw_backed: Option<bool>,
    message: String,
}

#[derive(Serialize, Default)]
struct WslReport {
    detected: bool,
    kind: Option<String>,
    windows_exe: Option<String>,
}

pub fn run(ctx: &Ctx, args: &DoctorArgs) -> Result<()> {
    let mut problems = Vec::new();
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string());
    let (vault_generation, vault_slots) = match ctx.vault.read_header() {
        Ok(h) => (
            Some(h.generation),
            h.slots
                .iter()
                .map(|s| format!("{} ({})", s.label, s.kind().as_str()))
                .collect(),
        ),
        Err(wcm_core::Error::NotInitialized(_)) => (None, Vec::new()),
        Err(e) => {
            problems.push(format!("vault header unreadable: {e}"));
            (None, Vec::new())
        }
    };
    let hello = wcm_hello::info();
    if cfg!(windows) && !hello.interactive {
        problems.push(
            "not running in an interactive Windows session; Windows Hello cannot prompt".into(),
        );
    }
    if cfg!(windows) && hello.supported == Some(false) {
        problems.push(
            "Windows Hello is not set up (add a PIN in Settings > Accounts > Sign-in options)"
                .into(),
        );
    }
    let wsl = wsl_report();
    let ssh_add = crate::ssh::find_ssh_add(None).map(|p| p.display().to_string());
    if ssh_add.is_none() {
        problems.push("ssh-add not found on PATH (`wcm ssh add` will not work)".into());
    }
    let agent = crate::commands::agent::agent_status();
    let passphrase_env_set = std::env::var_os(crate::prompt::PASSPHRASE_ENV).is_some();
    if passphrase_env_set {
        problems.push(format!(
            "{} is set: passphrase prompts are bypassed",
            crate::prompt::PASSPHRASE_ENV
        ));
    }
    let hello_selftest = if args.hello_selftest {
        Some(self_test(ctx))
    } else {
        None
    };
    if let Some(SelfTest {
        ok: false, message, ..
    }) = &hello_selftest
    {
        problems.push(format!("Windows Hello self-test failed: {message}"));
    }

    let report = DoctorReport {
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        exe,
        vault: ctx.vault.path.display().to_string(),
        vault_exists: ctx.vault.exists(),
        vault_generation,
        vault_slots,
        hello,
        hello_selftest,
        wsl,
        ssh_add,
        agent,
        passphrase_env_set,
        problems,
    };
    if ctx.out.json {
        return ctx.out.json(&report);
    }
    ctx.out.line(&format!(
        "wcm {} on {}/{}",
        report.version, report.os, report.arch
    ))?;
    ctx.out.line(&format!(
        "exe:           {}",
        report.exe.as_deref().unwrap_or("?")
    ))?;
    ctx.out.line(&format!(
        "vault:         {} ({})",
        report.vault,
        if report.vault_exists {
            "exists"
        } else {
            "missing"
        }
    ))?;
    if let Some(g) = report.vault_generation {
        ctx.out.line(&format!(
            "generation:    {g}; slots: {}",
            report.vault_slots.join(", ")
        ))?;
    }
    ctx.out
        .line(&format!("hello:         {}", report.hello.availability))?;
    ctx.out.line(&format!(
        "session:       {}{}",
        report
            .hello
            .session_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| "n/a".into()),
        if report.hello.interactive {
            " (interactive)"
        } else {
            " (NOT interactive)"
        }
    ))?;
    ctx.out.line(&format!(
        "dpapi:         {}",
        if report.hello.dpapi_available {
            "available"
        } else {
            "n/a"
        }
    ))?;
    if let Some(st) = &report.hello_selftest {
        ctx.out.line(&format!(
            "hello selftest: {} — {}",
            if st.ok { "OK" } else { "FAILED" },
            st.message
        ))?;
    }
    ctx.out.line(&format!(
        "wsl:           {}",
        if report.wsl.detected {
            format!(
                "{} (wcm.exe: {})",
                report.wsl.kind.as_deref().unwrap_or("?"),
                report.wsl.windows_exe.as_deref().unwrap_or("not found")
            )
        } else {
            "no".into()
        }
    ))?;
    ctx.out.line(&format!(
        "ssh-add:       {}",
        report.ssh_add.as_deref().unwrap_or("not found")
    ))?;
    ctx.out.line(&format!(
        "agent:         {}",
        if report.agent.running {
            format!(
                "running (pid {}, {})",
                report
                    .agent
                    .pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "?".into()),
                report.agent.endpoint.as_deref().unwrap_or("?")
            )
        } else {
            "not running".into()
        }
    ))?;
    if report.problems.is_empty() {
        ctx.out.line("problems:      none")?;
    } else {
        ctx.out.line("problems:")?;
        for p in &report.problems {
            ctx.out.line(&format!("  - {p}"))?;
        }
    }
    Ok(())
}

fn self_test(ctx: &Ctx) -> SelfTest {
    let backend = ctx.hello_backend(true, false);
    if backend.availability() != Availability::Available {
        return SelfTest {
            ok: false,
            hw_backed: None,
            message: "Windows Hello unavailable".into(),
        };
    }
    let vault_id = [0u8; 16];
    let uctx = ctx.unlock_ctx(vault_id, "Windows Hello self-test");
    match backend.enroll(&uctx) {
        Ok((params, _ikm)) => {
            let hw = match &params {
                SlotParams::Hello { hw_backed, .. } => Some(*hw_backed),
                SlotParams::Passphrase { .. } => None,
            };
            let _ = backend.destroy(&params);
            SelfTest {
                ok: true,
                hw_backed: hw,
                message: format!(
                    "create + sign + PKCS#1 v1.5 verify succeeded (tpm={})",
                    hw.map(|b| b.to_string()).unwrap_or_else(|| "?".into())
                ),
            }
        }
        Err(e) => SelfTest {
            ok: false,
            hw_backed: None,
            message: e.to_string(),
        },
    }
}

#[cfg(target_os = "linux")]
fn wsl_report() -> WslReport {
    let info = crate::wsl::info();
    WslReport {
        detected: info.kind.is_some(),
        kind: info.kind.map(|k| k.to_string()),
        windows_exe: info.windows_exe.map(|p| p.display().to_string()),
    }
}

#[cfg(not(target_os = "linux"))]
fn wsl_report() -> WslReport {
    // A run proxied from WSL carries the shim's context through WSLENV
    // (kind + wcm.exe path as seen from WSL); a plain run reports "no".
    let env: crate::wsl_core::Env = std::env::vars().collect();
    match crate::wsl_core::shim_wsl_context(&env) {
        Some(ctx) => WslReport {
            detected: true,
            kind: ctx.kind,
            windows_exe: ctx.windows_exe,
        },
        None => WslReport::default(),
    }
}
