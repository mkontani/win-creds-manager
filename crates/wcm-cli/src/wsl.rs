//! WSL shim — TODO(agent): detect WSL and exec `wcm.exe` via interop.

use std::path::PathBuf;

/// WSL flavour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WslKind {
    Wsl1,
    Wsl2,
}

impl std::fmt::Display for WslKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            WslKind::Wsl1 => "WSL1",
            WslKind::Wsl2 => "WSL2",
        })
    }
}

/// Diagnostic info for `wcm doctor`.
pub struct WslInfo {
    pub kind: Option<WslKind>,
    pub windows_exe: Option<PathBuf>,
}

/// Detects WSL and locates `wcm.exe` (without executing anything).
pub fn info() -> WslInfo {
    WslInfo {
        kind: None,
        windows_exe: None,
    }
}

/// If running under WSL, execs `wcm.exe` with the same arguments and returns its exit code.
/// Returns `None` when not under WSL (or when proxying is disabled), so the caller continues natively.
pub fn maybe_proxy() -> Option<u8> {
    None
}
