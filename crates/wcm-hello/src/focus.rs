//! Best-effort helper that brings the Windows Hello dialog ("Credential Dialog
//! Xaml Host") to the foreground while a prompt is pending. Console processes
//! launched from WSL or a background terminal otherwise get the prompt hidden
//! behind other windows. Disabled with `WCM_HELLO_FOCUS=0`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// Environment variable that disables the focus helper when set to `0`.
pub const FOCUS_ENV: &str = "WCM_HELLO_FOCUS";

/// RAII guard; stops the helper thread on drop.
pub struct FocusGuard {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl FocusGuard {
    /// Starts the helper if `enabled` and not disabled via env. No-op on non-Windows.
    pub fn start(enabled: bool) -> FocusGuard {
        let stop = Arc::new(AtomicBool::new(false));
        let disabled_by_env = std::env::var(FOCUS_ENV).map(|v| v == "0").unwrap_or(false);
        let handle = if enabled && !disabled_by_env && cfg!(windows) {
            let s = stop.clone();
            Some(std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    platform::focus_hello_dialog();
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }))
        } else {
            None
        };
        FocusGuard { stop, handle }
    }

    /// Whether the helper thread is running.
    pub fn is_active(&self) -> bool {
        self.handle.is_some()
    }
}

impl Drop for FocusGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(windows)]
mod platform {
    use windows::core::{s, PCSTR};
    use windows::Win32::UI::WindowsAndMessaging::{FindWindowA, SetForegroundWindow};

    pub fn focus_hello_dialog() {
        // SAFETY: FindWindowA / SetForegroundWindow are plain Win32 calls with
        // valid static class-name pointers; failures are ignored (best effort).
        #[allow(unsafe_code)]
        unsafe {
            if let Ok(hwnd) = FindWindowA(s!("Credential Dialog Xaml Host"), PCSTR::null()) {
                let _ = SetForegroundWindow(hwnd);
            }
        }
    }
}

#[cfg(not(windows))]
mod platform {
    pub fn focus_hello_dialog() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_is_inactive_when_disabled_or_non_windows() {
        let g = FocusGuard::start(false);
        assert!(!g.is_active());
        if !cfg!(windows) {
            let g = FocusGuard::start(true);
            assert!(!g.is_active());
        }
    }
}
