//! Process-launch hygiene for the detached agent.
//!
//! On Windows the standard library always calls `CreateProcessW` with
//! `bInheritHandles = TRUE`, and the pipe handles a parent hands to a child
//! are created inheritable. A process that was itself started with piped
//! stdio and then spawns a detached child therefore leaks its own stdout /
//! stderr pipes into that child — even when the child's stdio is redirected
//! to NUL — and whoever reads those pipes (a test harness, the WSL shim
//! relaying interop pipes) waits for an EOF that only arrives when the
//! detached child exits. Clearing the inherit flag on our standard handles
//! before spawning closes that leak. Unix marks pipes `CLOEXEC`, so the
//! function is a no-op there.

/// Marks this process's stdin/stdout/stderr handles as not inheritable so a
/// child spawned afterwards does not keep them open. Standard handles that are
/// absent (no console, detached process) are skipped.
pub fn stop_inheriting_stdio() -> std::io::Result<()> {
    platform::stop_inheriting_stdio()
}

#[cfg(windows)]
mod platform {
    use windows::Win32::Foundation::{SetHandleInformation, HANDLE_FLAGS, HANDLE_FLAG_INHERIT};
    use windows::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    pub fn stop_inheriting_stdio() -> std::io::Result<()> {
        for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            // SAFETY: `GetStdHandle` only reads process state and returns a
            // handle this process owns; `SetHandleInformation` takes that
            // handle plus two plain flag words and does not retain them.
            #[allow(unsafe_code)]
            let result = unsafe {
                match GetStdHandle(id) {
                    Ok(handle) if !handle.is_invalid() => {
                        SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))
                    }
                    // No such standard handle: nothing a child could inherit.
                    _ => Ok(()),
                }
            };
            result.map_err(std::io::Error::from)?;
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod platform {
    pub fn stop_inheriting_stdio() -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn stop_inheriting_stdio_succeeds_on_this_process() {
        super::stop_inheriting_stdio().expect("standard handles");
    }
}
