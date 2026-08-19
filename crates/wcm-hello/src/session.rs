//! Interactive-session detection. Windows Hello can only prompt in an
//! interactive desktop session (never session 0, e.g. SSH into Windows).

/// Windows session id of the current process (`None` on other platforms).
pub fn session_id() -> Option<u32> {
    platform::session_id()
}

/// Whether Windows Hello prompts can be shown from this process.
/// Always `true` on non-Windows (the question does not arise).
pub fn is_interactive() -> bool {
    !matches!(session_id(), Some(0))
}

#[cfg(windows)]
mod platform {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::System::Threading::GetCurrentProcessId;

    pub fn session_id() -> Option<u32> {
        let mut sid = 0u32;
        // SAFETY: both calls only read/write plain integers owned by this frame.
        #[allow(unsafe_code)]
        let ok = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut sid).is_ok() };
        ok.then_some(sid)
    }
}

#[cfg(not(windows))]
mod platform {
    pub fn session_id() -> Option<u32> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_windows_is_interactive() {
        if !cfg!(windows) {
            assert_eq!(session_id(), None);
            assert!(is_interactive());
        }
    }
}
