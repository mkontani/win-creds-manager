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

/// String SID (`S-1-5-21-…`) of the user running this process; `None` on
/// other platforms or if the token cannot be read. Used to restrict the agent's
/// named pipe to the current user.
pub fn current_user_sid() -> Option<String> {
    platform::current_user_sid()
}

#[cfg(windows)]
mod platform {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, OpenProcessToken,
    };

    pub fn session_id() -> Option<u32> {
        let mut sid = 0u32;
        // SAFETY: both calls only read/write plain integers owned by this frame.
        #[allow(unsafe_code)]
        let ok = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut sid).is_ok() };
        ok.then_some(sid)
    }

    pub fn current_user_sid() -> Option<String> {
        // SAFETY: every pointer handed to Win32 points into buffers owned by this
        // frame and sized by the size query; handles are closed before returning.
        #[allow(unsafe_code)]
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
            let mut len = 0u32;
            // Size query: fails with ERROR_INSUFFICIENT_BUFFER and fills `len`.
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
            // u64 storage keeps TOKEN_USER (pointer-sized fields) aligned.
            let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
            let filled = GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr().cast()),
                len,
                &mut len,
            )
            .is_ok();
            let _ = CloseHandle(token);
            if !filled {
                return None;
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut wide = PWSTR::null();
            ConvertSidToStringSidW(user.User.Sid, &mut wide).ok()?;
            let sid = wide.to_string().ok();
            let _ = LocalFree(Some(HLOCAL(wide.0.cast())));
            sid
        }
    }
}

#[cfg(not(windows))]
mod platform {
    pub fn session_id() -> Option<u32> {
        None
    }

    pub fn current_user_sid() -> Option<String> {
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

    #[test]
    fn current_user_sid_is_a_windows_sid_or_none() {
        match current_user_sid() {
            Some(sid) => {
                assert!(cfg!(windows));
                assert!(sid.starts_with("S-1-"), "{sid}");
            }
            None => assert!(!cfg!(windows)),
        }
    }
}
