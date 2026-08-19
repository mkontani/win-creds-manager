//! Error type and stable exit codes shared by every wcm crate.

/// Every failure mode of wcm, mapped 1:1 to a stable process exit code.
///
/// Exit codes are kept `<= 125` because the WSL interop relay truncates exit
/// codes to 8 bits and 126/127 are reserved for the WSL shim itself.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("item not found: {0}")]
    NotFound(String),
    #[error("item already exists: {0}")]
    AlreadyExists(String),
    #[error("vault not initialized at {0}")]
    NotInitialized(String),
    #[error("authentication cancelled")]
    AuthCancelled,
    #[error("authentication unavailable: {0}")]
    AuthUnavailable(String),
    #[error("vault integrity error: {0}")]
    Integrity(String),
    #[error("vault locked or modified concurrently")]
    Locked,
    #[error("i/o error: {0}")]
    Io(String),
    #[error("helper failed: {0}")]
    Helper(String),
    #[error("import/export format error: {0}")]
    Format(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("{0}")]
    Other(String),
}

/// Result alias used across the workspace.
pub type Result<T> = std::result::Result<T, Error>;

/// Exit code reserved by the WSL shim when interop is broken (`Exec format error`).
pub const EXIT_WSL_INTEROP_BROKEN: u8 = 126;
/// Exit code reserved by the WSL shim when `wcm.exe` cannot be located.
pub const EXIT_WSL_EXE_NOT_FOUND: u8 = 127;
/// Exit code used when interrupted by SIGINT / Ctrl+C.
pub const EXIT_INTERRUPTED: u8 = 130;

impl Error {
    /// Stable process exit code for this error.
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::Other(_) => 1,
            Error::Invalid(_) => 2,
            Error::NotFound(_) => 3,
            Error::AlreadyExists(_) => 4,
            Error::NotInitialized(_) => 5,
            Error::AuthCancelled => 6,
            Error::AuthUnavailable(_) => 7,
            Error::Integrity(_) => 8,
            Error::Locked => 9,
            Error::Io(_) => 10,
            Error::Helper(_) => 11,
            Error::Format(_) => 12,
        }
    }

    /// Machine-readable error code (used in `--json` error envelopes).
    pub fn code(&self) -> &'static str {
        match self {
            Error::Other(_) => "GENERAL",
            Error::Invalid(_) => "INVALID_INPUT",
            Error::NotFound(_) => "NOT_FOUND",
            Error::AlreadyExists(_) => "ALREADY_EXISTS",
            Error::NotInitialized(_) => "NOT_INITIALIZED",
            Error::AuthCancelled => "AUTH_CANCELLED",
            Error::AuthUnavailable(_) => "AUTH_UNAVAILABLE",
            Error::Integrity(_) => "INTEGRITY",
            Error::Locked => "LOCKED",
            Error::Io(_) => "IO",
            Error::Helper(_) => "HELPER",
            Error::Format(_) => "FORMAT",
        }
    }

    /// Optional actionable hint for humans.
    pub fn hint(&self) -> Option<String> {
        match self {
            Error::NotFound(_) => Some("run `wcm ls` to list stored items".into()),
            Error::AlreadyExists(_) => Some("use `-f/--force` to overwrite".into()),
            Error::NotInitialized(_) => Some("run `wcm init` first".into()),
            Error::AuthUnavailable(_) => Some(
                "if the Windows Hello key is gone, run `wcm recover` with your recovery key; \
                 on non-Windows machines use `--slot recovery`"
                    .into(),
            ),
            Error::Integrity(_) => Some(
                "the vault may be corrupt or the wrong key was used; a previous generation is kept in `vault.wcm.bak`"
                    .into(),
            ),
            Error::Locked => Some("another wcm process modified the vault; retry the command".into()),
            _ => None,
        }
    }

    /// All (code, exit) pairs — used by `wcm --exit-codes`.
    pub fn table() -> Vec<(&'static str, u8, &'static str)> {
        vec![
            ("OK", 0, "success"),
            ("GENERAL", 1, "unexpected error"),
            ("USAGE", 2, "usage / invalid input"),
            ("NOT_FOUND", 3, "item not found"),
            ("ALREADY_EXISTS", 4, "item already exists"),
            ("NOT_INITIALIZED", 5, "vault not initialized"),
            ("AUTH_CANCELLED", 6, "Windows Hello prompt cancelled"),
            ("AUTH_UNAVAILABLE", 7, "no usable key slot / Hello unavailable"),
            ("INTEGRITY", 8, "vault integrity or decryption failure"),
            ("LOCKED", 9, "vault locked or concurrently modified"),
            ("IO", 10, "file system error"),
            ("HELPER", 11, "clipboard / ssh-add helper failure"),
            ("FORMAT", 12, "import/export format error"),
            ("WSL_INTEROP_BROKEN", EXIT_WSL_INTEROP_BROKEN, "WSL interop cannot launch Windows executables"),
            ("WSL_EXE_NOT_FOUND", EXIT_WSL_EXE_NOT_FOUND, "wcm.exe not found from WSL"),
            ("INTERRUPTED", EXIT_INTERRUPTED, "interrupted"),
        ]
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_variants() -> Vec<Error> {
        vec![
            Error::NotFound("x".into()),
            Error::AlreadyExists("x".into()),
            Error::NotInitialized("x".into()),
            Error::AuthCancelled,
            Error::AuthUnavailable("x".into()),
            Error::Integrity("x".into()),
            Error::Locked,
            Error::Io("x".into()),
            Error::Helper("x".into()),
            Error::Format("x".into()),
            Error::Invalid("x".into()),
            Error::Other("x".into()),
        ]
    }

    #[test]
    fn exit_codes_are_unique_nonzero_and_below_126() {
        let mut seen = std::collections::HashSet::new();
        for e in all_variants() {
            let c = e.exit_code();
            assert!(c > 0 && c <= 125, "{e:?} -> {c}");
            assert!(seen.insert(c), "duplicate exit code {c}");
        }
    }

    #[test]
    fn table_covers_every_variant_code() {
        let table = Error::table();
        for e in all_variants() {
            let entry = table.iter().find(|(_, exit, _)| *exit == e.exit_code());
            assert!(entry.is_some(), "missing table entry for {e:?}");
            if e.exit_code() != 2 {
                assert_eq!(entry.map(|t| t.0), Some(e.code()), "code mismatch for {e:?}");
            }
        }
    }

    #[test]
    fn io_error_converts() {
        let e: Error = std::io::Error::other("boom").into();
        assert_eq!(e.exit_code(), 10);
        assert!(e.to_string().contains("boom"));
    }
}
