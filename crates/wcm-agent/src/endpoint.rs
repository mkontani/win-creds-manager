//! Where the agent listens and how clients find it.
//!
//! * Windows: a named pipe with a random name, recorded in `agent.json` under
//!   the user's data directory (profile ACL) and protected by an owner-only DACL.
//! * Unix: `agent.sock` in a `0700` runtime directory.
//!
//! `WCM_AGENT_ENDPOINT` overrides the endpoint on both sides (tests).

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use interprocess::local_socket::Name;
use serde::{Deserialize, Serialize};
use wcm_core::{Error, Result};

/// Environment variable overriding the endpoint (server and client).
pub const ENDPOINT_ENV: &str = "WCM_AGENT_ENDPOINT";
/// State file name inside the data directory.
pub const STATE_FILE_NAME: &str = "agent.json";
/// Textual prefix of a named-pipe endpoint.
pub const PIPE_PREFIX: &str = r"\\.\pipe\";
#[cfg(not(windows))]
const SOCKET_FILE_NAME: &str = "agent.sock";

/// Where the agent listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// Windows named pipe name without the `\\.\pipe\` prefix.
    Pipe(String),
    /// Unix domain socket path.
    Socket(PathBuf),
}

impl Endpoint {
    /// The `interprocess` name. Pipes only work on Windows, socket paths only on Unix.
    pub fn to_name(&self) -> Result<Name<'_>> {
        match self {
            #[cfg(windows)]
            Endpoint::Pipe(name) => {
                use interprocess::local_socket::{GenericNamespaced, ToNsName};
                name.as_str()
                    .to_ns_name::<GenericNamespaced>()
                    .map_err(|e| Error::Invalid(format!("agent endpoint '{self}': {e}")))
            }
            #[cfg(not(windows))]
            Endpoint::Pipe(_) => Err(Error::Invalid(format!(
                "agent endpoint '{self}' is a Windows named pipe; this platform uses socket paths"
            ))),
            #[cfg(unix)]
            Endpoint::Socket(path) => {
                use interprocess::local_socket::{GenericFilePath, ToFsName};
                path.as_path()
                    .to_fs_name::<GenericFilePath>()
                    .map_err(|e| Error::Invalid(format!("agent endpoint '{self}': {e}")))
            }
            #[cfg(not(unix))]
            Endpoint::Socket(_) => Err(Error::Invalid(format!(
                "agent endpoint '{self}' is a socket path; this platform uses named pipes"
            ))),
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Pipe(name) => write!(f, "{PIPE_PREFIX}{name}"),
            Endpoint::Socket(path) => write!(f, "{}", path.display()),
        }
    }
}

impl FromStr for Endpoint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Endpoint> {
        let text = s.trim();
        if let Some(name) = text.strip_prefix(PIPE_PREFIX) {
            if name.is_empty() || name.contains(['\\', '/']) {
                return Err(Error::Invalid(format!("invalid agent pipe name '{text}'")));
            }
            return Ok(Endpoint::Pipe(name.to_string()));
        }
        if text.is_empty() {
            return Err(Error::Invalid("empty agent endpoint".into()));
        }
        Ok(Endpoint::Socket(PathBuf::from(text)))
    }
}

/// `WCM_AGENT_ENDPOINT` if set and non-empty.
pub fn env_endpoint() -> Result<Option<Endpoint>> {
    match std::env::var(ENDPOINT_ENV) {
        Ok(value) if !value.trim().is_empty() => value.parse().map(Some),
        _ => Ok(None),
    }
}

/// Directory for the Unix socket: `$XDG_RUNTIME_DIR/wcm` when set, else `<data_dir>/run`.
pub fn runtime_dir(data_dir: &Path) -> PathBuf {
    #[cfg(unix)]
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(dir).join("wcm");
    }
    data_dir.join("run")
}

/// A fresh default endpoint: random pipe name on Windows; `agent.sock` in a
/// private `runtime_dir` (created `0700`) elsewhere.
pub fn default_endpoint(runtime_dir: &Path) -> Result<Endpoint> {
    #[cfg(windows)]
    {
        let _ = runtime_dir;
        let random: [u8; 16] = rand::random();
        Ok(Endpoint::Pipe(format!(
            "wcm-agent-{}",
            crate::cache::hex(&random)
        )))
    }
    #[cfg(not(windows))]
    {
        create_private_dir(runtime_dir)?;
        Ok(Endpoint::Socket(runtime_dir.join(SOCKET_FILE_NAME)))
    }
}

/// The endpoint a server should bind: the override, else the default.
pub fn resolve_endpoint(data_dir: &Path) -> Result<Endpoint> {
    if let Some(endpoint) = env_endpoint()? {
        return Ok(endpoint);
    }
    default_endpoint(&runtime_dir(data_dir))
}

/// Creates `dir` (and parents); on Unix restricts it to the owner (`0700`).
pub fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| Error::Io(format!("create {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::Io(format!("chmod {}: {e}", dir.display())))?;
    }
    Ok(())
}

/// Contents of `agent.json` (no secrets).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AgentState {
    /// [`Endpoint`] in its textual form.
    pub endpoint: String,
    /// Agent process id.
    pub pid: u32,
    /// RFC 3339 start time.
    pub started: String,
    /// `wcm` version of the agent.
    pub version: String,
}

/// `agent.json`: written by the agent after binding, read by clients.
pub struct StateFile {
    path: PathBuf,
}

impl StateFile {
    /// `<data_dir>/agent.json`.
    pub fn in_dir(data_dir: &Path) -> StateFile {
        StateFile {
            path: data_dir.join(STATE_FILE_NAME),
        }
    }

    /// The file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes the state (creating the directory; `0600` on Unix).
    pub fn write(&self, state: &AgentState) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Io(format!("create {}: {e}", parent.display())))?;
        }
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| Error::Other(format!("agent state encode: {e}")))?;
        std::fs::write(&self.path, json)
            .map_err(|e| Error::Io(format!("write {}: {e}", self.path.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| Error::Io(format!("chmod {}: {e}", self.path.display())))?;
        }
        Ok(())
    }

    /// `None` when missing or unparseable (both mean "no agent").
    pub fn read(&self) -> Option<AgentState> {
        let text = std::fs::read_to_string(&self.path).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Removes the file; a missing file is fine.
    pub fn remove(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io(format!("remove {}: {e}", self.path.display()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_display_and_parse_round_trip() {
        let pipe = Endpoint::Pipe("wcm-agent-ab".into());
        assert_eq!(pipe.to_string(), r"\\.\pipe\wcm-agent-ab");
        assert_eq!(pipe.to_string().parse::<Endpoint>().expect("pipe"), pipe);

        let sock = Endpoint::Socket(PathBuf::from("/run/user/1/wcm/agent.sock"));
        assert_eq!(sock.to_string(), "/run/user/1/wcm/agent.sock");
        assert_eq!(sock.to_string().parse::<Endpoint>().expect("socket"), sock);
    }

    #[test]
    fn empty_or_prefix_only_endpoints_are_invalid() {
        assert!(matches!("".parse::<Endpoint>(), Err(Error::Invalid(_))));
        assert!(matches!("   ".parse::<Endpoint>(), Err(Error::Invalid(_))));
        assert!(matches!(
            r"\\.\pipe\".parse::<Endpoint>(),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn to_name_accepts_only_this_platforms_kind() {
        let pipe = Endpoint::Pipe("wcm-agent-test".into());
        let sock = Endpoint::Socket(PathBuf::from("/tmp/wcm-agent-test.sock"));
        if cfg!(windows) {
            assert!(pipe.to_name().is_ok());
            assert!(matches!(sock.to_name(), Err(Error::Invalid(_))));
        } else {
            assert!(matches!(pipe.to_name(), Err(Error::Invalid(_))));
            assert!(sock.to_name().is_ok());
        }
    }

    #[test]
    fn default_endpoint_has_the_expected_shape() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = dir.path().join("run");
        let endpoint = default_endpoint(&runtime).expect("endpoint");
        match endpoint {
            Endpoint::Pipe(name) => {
                assert!(cfg!(windows));
                let hex = name.strip_prefix("wcm-agent-").expect("prefix");
                assert_eq!(hex.len(), 32);
                assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
                let again = default_endpoint(&runtime).expect("endpoint");
                assert_ne!(again, Endpoint::Pipe(name), "random per start");
            }
            Endpoint::Socket(path) => {
                assert!(!cfg!(windows));
                assert_eq!(path, runtime.join("agent.sock"));
                assert!(runtime.is_dir(), "runtime dir is created");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let private = dir.path().join("a").join("b");
        create_private_dir(&private).expect("create");
        let mode = std::fs::metadata(&private)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        create_private_dir(&private).expect("idempotent");
    }

    #[test]
    fn runtime_dir_prefers_xdg_runtime_dir_on_unix() {
        let data = Path::new("/data/wcm");
        let got = runtime_dir(data);
        match std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
            Some(xdg) if cfg!(unix) => assert_eq!(got, PathBuf::from(xdg).join("wcm")),
            _ => assert_eq!(got, data.join("run")),
        }
    }

    #[test]
    fn state_file_write_read_remove() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = StateFile::in_dir(&dir.path().join("nested"));
        assert_eq!(file.path(), dir.path().join("nested").join("agent.json"));
        assert!(file.read().is_none());
        let state = AgentState {
            endpoint: r"\\.\pipe\wcm-agent-01".into(),
            pid: 42,
            started: "2026-08-25T00:00:00Z".into(),
            version: "0.2.0".into(),
        };
        file.write(&state).expect("write");
        assert_eq!(file.read(), Some(state));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(file.path())
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        file.remove().expect("remove");
        assert!(file.read().is_none());
        file.remove().expect("removing a missing file is fine");
    }

    #[test]
    fn state_file_ignores_garbage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = StateFile::in_dir(dir.path());
        std::fs::write(file.path(), "not json").expect("write");
        assert!(file.read().is_none());
    }

    #[test]
    fn env_endpoint_reads_and_validates_the_override() {
        // The only test in this crate touching the variable; restored afterwards.
        let prev = std::env::var_os(ENDPOINT_ENV);
        std::env::remove_var(ENDPOINT_ENV);
        assert_eq!(env_endpoint().expect("unset"), None);
        std::env::set_var(ENDPOINT_ENV, "");
        assert_eq!(env_endpoint().expect("empty"), None);
        std::env::set_var(ENDPOINT_ENV, "/tmp/x.sock");
        assert_eq!(
            env_endpoint().expect("set"),
            Some(Endpoint::Socket(PathBuf::from("/tmp/x.sock")))
        );
        std::env::set_var(ENDPOINT_ENV, r"\\.\pipe\");
        assert!(matches!(env_endpoint(), Err(Error::Invalid(_))));
        match prev {
            Some(v) => std::env::set_var(ENDPOINT_ENV, v),
            None => std::env::remove_var(ENDPOINT_ENV),
        }
    }
}
