//! Client side: finds the running agent and talks to it (one connection per
//! request). Every request runs on a helper thread and is abandoned after
//! [`REQUEST_TIMEOUT`], so a wedged agent never hangs a `wcm` command.

use std::io;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use interprocess::local_socket::{prelude::*, Stream};
use wcm_core::slot::Dek;
use wcm_core::{Error, Result};

use crate::endpoint::{env_endpoint, Endpoint, StateFile};
use crate::protocol::{self, EntryInfo, Op, PolicyInfo, Request, Response, VaultId, WireDek};

/// Longest wait for an answer before the caller falls back to a normal unlock.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Handle on an agent endpoint. Each request opens its own connection.
#[derive(Clone, Debug)]
pub struct Client {
    endpoint: Endpoint,
}

impl Client {
    /// A client for `endpoint` (no I/O yet).
    pub fn connect(endpoint: Endpoint) -> Client {
        Client { endpoint }
    }

    /// The endpoint this client talks to.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Finds a running agent. Three cases:
    /// * `WCM_AGENT_ENDPOINT` set and valid: pings that endpoint; `Some` if it
    ///   answers, `None` otherwise. `agent.json` is never consulted or touched.
    /// * `WCM_AGENT_ENDPOINT` set but unparseable: `None` immediately — the
    ///   override disables discovery for this invocation rather than falling
    ///   back to the state file (the server side reports the parse error when
    ///   it starts). `agent.json` is never touched.
    /// * `WCM_AGENT_ENDPOINT` unset: the endpoint recorded in
    ///   `<data_dir>/agent.json`. `None` when there is no state file, its
    ///   `endpoint` field doesn't parse, or nothing answers. The state file is
    ///   removed only when it is provably useless: it doesn't parse, or nothing
    ///   is listening at the endpoint it names. A timeout or any other failure
    ///   leaves it alone — a wedged but live agent still owns that endpoint and
    ///   deleting its file would orphan it.
    pub fn discover(data_dir: &Path) -> Option<Client> {
        match env_endpoint() {
            Ok(Some(endpoint)) => {
                let client = Client::connect(endpoint);
                return matches!(client.probe(), Probe::Answered).then_some(client);
            }
            Err(_) => return None,
            Ok(None) => {}
        }
        let state = StateFile::in_dir(data_dir);
        let recorded = state.read()?;
        let Ok(endpoint) = recorded.endpoint.parse::<Endpoint>() else {
            let _ = state.remove();
            return None;
        };
        let client = Client::connect(endpoint);
        match client.probe() {
            Probe::Answered => Some(client),
            // The connect itself failed: the agent died without cleaning up.
            Probe::NoListener => {
                let _ = state.remove();
                None
            }
            // Something answers there (or might still): fall back to a normal
            // unlock, but keep the file so `agent stop` can still find it.
            Probe::Unreachable => None,
        }
    }

    /// Pings the endpoint, keeping "nothing is listening here" distinguishable
    /// from a timeout or a protocol failure.
    fn probe(&self) -> Probe {
        match self.send(Request::new(Op::Ping)) {
            Ok(Response::Ok) => Probe::Answered,
            // The connect succeeded, so something owns this endpoint even if it
            // answered nonsense, timed out, or is a kind we cannot speak to.
            Ok(_) | Err(RoundTripError::Other(_)) => Probe::Unreachable,
            Err(RoundTripError::Connect(_)) => Probe::NoListener,
        }
    }

    /// Liveness check.
    pub fn ping(&self) -> Result<()> {
        expect_ok(self.raw(Request::new(Op::Ping))?)
    }

    /// The cached key for `vault_id`, if any.
    pub fn get(&self, vault_id: &VaultId) -> Result<Option<Dek>> {
        match self.raw(Request::new(Op::Get {
            vault_id: *vault_id,
        }))? {
            Response::Dek { dek } => dek
                .to_dek()
                .map(Some)
                .ok_or_else(|| Error::Helper("agent: returned a key of the wrong length".into())),
            Response::Miss => Ok(None),
            other => Err(unexpected(other)),
        }
    }

    /// Caches `dek` for `vault_id` (`path` is shown by `status`).
    pub fn put(&self, vault_id: &VaultId, path: &str, dek: &Dek) -> Result<()> {
        expect_ok(self.raw(Request::new(Op::Put {
            vault_id: *vault_id,
            path: path.to_string(),
            dek: WireDek::from_dek(dek),
        }))?)
    }

    /// Forgets the key for one vault.
    pub fn lock(&self, vault_id: &VaultId) -> Result<()> {
        expect_ok(self.raw(Request::new(Op::Lock {
            vault_id: *vault_id,
        }))?)
    }

    /// Forgets every key.
    pub fn lock_all(&self) -> Result<()> {
        expect_ok(self.raw(Request::new(Op::LockAll))?)
    }

    /// Policy and cached entries.
    pub fn status(&self) -> Result<(PolicyInfo, Vec<EntryInfo>)> {
        match self.raw(Request::new(Op::Status))? {
            Response::Status { policy, entries } => Ok((policy, entries)),
            other => Err(unexpected(other)),
        }
    }

    /// Asks the agent to forget everything and exit.
    pub fn stop(&self) -> Result<()> {
        expect_ok(self.raw(Request::new(Op::Stop))?)
    }

    /// Sends one request and waits at most [`REQUEST_TIMEOUT`] for the answer.
    pub fn raw(&self, request: Request) -> Result<Response> {
        self.send(request).map_err(|e| e.into_error(&self.endpoint))
    }

    /// [`Client::raw`] without flattening the failure: the caller can tell a
    /// failed connect from everything else.
    fn send(&self, request: Request) -> std::result::Result<Response, RoundTripError> {
        let endpoint = self.endpoint.clone();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(round_trip(&endpoint, request));
        });
        match rx.recv_timeout(REQUEST_TIMEOUT) {
            Ok(result) => result,
            Err(_) => Err(RoundTripError::Other(Error::Helper(format!(
                "agent: no response from {} within {}s",
                self.endpoint,
                REQUEST_TIMEOUT.as_secs()
            )))),
        }
    }
}

/// What a [`Client::probe`] found at the endpoint.
///
/// The distinction that matters is [`Probe::NoListener`] versus everything
/// else: only "nothing is listening" proves an `agent.json` naming this
/// endpoint is stale. The reason behind [`Probe::Unreachable`] is not carried —
/// [`Client::discover`] falls back silently either way, and callers that need
/// the message use [`Client::raw`], which returns the full [`Error`].
enum Probe {
    /// An agent answered the ping.
    Answered,
    /// Nothing is listening: the connect itself failed.
    NoListener,
    /// Reached but unusable: an unexpected answer, a timeout, a framing or
    /// protocol failure, or an endpoint kind this platform cannot open.
    Unreachable,
}

/// A failed round trip, before it is flattened into [`Error::Helper`].
enum RoundTripError {
    /// `Stream::connect` failed — nobody is listening at this endpoint.
    Connect(io::Error),
    /// Anything else: unusable endpoint kind, write, read, decode.
    Other(Error),
}

impl RoundTripError {
    /// Every client failure is an [`Error::Helper`] so they share one exit code.
    fn into_error(self, endpoint: &Endpoint) -> Error {
        match self {
            RoundTripError::Connect(e) => Error::Helper(format!("agent: connect {endpoint}: {e}")),
            RoundTripError::Other(e) => e,
        }
    }
}

fn round_trip(
    endpoint: &Endpoint,
    request: Request,
) -> std::result::Result<Response, RoundTripError> {
    let name = endpoint
        .to_name()
        .map_err(|e| RoundTripError::Other(Error::Helper(format!("agent: {endpoint}: {e}"))))?;
    let mut stream = Stream::connect(name).map_err(RoundTripError::Connect)?;
    protocol::write_frame(&mut stream, &request).map_err(RoundTripError::Other)?;
    protocol::read_frame(&mut stream).map_err(RoundTripError::Other)
}

fn expect_ok(response: Response) -> Result<()> {
    match response {
        Response::Ok => Ok(()),
        other => Err(unexpected(other)),
    }
}

fn unexpected(response: Response) -> Error {
    match response {
        Response::Error { code, message } => Error::Helper(format!("agent: {code}: {message}")),
        other => Error::Helper(format!("agent: unexpected response {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_responses_become_helper_errors() {
        let e = unexpected(Response::Error {
            code: "VERSION".into(),
            message: "old".into(),
        });
        assert_eq!(e.to_string(), "helper failed: agent: VERSION: old");
        assert!(matches!(expect_ok(Response::Miss), Err(Error::Helper(_))));
        assert!(expect_ok(Response::Ok).is_ok());
    }

    #[test]
    fn an_endpoint_kind_the_platform_cannot_use_is_a_helper_error() {
        // `to_name` rejects the other platform's endpoint kind with
        // `Error::Invalid`; `round_trip` must map that into `Error::Helper` so
        // every client error keeps the same exit code.
        let endpoint = if cfg!(windows) {
            Endpoint::Socket("/x".into())
        } else {
            Endpoint::Pipe("x".into())
        };
        let client = Client::connect(endpoint);
        assert!(matches!(client.ping(), Err(Error::Helper(_))));
    }
}
