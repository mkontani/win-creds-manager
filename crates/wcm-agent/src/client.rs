//! Client side: finds the running agent and talks to it (one connection per
//! request). Every request runs on a helper thread and is abandoned after
//! [`REQUEST_TIMEOUT`], so a wedged agent never hangs a `wcm` command.

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

    /// Finds a running agent: `WCM_AGENT_ENDPOINT` if set, else the endpoint
    /// recorded in `<data_dir>/agent.json`. `None` when nothing answers; a
    /// state file nobody answers for (crashed agent) is removed.
    pub fn discover(data_dir: &Path) -> Option<Client> {
        if let Ok(Some(endpoint)) = env_endpoint() {
            let client = Client::connect(endpoint);
            return client.ping().is_ok().then_some(client);
        }
        let state = StateFile::in_dir(data_dir);
        let endpoint: Endpoint = state.read()?.endpoint.parse().ok()?;
        let client = Client::connect(endpoint);
        if client.ping().is_ok() {
            Some(client)
        } else {
            let _ = state.remove();
            None
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
        let endpoint = self.endpoint.clone();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(round_trip(&endpoint, request));
        });
        match rx.recv_timeout(REQUEST_TIMEOUT) {
            Ok(result) => result,
            Err(_) => Err(Error::Helper(format!(
                "agent: no response from {} within {}s",
                self.endpoint,
                REQUEST_TIMEOUT.as_secs()
            ))),
        }
    }
}

fn round_trip(endpoint: &Endpoint, request: Request) -> Result<Response> {
    let name = endpoint.to_name()?;
    let mut stream = Stream::connect(name)
        .map_err(|e| Error::Helper(format!("agent: connect {endpoint}: {e}")))?;
    protocol::write_frame(&mut stream, &request)?;
    protocol::read_frame(&mut stream)
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
}
