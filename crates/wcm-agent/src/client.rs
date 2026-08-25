//! Client side: finds the running agent and talks to it (one connection per request).

use wcm_core::{Error, Result};

use crate::endpoint::Endpoint;

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

    /// Liveness check.
    pub fn ping(&self) -> Result<()> {
        Err(Error::Helper(format!(
            "agent: ping {} not implemented",
            self.endpoint
        )))
    }
}
