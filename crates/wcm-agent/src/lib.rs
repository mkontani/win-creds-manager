//! Session cache agent for `wcm`: keeps unlocked vault keys (DEKs) in memory
//! for a bounded time so that a burst of `wcm` commands needs a single
//! Windows Hello prompt.
//!
//! The agent never sees Windows Hello: clients unlock the vault themselves and
//! hand the DEK over (`Put`); later invocations fetch it back (`Get`). Transport
//! is a local socket (named pipe on Windows, Unix domain socket elsewhere).
#![forbid(unsafe_code)]

pub mod cache;
pub mod client;
pub mod duration;
pub mod endpoint;
pub mod protocol;
pub mod server;

pub use cache::{Cache, Policy};
pub use client::Client;
pub use endpoint::{AgentState, Endpoint, StateFile, ENDPOINT_ENV};
pub use protocol::{EntryInfo, PolicyInfo, Request, Response, VaultId, WireDek, PROTOCOL_VERSION};
pub use server::{Server, ServerOptions};
