//! Session cache agent for `wcm`: keeps unlocked vault keys (DEKs) in memory
//! for a bounded time so that a burst of `wcm` commands needs a single
//! Windows Hello prompt.
//!
//! The agent never sees Windows Hello: clients unlock the vault themselves and
//! hand the DEK over (`Put`); later invocations fetch it back (`Get`). Transport
//! is a local socket (named pipe on Windows, Unix domain socket elsewhere).
#![forbid(unsafe_code)]

pub mod duration;
pub mod protocol;

pub use protocol::{EntryInfo, PolicyInfo, Request, Response, VaultId, WireDek, PROTOCOL_VERSION};
