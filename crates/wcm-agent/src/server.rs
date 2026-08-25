//! The agent process: accepts one request per connection and answers from the
//! cache. `serve` polls a nonblocking `accept` so a `Stop` request can end the
//! loop on every platform without signals.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use interprocess::local_socket::{
    prelude::*, Listener, ListenerNonblockingMode, ListenerOptions, Stream,
};
use wcm_core::crypto::aead::KEY_LEN;
use wcm_core::{Error, Result};

use crate::cache::Cache;
use crate::client::Client;
use crate::endpoint::Endpoint;
use crate::protocol::{self, Op, Request, Response, WireDek, PROTOCOL_VERSION};

/// How often the accept loop checks the shutdown flag.
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// How often expired entries are zeroized even when nobody asks.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Platform options for [`Server::bind`].
#[derive(Clone, Debug, Default)]
pub struct ServerOptions {
    /// Windows: string SID of the user allowed to use the pipe (**required**).
    /// Ignored elsewhere.
    pub owner_sid: Option<String>,
}

/// A bound, not yet serving, listener.
pub struct Server {
    listener: Listener,
    endpoint: Endpoint,
}

impl Server {
    /// Binds `endpoint`.
    ///
    /// * Windows: the pipe gets the DACL `D:P(A;;GA;;;<owner_sid>)`; without a
    ///   SID this fails (`Error::Helper`) rather than using the default ACL.
    /// * `AddrInUse`: if an agent answers there, `Error::AlreadyExists`;
    ///   otherwise (Unix) the stale socket file is removed and the bind retried.
    pub fn bind(endpoint: Endpoint, opts: &ServerOptions) -> Result<Server> {
        let listener = match try_create(&endpoint, opts) {
            Ok(listener) => listener,
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                if Client::connect(endpoint.clone()).ping().is_ok() {
                    return Err(Error::AlreadyExists(format!(
                        "agent already listening on {endpoint}"
                    )));
                }
                // Nobody answers: a previous agent died without cleaning up.
                if let Endpoint::Socket(path) = &endpoint {
                    let _ = std::fs::remove_file(path);
                }
                try_create(&endpoint, opts)
                    .map_err(|e| Error::Helper(format!("agent: bind {endpoint}: {e}")))?
            }
            Err(e) => return Err(Error::Helper(format!("agent: bind {endpoint}: {e}"))),
        };
        Ok(Server { listener, endpoint })
    }

    /// Where this server listens.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Serves until a `Stop` request. Every cached key is wiped before returning.
    pub fn serve(self, cache: Arc<Mutex<Cache>>) -> Result<()> {
        let stop = Arc::new(AtomicBool::new(false));
        spawn_sweeper(cache.clone(), stop.clone());
        while !stop.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok(stream) => {
                    let cache = cache.clone();
                    let stop = stop.clone();
                    thread::spawn(move || handle(stream, &cache, &stop));
                }
                // WouldBlock: nobody is connecting. Anything else is transient
                // (a client that vanished between connect and accept); keep serving.
                Err(_) => thread::sleep(ACCEPT_POLL),
            }
        }
        if let Ok(mut c) = cache.lock() {
            c.lock_all();
        }
        Ok(())
    }
}

fn try_create(endpoint: &Endpoint, opts: &ServerOptions) -> io::Result<Listener> {
    let name = endpoint
        .to_name()
        .map_err(|e| io::Error::other(e.to_string()))?;
    let options = ListenerOptions::new()
        .name(name)
        .nonblocking(ListenerNonblockingMode::Accept);
    let options = apply_acl(options, opts)?;
    options.create_sync()
}

#[cfg(windows)]
fn apply_acl<'n>(
    options: ListenerOptions<'n>,
    opts: &ServerOptions,
) -> io::Result<ListenerOptions<'n>> {
    use interprocess::os::windows::local_socket::ListenerOptionsExt;
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;
    use widestring::U16CString;

    let sid = opts
        .owner_sid
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            io::Error::other(
                "cannot determine the current user's SID; refusing to start with the default pipe ACL",
            )
        })?;
    // Protected DACL with a single ACE: full access for the owner, nobody else.
    let sddl = format!("D:P(A;;GA;;;{sid})");
    let wide = U16CString::from_str(&sddl).map_err(|e| io::Error::other(format!("sddl: {e}")))?;
    let descriptor = SecurityDescriptor::deserialize(&wide)?;
    Ok(options.security_descriptor(descriptor))
}

#[cfg(not(windows))]
fn apply_acl<'n>(
    options: ListenerOptions<'n>,
    _opts: &ServerOptions,
) -> io::Result<ListenerOptions<'n>> {
    Ok(options)
}

fn spawn_sweeper(cache: Arc<Mutex<Cache>>, stop: Arc<AtomicBool>) {
    thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            thread::sleep(SWEEP_INTERVAL);
            if let Ok(mut c) = cache.lock() {
                c.sweep(Instant::now());
            }
        }
    });
}

fn handle(mut stream: Stream, cache: &Mutex<Cache>, stop: &AtomicBool) {
    let Ok(request) = protocol::read_frame::<_, Request>(&mut stream) else {
        return;
    };
    let (response, stop_after) = dispatch(request, cache);
    let _ = protocol::write_frame(&mut stream, &response);
    // Set only after the reply is on the wire so `wcm agent stop` sees `Ok`.
    if stop_after {
        stop.store(true, Ordering::SeqCst);
    }
}

/// Computes the response for `request`; the flag asks the accept loop to exit.
pub fn dispatch(request: Request, cache: &Mutex<Cache>) -> (Response, bool) {
    if request.version != PROTOCOL_VERSION {
        return (
            Response::Error {
                code: "VERSION".into(),
                message: format!(
                    "protocol version {} not supported (agent speaks {PROTOCOL_VERSION})",
                    request.version
                ),
            },
            false,
        );
    }
    let now = Instant::now();
    let Ok(mut cache) = cache.lock() else {
        return (
            Response::Error {
                code: "INTERNAL".into(),
                message: "cache lock poisoned".into(),
            },
            false,
        );
    };
    match request.op {
        Op::Ping => (Response::Ok, false),
        Op::Put {
            vault_id,
            path,
            dek,
        } => match dek.to_dek() {
            Some(key) => {
                cache.put(vault_id, path, key, now);
                (Response::Ok, false)
            }
            None => (
                Response::Error {
                    code: "BAD_REQUEST".into(),
                    message: format!("dek must be {KEY_LEN} bytes, got {}", dek.len()),
                },
                false,
            ),
        },
        Op::Get { vault_id } => match cache.get(&vault_id, now) {
            Some(key) => (
                Response::Dek {
                    dek: WireDek::from_dek(&key),
                },
                false,
            ),
            None => (Response::Miss, false),
        },
        Op::Lock { vault_id } => {
            cache.lock(&vault_id);
            (Response::Ok, false)
        }
        Op::LockAll => {
            cache.lock_all();
            (Response::Ok, false)
        }
        Op::Status => (
            Response::Status {
                policy: cache.policy().info(),
                entries: cache.status(now),
            },
            false,
        ),
        Op::Stop => {
            cache.lock_all();
            (Response::Ok, true)
        }
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use crate::cache::Policy;

    fn cache() -> Mutex<Cache> {
        Mutex::new(Cache::new(Policy::DEFAULT))
    }

    fn dek() -> WireDek {
        WireDek::from_dek(&Zeroizing::new([5u8; KEY_LEN]))
    }

    const ID: [u8; 16] = [1; 16];

    #[test]
    fn version_mismatch_is_rejected() {
        let c = cache();
        let (r, stop) = dispatch(
            Request {
                version: PROTOCOL_VERSION + 1,
                op: Op::Ping,
            },
            &c,
        );
        assert!(
            matches!(r, Response::Error { ref code, .. } if code == "VERSION"),
            "{r:?}"
        );
        assert!(!stop);
    }

    #[test]
    fn ping_put_get_lock_flow() {
        let c = cache();
        assert_eq!(dispatch(Request::new(Op::Ping), &c), (Response::Ok, false));
        assert_eq!(
            dispatch(Request::new(Op::Get { vault_id: ID }), &c),
            (Response::Miss, false)
        );
        assert_eq!(
            dispatch(
                Request::new(Op::Put {
                    vault_id: ID,
                    path: "/v".into(),
                    dek: dek()
                }),
                &c
            ),
            (Response::Ok, false)
        );
        assert_eq!(
            dispatch(Request::new(Op::Get { vault_id: ID }), &c),
            (Response::Dek { dek: dek() }, false)
        );
        assert_eq!(
            dispatch(Request::new(Op::Lock { vault_id: ID }), &c),
            (Response::Ok, false)
        );
        assert_eq!(
            dispatch(Request::new(Op::Get { vault_id: ID }), &c),
            (Response::Miss, false)
        );
    }

    #[test]
    fn put_with_a_wrong_key_length_is_a_bad_request() {
        let c = cache();
        let (r, _) = dispatch(
            Request::new(Op::Put {
                vault_id: ID,
                path: "/v".into(),
                dek: WireDek::from_bytes(vec![0; 5]),
            }),
            &c,
        );
        assert!(
            matches!(r, Response::Error { ref code, .. } if code == "BAD_REQUEST"),
            "{r:?}"
        );
        assert!(c.lock().expect("lock").is_empty());
    }

    #[test]
    fn status_lists_policy_and_entries() {
        let c = cache();
        dispatch(
            Request::new(Op::Put {
                vault_id: ID,
                path: "/v".into(),
                dek: dek(),
            }),
            &c,
        );
        match dispatch(Request::new(Op::Status), &c) {
            (Response::Status { policy, entries }, false) => {
                assert_eq!(policy, Policy::DEFAULT.info());
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].path, "/v");
                assert_eq!(entries[0].uses, 0);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn lock_all_and_stop_wipe_the_cache() {
        let c = cache();
        for id in [ID, [2; 16]] {
            dispatch(
                Request::new(Op::Put {
                    vault_id: id,
                    path: "/v".into(),
                    dek: dek(),
                }),
                &c,
            );
        }
        assert_eq!(
            dispatch(Request::new(Op::LockAll), &c),
            (Response::Ok, false)
        );
        assert!(c.lock().expect("lock").is_empty());
        dispatch(
            Request::new(Op::Put {
                vault_id: ID,
                path: "/v".into(),
                dek: dek(),
            }),
            &c,
        );
        assert_eq!(dispatch(Request::new(Op::Stop), &c), (Response::Ok, true));
        assert!(c.lock().expect("lock").is_empty());
    }
}
