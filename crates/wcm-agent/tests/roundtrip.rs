//! Server + client over a real local socket (Unix socket / Windows named pipe).

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use wcm_agent::endpoint::{AgentState, StateFile};
use wcm_agent::protocol::{Op, Request, Response, PROTOCOL_VERSION};
use wcm_agent::{Cache, Client, Endpoint, Policy, Server, ServerOptions};
use wcm_core::{Error, Result};
use zeroize::Zeroizing;

/// A private endpoint per test (pipe names are global on Windows).
fn endpoint_in(dir: &Path) -> Endpoint {
    if cfg!(windows) {
        let unique = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("x")
            .replace('.', "");
        Endpoint::Pipe(format!("wcm-agent-test-{unique}"))
    } else {
        Endpoint::Socket(dir.join("a.sock"))
    }
}

fn options() -> ServerOptions {
    ServerOptions {
        owner_sid: wcm_hello::session::current_user_sid(),
    }
}

fn serve(endpoint: &Endpoint) -> JoinHandle<Result<()>> {
    let server = Server::bind(endpoint.clone(), &options()).expect("bind");
    let cache = Arc::new(Mutex::new(Cache::new(Policy::DEFAULT)));
    thread::spawn(move || server.serve(cache))
}

#[test]
fn put_get_lock_status_stop_over_the_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let endpoint = endpoint_in(dir.path());
    let handle = serve(&endpoint);
    let client = Client::connect(endpoint.clone());
    client.ping().expect("ping");

    let id = [7u8; 16];
    assert!(client.get(&id).expect("get").is_none(), "miss");
    let dek = Zeroizing::new([42u8; 32]);
    client.put(&id, "/v/vault.wcm", &dek).expect("put");
    assert_eq!(*client.get(&id).expect("get").expect("hit"), [42u8; 32]);

    let (policy, entries) = client.status().expect("status");
    assert_eq!(policy, Policy::DEFAULT.info());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "/v/vault.wcm");
    assert_eq!(entries[0].uses, 1);

    client.lock(&id).expect("lock");
    assert!(client.get(&id).expect("get").is_none());
    client.put(&id, "/v/vault.wcm", &dek).expect("put again");
    client.lock_all().expect("lock all");
    assert!(client.status().expect("status").1.is_empty());

    client.stop().expect("stop");
    handle.join().expect("join").expect("serve");
    assert!(client.ping().is_err(), "nothing listens after stop");
}

#[test]
fn wrong_protocol_version_is_answered_with_a_version_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let endpoint = endpoint_in(dir.path());
    let handle = serve(&endpoint);
    let client = Client::connect(endpoint);
    let response = client
        .raw(Request {
            version: PROTOCOL_VERSION + 1,
            op: Op::Ping,
        })
        .expect("raw");
    assert!(
        matches!(response, Response::Error { ref code, .. } if code == "VERSION"),
        "{response:?}"
    );
    client.stop().expect("stop");
    handle.join().expect("join").expect("serve");
}

#[test]
fn binding_a_live_endpoint_again_is_already_exists() {
    let dir = tempfile::tempdir().expect("tempdir");
    let endpoint = endpoint_in(dir.path());
    let handle = serve(&endpoint);
    let client = Client::connect(endpoint.clone());
    client.ping().expect("ping");
    let second = Server::bind(endpoint, &options());
    assert!(
        matches!(second, Err(Error::AlreadyExists(_))),
        "{:?}",
        second.err()
    );
    client.stop().expect("stop");
    handle.join().expect("join").expect("serve");
}

#[cfg(unix)]
#[test]
fn a_stale_socket_file_is_reclaimed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let endpoint = endpoint_in(dir.path());
    let Endpoint::Socket(path) = &endpoint else {
        unreachable!("unix uses socket paths");
    };
    std::fs::write(path, b"stale").expect("stale file");
    let handle = serve(&endpoint);
    let client = Client::connect(endpoint.clone());
    client.ping().expect("ping after reclaim");
    client.stop().expect("stop");
    handle.join().expect("join").expect("serve");
}

#[test]
fn discover_uses_the_state_file_and_removes_it_when_dead() {
    let dir = tempfile::tempdir().expect("tempdir");
    let endpoint = endpoint_in(dir.path());
    assert!(Client::discover(dir.path()).is_none(), "no state file");

    let handle = serve(&endpoint);
    let state = StateFile::in_dir(dir.path());
    state
        .write(&AgentState {
            endpoint: endpoint.to_string(),
            pid: std::process::id(),
            started: "2026-08-25T00:00:00Z".into(),
            version: "test".into(),
        })
        .expect("write state");
    let client = Client::discover(dir.path()).expect("agent found via agent.json");
    assert_eq!(client.endpoint(), &endpoint);

    client.stop().expect("stop");
    handle.join().expect("join").expect("serve");
    assert!(Client::discover(dir.path()).is_none(), "dead agent");
    assert!(!state.path().exists(), "stale state file removed");
}

/// A live agent that is merely slow (or wedged) must keep its `agent.json`:
/// removing it would orphan the process holding the endpoint. The listener here
/// never accepts, so the connect succeeds and the ping times out (~2 s).
#[cfg(unix)]
#[test]
fn discover_keeps_the_state_file_when_the_agent_does_not_answer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("wedged.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
    let state = StateFile::in_dir(dir.path());
    state
        .write(&AgentState {
            endpoint: path.display().to_string(),
            pid: std::process::id(),
            started: "2026-08-25T00:00:00Z".into(),
            version: "test".into(),
        })
        .expect("write state");

    assert!(Client::discover(dir.path()).is_none(), "nothing answered");
    assert!(
        state.path().exists(),
        "a timeout must not delete a live agent's state file"
    );
}

#[test]
fn discover_removes_a_corrupt_state_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = StateFile::in_dir(dir.path());
    state
        .write(&AgentState {
            endpoint: r"\\.\pipe\".into(),
            pid: std::process::id(),
            started: "2026-08-25T00:00:00Z".into(),
            version: "test".into(),
        })
        .expect("write state");
    assert!(
        Client::discover(dir.path()).is_none(),
        "endpoint field doesn't parse"
    );
    assert!(!state.path().exists(), "corrupt state file removed");
}

#[test]
fn requests_to_nothing_fail_fast_with_helper_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let client = Client::connect(endpoint_in(dir.path()));
    assert!(matches!(client.ping(), Err(Error::Helper(_))));
    assert!(matches!(client.get(&[0; 16]), Err(Error::Helper(_))));
    assert!(matches!(client.stop(), Err(Error::Helper(_))));
}
