//! ssh-add integration helpers — TODO(agent): implement `ssh add/remove/pubkey`.

use std::path::{Path, PathBuf};

/// Locates `ssh-add` (explicit path, then PATH, then the Windows OpenSSH default).
pub fn find_ssh_add(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    let name = if cfg!(windows) {
        "ssh-add.exe"
    } else {
        "ssh-add"
    };
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let cand = dir.join(name);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    if cfg!(windows) {
        let p = PathBuf::from(r"C:\Windows\System32\OpenSSH\ssh-add.exe");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}
