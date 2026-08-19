//! Writing secret material to files.
//!
//! Everything wcm writes outside the vault (plaintext exports, `get --out-file`)
//! contains secrets, so the file is owner-only from the moment it is created —
//! never `0644` from the process umask, and never the mode an existing file
//! happened to carry.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use wcm_core::{Error, Result};

/// File mode of every file wcm writes secrets into (unix).
#[cfg(unix)]
pub const SECRET_FILE_MODE: u32 = 0o600;

/// Writes `data` to a file that must not exist yet.
///
/// [`Error::AlreadyExists`] when the path is taken (never overwrites).
pub fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    finish(path, opts, data)
}

/// Writes `data` to `path`, truncating an existing file.
pub fn write_truncate(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    finish(path, opts, data)
}

fn finish(path: &Path, opts: OpenOptions, data: &[u8]) -> Result<()> {
    let mut f = open(path, opts).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => Error::AlreadyExists(path.display().to_string()),
        _ => Error::Io(format!("{}: {e}", path.display())),
    })?;
    // The mode above only applies to a file this call created; a pre-existing
    // one keeps whatever it had, so tighten it explicitly.
    restrict(&f, path)?;
    f.write_all(data)
        .and_then(|_| f.sync_all())
        .map_err(|e| Error::Io(format!("{}: {e}", path.display())))
}

#[cfg(unix)]
fn open(path: &Path, mut opts: OpenOptions) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(SECRET_FILE_MODE);
    opts.open(path)
}

#[cfg(not(unix))]
fn open(path: &Path, opts: OpenOptions) -> std::io::Result<File> {
    // Windows inherits the ACL of the parent directory (per-user AppData or the
    // user's own working directory); there is no umask to correct.
    opts.open(path)
}

#[cfg(unix)]
fn restrict(f: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(std::fs::Permissions::from_mode(SECRET_FILE_MODE))
        .map_err(|e| Error::Io(format!("{}: {e}", path.display())))
}

#[cfg(not(unix))]
fn restrict(_f: &File, _path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn write_new_refuses_an_existing_file() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("x");
        write_new(&p, b"a").expect("write");
        assert!(matches!(write_new(&p, b"b"), Err(Error::AlreadyExists(_))));
        assert_eq!(std::fs::read(&p).expect("read"), b"a");
        assert!(matches!(
            write_new(&dir.path().join("no-dir").join("x"), b"a"),
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn write_truncate_replaces_content() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("x");
        write_truncate(&p, b"longer").expect("write");
        write_truncate(&p, b"ab").expect("write");
        assert_eq!(std::fs::read(&p).expect("read"), b"ab");
    }

    #[cfg(unix)]
    #[test]
    fn files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tmp");
        let new = dir.path().join("new");
        write_new(&new, b"a").expect("write");
        assert_eq!(mode_of(&new), SECRET_FILE_MODE);

        let existing = dir.path().join("existing");
        std::fs::write(&existing, b"old").expect("write");
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        write_truncate(&existing, b"new").expect("write");
        assert_eq!(mode_of(&existing), SECRET_FILE_MODE);
    }
}
