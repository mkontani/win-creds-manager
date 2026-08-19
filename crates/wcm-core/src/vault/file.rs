//! Atomic vault file I/O: read, locked write with `.bak`, generation check.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Reads the whole vault file; `NotInitialized` if it does not exist.
pub fn read_all(path: &Path) -> Result<Vec<u8>> {
    match fs::read(path) {
        Ok(b) => Ok(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(Error::NotInitialized(path.display().to_string()))
        }
        Err(e) => Err(Error::Io(format!("{}: {e}", path.display()))),
    }
}

/// Path of the lock file next to the vault.
pub fn lock_path(path: &Path) -> PathBuf {
    with_suffix(path, ".lock")
}

/// Path of the backup of the previous generation.
pub fn backup_path(path: &Path) -> PathBuf {
    with_suffix(path, ".bak")
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push(suffix);
    path.with_file_name(name)
}

/// Acquires an exclusive advisory lock on `<vault>.lock` (blocking).
///
/// The lock is released when the returned guard is dropped.
pub fn lock(path: &Path) -> Result<WriteLockGuard> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| Error::Io(format!("create {}: {e}", parent.display())))?;
        }
    }
    let lp = lock_path(path);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lp)
        .map_err(|e| Error::Io(format!("open lock {}: {e}", lp.display())))?;
    file.lock()
        .map_err(|e| Error::Io(format!("lock {}: {e}", lp.display())))?;
    Ok(WriteLockGuard { file })
}

/// RAII guard for the vault write lock.
pub struct WriteLockGuard {
    file: File,
}

impl Drop for WriteLockGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Atomically replaces `path` with `data`: temp file in the same directory,
/// fsync, best-effort copy of the previous file to `.bak`, then rename.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    fs::create_dir_all(&dir).map_err(|e| Error::Io(format!("create {}: {e}", dir.display())))?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".vault-")
        .suffix(".tmp")
        .tempfile_in(&dir)
        .map_err(|e| Error::Io(format!("temp file in {}: {e}", dir.display())))?;
    tmp.write_all(data)
        .map_err(|e| Error::Io(format!("write temp: {e}")))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| Error::Io(format!("fsync temp: {e}")))?;
    if path.exists() {
        let _ = fs::copy(path, backup_path(path));
    }
    tmp.persist(path)
        .map_err(|e| Error::Io(format!("replace {}: {}", path.display(), e.error)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_creates_backup_and_replaces() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("sub").join("vault.wcm");
        write_atomic(&p, b"one").expect("write");
        assert_eq!(fs::read(&p).expect("read"), b"one");
        assert!(!backup_path(&p).exists());
        write_atomic(&p, b"two").expect("write");
        assert_eq!(fs::read(&p).expect("read"), b"two");
        assert_eq!(fs::read(backup_path(&p)).expect("bak"), b"one");
        assert!(fs::read_dir(p.parent().expect("parent"))
            .expect("dir")
            .all(|e| {
                !e.expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            }));
    }

    #[test]
    fn read_all_reports_not_initialized() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("missing.wcm");
        assert!(matches!(read_all(&p), Err(Error::NotInitialized(_))));
        fs::write(&p, b"x").expect("w");
        assert_eq!(read_all(&p).expect("r"), b"x");
    }

    #[test]
    fn lock_can_be_taken_and_released() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("vault.wcm");
        {
            let _g = lock(&p).expect("lock");
            assert!(lock_path(&p).exists());
        }
        let _g2 = lock(&p).expect("relock");
        assert_eq!(
            lock_path(&p)
                .file_name()
                .map(|s| s.to_string_lossy().to_string()),
            Some("vault.wcm.lock".into())
        );
        assert_eq!(
            backup_path(&p)
                .file_name()
                .map(|s| s.to_string_lossy().to_string()),
            Some("vault.wcm.bak".into())
        );
    }
}
