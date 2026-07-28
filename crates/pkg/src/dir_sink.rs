//! A [`Sink`] that writes an unpacked payload to a real directory.
//!
//! Used by the desktop build to expand an AppImage into a cache directory, so
//! the rest of Achilles — detection, the audit, the static scan — can walk it
//! like any other installed application.
//!
//! Symlinks are deliberately created *last*, by [`DirSink::finish`]. A package
//! that ships `lib -> /etc` followed by `lib/passwd` would otherwise have its
//! second entry written through the first, outside the extraction root. Holding
//! the links back means every file lands in a directory this sink created
//! itself.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{PkgError, Sink};

pub struct DirSink {
    root: PathBuf,
    /// Deferred until `finish`, see the module note.
    links: Vec<(PathBuf, PathBuf)>,
    /// Directory modes, applied on `finish`: a read-only directory can't be
    /// written into while the payload is still being unpacked.
    dir_modes: HashMap<PathBuf, u32>,
}

impl DirSink {
    /// Extract under `root`, which is created if it doesn't exist.
    pub fn new(root: impl Into<PathBuf>) -> Result<DirSink, PkgError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(DirSink {
            root,
            links: Vec::new(),
            dir_modes: HashMap::new(),
        })
    }

    /// Create the deferred symlinks and apply directory modes. Skipping a link
    /// whose path is already taken is deliberate: the file that's there was
    /// written from this same payload.
    pub fn finish(self) -> Result<(), PkgError> {
        for (path, target) in &self.links {
            if path.symlink_metadata().is_ok() {
                continue;
            }
            #[cfg(unix)]
            let _ = std::os::unix::fs::symlink(target, path);
            #[cfg(not(unix))]
            let _ = target;
        }
        for (path, mode) in &self.dir_modes {
            set_mode(path, *mode);
        }
        Ok(())
    }

    /// True if `path` is inside the extraction root. Paths arrive sanitised, so
    /// this only ever fires on a caller mistake — but the cost of being wrong
    /// here is writing outside the cache.
    fn contains(&self, path: &Path) -> bool {
        path.starts_with(&self.root)
    }
}

impl Sink for DirSink {
    fn dir(&mut self, path: &Path) -> Result<(), PkgError> {
        if !self.contains(path) {
            return Ok(());
        }
        fs::create_dir_all(path)?;
        Ok(())
    }

    fn file(&mut self, path: &Path, data: Vec<u8>, mode: u32) -> Result<(), PkgError> {
        if !self.contains(path) {
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, data)?;
        set_mode(path, mode);
        Ok(())
    }

    fn symlink(&mut self, path: &Path, target: &Path) -> Result<(), PkgError> {
        if !self.contains(path) {
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        self.links.push((path.to_path_buf(), target.to_path_buf()));
        Ok(())
    }
}

/// Best-effort mode application — the executable bit is what matters (the
/// detector and the audit look for it), and a filesystem that can't express it
/// is not a reason to fail the extraction.
fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Never leave a group/world-writable file behind, whatever the package
        // asked for: this tree is written into a cache the user's own tools
        // will read.
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o755));
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_symlink_cannot_be_used_to_write_outside_the_root() {
        let tmp = std::env::temp_dir().join(format!("pkg-dir-sink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let root = tmp.join("root");
        let outside = tmp.join("outside");
        fs::create_dir_all(&outside).unwrap();

        let mut sink = DirSink::new(&root).unwrap();
        // The attack shape: a link pointing out of the tree, then a file
        // written "through" it.
        sink.symlink(&root.join("lib"), &outside).unwrap();
        sink.file(&root.join("lib/passwd"), b"pwned".to_vec(), 0o644)
            .unwrap();
        sink.finish().unwrap();

        assert!(!outside.join("passwd").exists());
        assert_eq!(fs::read(root.join("lib/passwd")).unwrap(), b"pwned");
        // The link lost the race with the real directory, as intended.
        assert!(root.join("lib").is_dir());

        let _ = fs::remove_dir_all(&tmp);
    }
}
