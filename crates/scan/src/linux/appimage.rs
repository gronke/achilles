//! Find AppImages the desktop menu doesn't know about.
//!
//! An AppImage is a single executable file the user downloads and runs. Unless
//! something (AppImageLauncher, or the app itself on first launch) registers a
//! `.desktop` entry for it, it is invisible to the menu — and so to the rest of
//! discovery, which reads the menu. Yet it is exactly the kind of app worth
//! looking at: shipped outside any package manager, updated by the vendor, and
//! very often Electron.
//!
//! So the standard download locations get swept directly. Files already reached
//! through a menu entry are filtered out by the caller, which dedups on path.

use std::path::{Path, PathBuf};

use detect::DiscoveredApp;

/// Depth of the sweep. AppImages sit directly in these directories; going
/// deeper would turn `~/Downloads` into a recursive walk of everything the user
/// has ever unpacked.
const MAX_DEPTH: u32 = 2;

/// Where people keep AppImages: the conventional integrated location first
/// (AppImageLauncher moves them to `~/Applications`), then the places a
/// downloaded one sits before anyone moves it.
fn sweep_dirs() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    [
        "Applications",
        ".local/bin",
        ".local/share/applications",
        "bin",
        "Downloads",
        "Desktop",
        "opt",
    ]
    .iter()
    .map(|d| home.join(d))
    .collect()
}

/// Every AppImage found in the sweep directories.
pub(super) fn discover() -> Vec<DiscoveredApp> {
    let mut found = Vec::new();
    for dir in sweep_dirs() {
        collect(&dir, 0, &mut found);
    }
    found.sort_by(|a, b| a.path.cmp(&b.path));
    found.dedup_by(|a, b| a.path == b.path);
    found
}

fn collect(dir: &Path, depth: u32, out: &mut Vec<DiscoveredApp>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            if depth < MAX_DEPTH {
                collect(&path, depth + 1, out);
            }
            continue;
        }
        // Follow a symlinked AppImage to the file itself, so the same app found
        // through a link and directly dedups to one entry.
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        if !is_appimage(&path) {
            continue;
        }
        out.push(DiscoveredApp {
            name: path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .or_else(|| Some("AppImage".to_string())),
            // The file is the identity, as it is for any other Linux app; the
            // root and executable are filled in by detection, once the payload
            // has been expanded.
            root: path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| path.clone()),
            executable: Some(path.clone()),
            path,
        });
    }
}

/// True for a file that is really an AppImage — named like one *and* carrying
/// the format's magic, so a renamed download or a stray `.appimage` text file
/// can't enter the scan as an application.
fn is_appimage(path: &Path) -> bool {
    let named = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("appimage"))
        .unwrap_or(false);
    if !named {
        return false;
    }
    crate::linux::read_prefix(path, 512)
        .map(|bytes| pkg::sniff(&bytes, "x.appimage") == Some(pkg::Format::AppImage))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file that is named like an AppImage but isn't one must not be reported
    /// as an app: discovery feeding it to detection would be a wasted expansion
    /// at best, and a confusing entry in the list at worst.
    #[test]
    fn only_real_appimages_pass_the_magic_check() {
        let dir = std::env::temp_dir().join(format!("scan-appimage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let text = dir.join("notes.AppImage");
        std::fs::write(&text, b"not actually an app").unwrap();
        assert!(!is_appimage(&text));

        // An ELF with the type-2 marker in `e_ident`'s padding.
        let real = dir.join("Fixture-1.0.AppImage");
        let mut bytes = vec![0u8; 512];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[8..11].copy_from_slice(&[0x41, 0x49, 0x02]);
        std::fs::write(&real, &bytes).unwrap();
        assert!(is_appimage(&real));

        // The extension still has to be there — an ordinary ELF is not one.
        let plain = dir.join("binary");
        std::fs::write(&plain, &bytes).unwrap();
        assert!(!is_appimage(&plain));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
