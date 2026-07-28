//! Work out *what* the browser was handed: which OS's layout the uploaded tree
//! follows, where the application root sits inside it, and which file is the
//! primary executable.
//!
//! On the desktop this is discovery's job — `/Applications`, the Start Menu,
//! `.desktop` entries — and each platform's scanner answers it with OS-specific
//! knowledge. In the browser there is no discovery: there is a directory the
//! user dropped, and it may be a macOS `.app`, a Windows install folder, or a
//! Linux app tree. So we infer the same three facts from the tree's own shape.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use detect::DiscoveredApp;
use vfs::Platform;

/// How far below the upload root to look for the application. Deep enough for
/// a zip that wraps the app in a folder or two (`MyApp/app-1.2.3/…`), shallow
/// enough that we never walk a whole Electron `resources/` tree.
const MAX_DEPTH: u32 = 4;

const ELF_MAGIC: &[u8] = b"\x7fELF";
const PE_MAGIC: &[u8] = b"MZ";

/// Windows binaries that ship *beside* the app but aren't it — updaters,
/// installers, and Chromium's out-of-process helpers. Matched on the file stem.
const WINDOWS_HELPERS: &[&str] = &[
    "update",
    "squirrel",
    "setup",
    "installer",
    "uninstall",
    "elevate",
    "notification_helper",
    "chrome_pwa_launcher",
    "crashpad_handler",
    "chrome_crashpad_handler",
];

/// The Linux equivalents.
const LINUX_HELPERS: &[&str] = &[
    "chrome-sandbox",
    "crashpad_handler",
    "chrome_crashpad_handler",
];

/// Guess which platform's application layout the tree under `base` follows.
///
/// The markers are near-disjoint in practice — a `.app` never contains a
/// `.exe`, a Windows install never contains `Contents/Info.plist` — so a single
/// strong hit decides it. Linux is the fallback: an app that is just an ELF
/// binary plus sibling files has no marker of its own to find.
pub fn sniff_platform(base: &Path) -> Platform {
    // A zip made from *inside* a `.app` puts `Contents/` at the archive root.
    if vfs::is_file(base.join("Contents/Info.plist")) {
        return Platform::Macos;
    }

    let mut saw_pe = false;
    let mut queue = VecDeque::from([(base.to_path_buf(), 0u32)]);
    while let Some((dir, depth)) = queue.pop_front() {
        let Ok(entries) = vfs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = file_name_lower(&path);
            if vfs::is_dir(&path) {
                if name.ends_with(".app") || vfs::is_file(path.join("Contents/Info.plist")) {
                    return Platform::Macos;
                }
                if depth < MAX_DEPTH {
                    queue.push_back((path, depth + 1));
                }
                continue;
            }
            if name.ends_with(".exe") || name.ends_with(".dll") {
                saw_pe = true;
            } else if !saw_pe && has_magic(&path, PE_MAGIC) {
                // An extension-less PE is unusual but cheap to rule in.
                saw_pe = true;
            }
        }
    }

    if saw_pe {
        Platform::Windows
    } else {
        Platform::Linux
    }
}

/// Locate the application under `base` and describe it the way desktop
/// discovery would.
///
/// Both entry points use this — the unpacked zip, and the streaming path where
/// the caller enumerated one directory it believes *is* the app. Neither can
/// assume `base` is the application root: a zip may wrap it in a folder or two,
/// and a picked folder may hold the `.app` deeper than the one level the caller
/// unwraps.
///
/// `None` when nothing app-shaped was found. The browser can't know that before
/// reading: a Windows or Linux folder is only recognisable as an app by the
/// binary inside it, so "the user chose their Documents folder" and "the user
/// chose an app" look identical until we look. Saying nothing was found beats
/// reporting an empty app.
pub fn find_app(base: &Path, platform: Platform) -> Option<DiscoveredApp> {
    if platform.is_bundle() {
        find_bundle(base)
    } else {
        find_portable(base, platform)
    }
}

/// A single uploaded binary (a bare `.exe` or ELF, no surrounding tree). There
/// are no sibling files to probe, so detection rests entirely on what the
/// binary itself carries: its import table and embedded version strings.
pub fn single_binary(path: &Path) -> DiscoveredApp {
    DiscoveredApp {
        path: path.to_path_buf(),
        root: path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| path.to_path_buf()),
        executable: Some(path.to_path_buf()),
        name: path.file_name().map(|n| n.to_string_lossy().into_owned()),
    }
}

/// Breadth-first search for the shallowest directory holding a plausible main
/// executable. Shallowest wins because that's where the app's own binary sits;
/// anything deeper is a helper or a bundled runtime.
fn find_portable(base: &Path, platform: Platform) -> Option<DiscoveredApp> {
    let mut queue = VecDeque::from([(base.to_path_buf(), 0u32)]);
    while let Some((dir, depth)) = queue.pop_front() {
        if let Some(executable) = pick_executable(&dir, platform) {
            return Some(DiscoveredApp {
                // Windows / Linux key an app on its executable, as discovery does.
                path: executable.clone(),
                name: dir_name(&dir),
                root: dir,
                executable: Some(executable),
            });
        }
        if depth >= MAX_DEPTH {
            continue;
        }
        if let Ok(entries) = vfs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if vfs::is_dir(&path) {
                    queue.push_back((path, depth + 1));
                }
            }
        }
    }
    None
}

/// The most plausible main executable directly inside `dir`, or `None` if it
/// holds no candidates. Prefers a binary named after its directory (`Slack/
/// slack.exe`), then the largest one — the main binary dwarfs its helpers.
fn pick_executable(dir: &Path, platform: Platform) -> Option<PathBuf> {
    let dir_stem = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    let mut best: Option<(u8, u64, PathBuf)> = None;
    for entry in vfs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if !vfs::is_file(&path) {
            continue;
        }
        let name = file_name_lower(&path);
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();

        let is_candidate = match platform {
            Platform::Windows => name.ends_with(".exe"),
            // Shared objects are never the entry point; everything else has to
            // prove itself by carrying ELF magic.
            _ => !name.ends_with(".so") && !name.contains(".so.") && has_magic(&path, ELF_MAGIC),
        };
        if !is_candidate || is_helper(&stem, platform) {
            continue;
        }

        let size = vfs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let score = u8::from(stem == dir_stem);
        if best
            .as_ref()
            .map(|(bs, bz, _)| (score, size) > (*bs, *bz))
            .unwrap_or(true)
        {
            best = Some((score, size, path));
        }
    }
    best.map(|(_, _, path)| path)
}

fn is_helper(stem: &str, platform: Platform) -> bool {
    let helpers = match platform {
        Platform::Windows => WINDOWS_HELPERS,
        _ => LINUX_HELPERS,
    };
    helpers.contains(&stem)
}

/// Locate the `.app` bundle root within an unpacked upload.
fn find_bundle(base: &Path) -> Option<DiscoveredApp> {
    let bundle = bundle_root(base)?;
    Some(DiscoveredApp {
        path: bundle.clone(),
        root: bundle,
        executable: None,
        name: None,
    })
}

fn bundle_root(base: &Path) -> Option<PathBuf> {
    // The zip was created from *inside* the `.app` (its `Contents/` sits at the
    // archive root): the scan root itself is the bundle.
    if vfs::is_dir(base.join("Contents")) {
        return Some(base.to_path_buf());
    }

    let mut queue = VecDeque::from([(base.to_path_buf(), 0u32)]);
    while let Some((dir, depth)) = queue.pop_front() {
        let Ok(entries) = vfs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !vfs::is_dir(&path) {
                continue;
            }
            if file_name_lower(&path).ends_with(".app")
                || vfs::is_file(path.join("Contents/Info.plist"))
            {
                return Some(path);
            }
            if depth < MAX_DEPTH {
                queue.push_back((path, depth + 1));
            }
        }
    }
    None
}

/// Where the app's `app.asar` (or unpacked `app/` directory) lives, for the
/// static rule scan. `Contents/Resources` under the bundle layout, `resources`
/// otherwise — the same split [`detect`] uses internally.
pub fn locate_scan_target(root: &Path, platform: Platform) -> Option<PathBuf> {
    let resources = if platform.is_bundle() {
        root.join("Contents/Resources")
    } else {
        root.join("resources")
    };

    for name in ["app.asar", "electron.asar", "default_app.asar"] {
        let candidate = resources.join(name);
        if vfs::is_file(&candidate) {
            return Some(candidate);
        }
    }
    // Unpacked apps (VS Code and friends) ship `resources/app/` as plain files.
    let unpacked = resources.join("app");
    if vfs::is_file(unpacked.join("package.json")) {
        return Some(unpacked);
    }
    None
}

/// True if the file starts with `magic`. Reads only the prefix, so it stays
/// cheap to run across every file in a directory.
fn has_magic(path: &Path, magic: &[u8]) -> bool {
    vfs::read_prefix(path, magic.len())
        .map(|prefix| prefix == magic)
        .unwrap_or(false)
}

fn file_name_lower(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

fn dir_name(dir: &Path) -> Option<String> {
    dir.file_name().map(|n| n.to_string_lossy().into_owned())
}
