//! Platform-neutral description of a discovered application and the on-disk
//! [`Layout`] probes use to find runtime markers.
//!
//! macOS apps are `.app` *directories* with everything under `Contents/`.
//! Windows and Linux apps are an executable plus sibling files (DLLs / shared
//! objects / a `resources/` dir). [`Layout`] hides that difference: a probe
//! asks "where do frameworks live?" / "is library X present?" instead of
//! hardcoding `Contents/Frameworks/...`.
//!
//! Which convention applies comes from [`vfs::platform`] — the host OS on the
//! desktop (a compile-time constant, so the other arms fold away), and whatever
//! the browser was handed on wasm.

use std::path::{Path, PathBuf};

use vfs::Platform;

/// One application found by discovery, in a form every consumer
/// (`detect` / `app-audit` / `sideeffects`) can use without re-deriving
/// platform paths.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscoveredApp {
    /// Stable identity and what the UI shows / keys on.
    ///
    /// * macOS: the `.app` bundle directory.
    /// * Windows / Linux: the primary executable.
    pub path: PathBuf,
    /// Directory to look in for sibling runtime files.
    ///
    /// * macOS: the `.app` directory (probes join `Contents/...`).
    /// * Windows / Linux: the directory containing the executable.
    pub root: PathBuf,
    /// Primary executable to string-scan, if known up front. On macOS this is
    /// usually `None` and resolved from `Info.plist`'s `CFBundleExecutable`.
    pub executable: Option<PathBuf>,
    /// Human-facing name from discovery (`.desktop` `Name=`, `.lnk` title).
    /// macOS leaves this `None` and reads it from `Info.plist` instead.
    pub name: Option<String>,
}

impl DiscoveredApp {
    /// Build a [`DiscoveredApp`] from a single user-supplied path (the
    /// "open this specific app" case). The path means different things per
    /// platform: a `.app` directory on macOS, an executable elsewhere.
    pub fn from_path(path: &Path) -> Self {
        if vfs::platform().is_bundle() {
            return DiscoveredApp {
                path: path.to_path_buf(),
                root: path.to_path_buf(),
                executable: None,
                name: None,
            };
        }
        let root = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| path.to_path_buf());
        DiscoveredApp {
            path: path.to_path_buf(),
            root,
            executable: Some(path.to_path_buf()),
            name: None,
        }
    }
}

/// Windows Squirrel installs (GitKraken, older Slack/Discord, …) drop a small
/// launcher *stub* at the install root next to `Update.exe`, while the real
/// application lives in versioned `app-<version>` subdirectories. The Start Menu
/// shortcut targets the stub, so discovery hands us a root with no runtime
/// markers and the app gets misclassified as `Native`.
///
/// If `app` looks like such a stub, return a copy whose `root` + `executable`
/// point at the newest `app-<version>` dir so framework probes see the real
/// binary and its `resources/`. `path` (the stable identity the UI keys on) is
/// preserved, so it survives version bumps. Returns `None` when this isn't a
/// Squirrel layout, leaving the app untouched.
pub(crate) fn redirect_squirrel_stub(app: &DiscoveredApp) -> Option<DiscoveredApp> {
    // A genuine Squirrel root has `Update.exe` sitting beside the stub.
    if !vfs::is_file(app.root.join("Update.exe")) {
        return None;
    }
    let versioned = newest_squirrel_app_dir(&app.root)?;

    // Map the stub to its namesake inside the versioned dir (GitKraken's stub
    // and real binary are both `gitkraken.exe`); fall back to the first plain
    // executable there so detection still has a binary to scan.
    let executable = app
        .executable
        .as_ref()
        .and_then(|e| e.file_name())
        .map(|n| versioned.join(n))
        .filter(|p| vfs::is_file(p))
        .or_else(|| first_versioned_exe(&versioned));

    Some(DiscoveredApp {
        path: app.path.clone(),
        root: versioned,
        executable,
        name: app.name.clone(),
    })
}

/// Newest `app-<version>` subdirectory of a Squirrel install root, compared by
/// dotted numeric version (so `app-12.10.0` beats `app-12.2.0`).
fn newest_squirrel_app_dir(root: &Path) -> Option<PathBuf> {
    let mut best: Option<(Vec<u64>, PathBuf)> = None;
    for entry in vfs::read_dir(root).ok()?.flatten() {
        let path = entry.path();
        if !vfs::is_dir(&path) {
            continue;
        }
        let name = entry.file_name();
        let Some(version) = name
            .to_string_lossy()
            .strip_prefix("app-")
            .map(str::to_owned)
        else {
            continue;
        };
        let key: Vec<u64> = version.split('.').map(|p| p.parse().unwrap_or(0)).collect();
        if best.as_ref().map(|(b, _)| key > *b).unwrap_or(true) {
            best = Some((key, path));
        }
    }
    best.map(|(_, p)| p)
}

/// First non-helper `.exe` directly inside a Squirrel versioned dir, skipping
/// the bundled `squirrel.exe` / `Update.exe` maintenance binaries.
fn first_versioned_exe(dir: &Path) -> Option<PathBuf> {
    for entry in vfs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e.eq_ignore_ascii_case("exe")) != Some(true) {
            continue;
        }
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if stem == "squirrel" || stem == "update" {
            continue;
        }
        return Some(path);
    }
    None
}

/// Resolved on-disk layout for a discovered app. Probes consult this rather
/// than joining platform paths themselves.
pub(crate) struct Layout {
    /// Sibling-files root (`DiscoveredApp::root`).
    pub root: PathBuf,
    /// Effective primary executable, after resolving `CFBundleExecutable` on
    /// macOS. May still be `None` if nothing was declared / found.
    pub executable: Option<PathBuf>,
    /// Layout convention this app follows. Captured once at construction so a
    /// probe can't observe it changing mid-detection.
    pub platform: Platform,
    /// Lower-cased basenames of the libraries the executable imports
    /// (ELF `DT_NEEDED` / PE import table). Empty under the bundle layout or
    /// when the binary can't be parsed. Lazily filled by [`Layout::imports`].
    imports: std::cell::OnceCell<Vec<String>>,
}

impl Layout {
    pub(crate) fn new(root: PathBuf, executable: Option<PathBuf>) -> Self {
        Layout {
            root,
            executable,
            platform: vfs::platform(),
            imports: std::cell::OnceCell::new(),
        }
    }

    /// True when this app uses the macOS `.app` bundle layout.
    pub(crate) fn is_bundle(&self) -> bool {
        self.platform.is_bundle()
    }

    /// Directory where shared frameworks / runtime libraries live.
    ///
    /// * macOS: `root/Contents/Frameworks`.
    /// * Windows / Linux: `root` (DLLs / `.so`s sit beside the executable).
    pub(crate) fn frameworks_dir(&self) -> PathBuf {
        if self.is_bundle() {
            self.root.join("Contents/Frameworks")
        } else {
            self.root.clone()
        }
    }

    /// Directory where bundled app resources (`app.asar`, `*.pak`) live.
    ///
    /// * macOS: `root/Contents/Resources`.
    /// * Windows / Linux: `root/resources`.
    pub(crate) fn resources_dir(&self) -> PathBuf {
        if self.is_bundle() {
            self.root.join("Contents/Resources")
        } else {
            self.root.join("resources")
        }
    }

    /// True if the executable imports a library whose name contains `needle`,
    /// or a sibling file in the app's *private* `root` (or `root/lib`) matches.
    /// Used by the portable probes to find `.dll` / `.so` framework markers
    /// whether bundled or system-linked.
    pub(crate) fn has_library(&self, needle: &str) -> bool {
        let needle = needle.to_ascii_lowercase();
        // The import table (DT_NEEDED / PE imports) is the reliable signal and
        // works for system-installed libraries.
        if self.imports().iter().any(|n| n.contains(&needle)) {
            return true;
        }
        self.find_file(&needle).is_some()
    }

    /// Path to the first sibling file in the app's private `root` / `root/lib`
    /// whose filename contains `needle` (case-insensitive). Skipped for shared
    /// system directories (`/usr/bin`, `/usr/lib`, …) where sibling files aren't
    /// the app's own and would cause false positives — there the import table is
    /// authoritative instead.
    pub(crate) fn find_file(&self, needle: &str) -> Option<PathBuf> {
        if is_system_dir(&self.root) {
            return None;
        }
        let needle = needle.to_ascii_lowercase();
        for dir in [self.root.clone(), self.root.join("lib")] {
            if let Ok(entries) = vfs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                    if name.contains(&needle) {
                        return Some(entry.path());
                    }
                }
            }
        }
        None
    }

    /// Lower-cased basenames of imported / needed libraries. Cached.
    fn imports(&self) -> &[String] {
        self.imports.get_or_init(|| {
            if self.is_bundle() {
                return Vec::new();
            }
            self.executable
                .as_deref()
                .map(read_imports)
                .unwrap_or_default()
        })
    }
}

/// Shared system directories whose sibling files belong to the OS, not the app
/// being probed. Scanning these for framework libraries yields false positives.
fn is_system_dir(dir: &Path) -> bool {
    const SYSTEM: &[&str] = &[
        "/",
        "/usr",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/usr/lib64",
        "/usr/local",
        "/usr/local/bin",
        "/usr/local/lib",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/opt",
        "/tmp",
        "/var",
    ];
    SYSTEM.iter().any(|s| dir == Path::new(s))
}

/// Read the dynamic libraries an executable imports (ELF `DT_NEEDED` on Linux,
/// the PE import table on Windows), returning lower-cased basenames. Best
/// effort: any parse failure yields an empty list.
fn read_imports(exe: &Path) -> Vec<String> {
    let Ok(data) = vfs::read(exe) else {
        return Vec::new();
    };
    let normalise = |lib: &str| {
        // ELF gives a bare soname (`libQt6Core.so.6`); PE gives a DLL name
        // (`Qt6Core.dll`). Normalise to a lower-cased basename.
        lib.rsplit(['/', '\\'])
            .next()
            .unwrap_or(lib)
            .to_ascii_lowercase()
    };
    match goblin::Object::parse(&data) {
        Ok(goblin::Object::Elf(elf)) => elf.libraries.iter().map(|l| normalise(l)).collect(),
        Ok(goblin::Object::PE(pe)) => pe.libraries.iter().map(|l| normalise(l)).collect(),
        _ => Vec::new(),
    }
}
