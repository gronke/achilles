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

/// An AppImage is a single file: the application is a squashfs filesystem
/// appended to a runtime stub, so there is no directory to probe and the
/// binary's own bytes reveal nothing — everything that identifies the app is
/// compressed inside the payload.
///
/// If `app` points at one, expand it (once — the result is cached under
/// `~/.cache/achilles/packages`, see [`pkg::extract_cached`]) and return a copy
/// rooted in that tree. As with [`redirect_squirrel_stub`], `path` is preserved
/// as the identity the UI keys on, so it survives the app being updated in
/// place.
///
/// `None` when this isn't an AppImage or it couldn't be expanded — detection
/// then proceeds against the file itself and reports what little it can, which
/// beats failing the app outright.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn redirect_appimage(app: &DiscoveredApp) -> Option<DiscoveredApp> {
    if !vfs::is_file(&app.path) || !pkg::is_expandable(&app.path) {
        return None;
    }
    let payload = pkg::extract_cached(&app.path).ok()?;
    let executable = payload_executable(&payload);
    // The `.desktop` entry inside the AppImage is the app's own name for itself
    // ("Achilles"); discovery only had the file to go on, which for a swept
    // AppImage is a release filename ("Achilles_0.5.0_amd64").
    let name = payload_name(&payload).or_else(|| app.name.clone());
    // Root the app where its binary sits, as discovery does for any other Linux
    // app: that's where `resources/` and the sibling `.so`s are. For the usual
    // AppImage — binary at the top of the squashfs — that is the payload root
    // itself; for one that ships a `usr/`-shaped tree it is the directory
    // inside, which is where the app's own files actually are.
    let root = executable
        .as_deref()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or(payload);
    Some(DiscoveredApp {
        path: app.path.clone(),
        executable,
        root,
        name,
    })
}

/// The application binary inside an expanded package — an AppImage's squashfs
/// root, a snap's mount, a `.deb`'s installed tree, the payload of an upload.
///
/// `AppRun` is the AppImage entry point by definition of the format, so it wins
/// whenever it is a binary (or a symlink to one — [`vfs`] follows those). It is
/// often a shell script instead, and the other package formats have no
/// equivalent at all, so the fallback is the largest executable in the tree.
///
/// Size is the right tie-break here, and the reason the shallowest-first rule
/// used for an app *folder* is not: a package reproduces a slice of a
/// filesystem, so the shallowest binary is usually the `usr/bin` launcher while
/// the application sits in `opt/Foo` or `usr/lib/foo`. An application binary
/// dwarfs the stub that starts it, by a factor of thousands when it bundles a
/// runtime.
///
/// Goes through [`vfs`], so the desktop reads a real cache directory and the
/// browser reads the in-memory tree it unpacked an upload into.
pub fn payload_executable(root: &Path) -> Option<PathBuf> {
    let app_run = root.join("AppRun");
    if is_app_binary(&app_run) {
        return Some(app_run);
    }
    largest_executable(root)
}

/// What an expanded package calls itself, from the `.desktop` entry it ships.
///
/// Every package format carries one — it's how the app reaches the menu once
/// installed, and mandatory in an AppImage — and it holds the name a human
/// wrote (`Achilles`), which no path in the tree does. Naming the app after a
/// directory instead gets you `bin`, since a packaged binary usually sits in
/// `usr/bin`.
///
/// The conventional locations, in the order a payload is likely to use them:
/// the AppImage root, then the installed-tree path a `.deb`/`.rpm`/tarball
/// uses, then a snap's.
pub fn payload_name(root: &Path) -> Option<String> {
    [
        root.to_path_buf(),
        root.join("usr/share/applications"),
        root.join("share/applications"),
        root.join("meta/gui"),
    ]
    .into_iter()
    .find_map(|dir| desktop_entry_name(&dir))
}

/// The `Name=` of the first `.desktop` file directly inside `dir`.
fn desktop_entry_name(dir: &Path) -> Option<String> {
    let mut entries: Vec<PathBuf> = vfs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .map(|e| e.eq_ignore_ascii_case("desktop"))
                .unwrap_or(false)
        })
        .collect();
    // A payload may ship several (an app plus its URL handlers); sort so the
    // choice doesn't depend on directory order.
    entries.sort();

    entries.iter().find_map(|path| {
        let text = vfs::read_to_string(path).ok()?;
        let mut in_entry = false;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('[') && line.ends_with(']') {
                // Only the main group counts — an action group has a `Name`
                // too, and it names the action ("New Window"), not the app.
                in_entry = line == "[Desktop Entry]";
                continue;
            }
            // The unlocalised key only: `Name[de]` is a translation.
            if in_entry {
                if let Some(value) = line.strip_prefix("Name=") {
                    let value = value.trim();
                    if !value.is_empty() {
                        return Some(value.to_string());
                    }
                }
            }
        }
        None
    })
}

/// Helper binaries that ship beside an application but are not it.
const PAYLOAD_HELPERS: &[&str] = &[
    "chrome-sandbox",
    "crashpad_handler",
    "chrome_crashpad_handler",
    "apprun",
    "desktop-launch",
];

/// Depth and directory budget for the payload walk: an expanded package nests
/// as deep as a filesystem slice (`usr/lib/x86_64-linux-gnu/…`), and a package
/// with a big locale tree must not turn detection into a full disk walk.
const PAYLOAD_MAX_DEPTH: u32 = 8;
const PAYLOAD_MAX_DIRS: u32 = 20_000;

fn largest_executable(root: &Path) -> Option<PathBuf> {
    let mut best: Option<(u64, PathBuf)> = None;
    let mut queue = std::collections::VecDeque::from([(root.to_path_buf(), 0u32)]);
    let mut visited = 0u32;

    while let Some((dir, depth)) = queue.pop_front() {
        visited += 1;
        if visited > PAYLOAD_MAX_DIRS {
            break;
        }
        let Ok(entries) = vfs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // A package points several names at one binary (`usr/bin/foo`, the
            // `.build-id` entries); following those would root the app in
            // whichever directory happened to hold an alias.
            if entry.file_type().map(|t| t.is_symlink()).unwrap_or(false) {
                continue;
            }
            if vfs::is_dir(&path) {
                if depth < PAYLOAD_MAX_DEPTH {
                    queue.push_back((path, depth + 1));
                }
                continue;
            }
            if !is_app_binary(&path) {
                continue;
            }
            let size = vfs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if best.as_ref().map(|(b, _)| size > *b).unwrap_or(true) {
                best = Some((size, path));
            }
        }
    }
    best.map(|(_, path)| path)
}

/// True for a file that could be an application's main binary: an ELF that
/// isn't a shared object and isn't a known helper.
pub fn is_app_binary(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if name.ends_with(".so") || name.contains(".so.") {
        return false;
    }
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if PAYLOAD_HELPERS.contains(&stem.as_str()) {
        return false;
    }
    vfs::read_prefix(path, 4)
        .map(|p| p == b"\x7fELF")
        .unwrap_or(false)
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
