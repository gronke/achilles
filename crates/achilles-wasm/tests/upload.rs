//! Fixtures for the browser's "what did the user just hand me?" step.
//!
//! In the browser these run against an in-memory tree, but the module goes
//! through [`vfs`], so on native the same code walks a real temp directory —
//! which is what these tests build. No wasm toolchain needed.

use std::fs;
use std::path::{Path, PathBuf};

use achilles_wasm::upload::{find_app, locate_scan_target, sniff_platform};
use vfs::Platform;

fn tempdir(name: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let base = std::env::temp_dir().join(format!(
        "achilles-upload-{}-{}-{}",
        name,
        std::process::id(),
        nonce
    ));
    fs::create_dir_all(&base).unwrap();
    base
}

fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// A byte blob that starts with ELF magic and is `size` bytes long, so the
/// "largest binary wins" tie-break has something to compare.
fn elf(size: usize) -> Vec<u8> {
    let mut bytes = b"\x7fELF".to_vec();
    bytes.resize(size.max(4), 0);
    bytes
}

fn pe(size: usize) -> Vec<u8> {
    let mut bytes = b"MZ".to_vec();
    bytes.resize(size.max(2), 0);
    bytes
}

// ---- platform sniffing ------------------------------------------------

#[test]
fn sniffs_macos_from_a_dot_app_child() {
    let base = tempdir("sniff-macos");
    write(&base.join("Signal.app/Contents/Info.plist"), b"<plist/>");
    write(&base.join("Signal.app/Contents/MacOS/Signal"), &elf(64));

    assert_eq!(sniff_platform(&base), Platform::Macos);
    fs::remove_dir_all(&base).ok();
}

/// A zip made from *inside* the bundle puts `Contents/` at the archive root,
/// with no `.app` directory name left to recognise.
#[test]
fn sniffs_macos_from_a_bare_contents_dir() {
    let base = tempdir("sniff-contents");
    write(&base.join("Contents/Info.plist"), b"<plist/>");

    assert_eq!(sniff_platform(&base), Platform::Macos);
    fs::remove_dir_all(&base).ok();
}

#[test]
fn sniffs_windows_from_an_exe() {
    let base = tempdir("sniff-windows");
    write(&base.join("Slack/slack.exe"), &pe(4096));
    write(&base.join("Slack/ffmpeg.dll"), &pe(64));

    assert_eq!(sniff_platform(&base), Platform::Windows);
    fs::remove_dir_all(&base).ok();
}

/// Linux is the fallback: an ELF binary plus sibling `.so`s has no marker of
/// its own, only the absence of the other two.
#[test]
fn sniffs_linux_from_an_elf_tree() {
    let base = tempdir("sniff-linux");
    write(&base.join("slack/slack"), &elf(4096));
    write(&base.join("slack/libffmpeg.so"), &elf(64));

    assert_eq!(sniff_platform(&base), Platform::Linux);
    fs::remove_dir_all(&base).ok();
}

// ---- locating the app + its executable --------------------------------

#[test]
fn finds_the_macos_bundle_root() {
    let base = tempdir("find-macos");
    write(&base.join("Signal.app/Contents/Info.plist"), b"<plist/>");

    let app = find_app(&base, Platform::Macos).expect("bundle should be found");
    assert_eq!(app.path, base.join("Signal.app"));
    assert_eq!(app.root, base.join("Signal.app"));
    // macOS resolves the executable from Info.plist's CFBundleExecutable.
    assert_eq!(app.executable, None);
    fs::remove_dir_all(&base).ok();
}

/// The picked folder *is* the bundle — the common case for both the folder
/// picker and a drag-dropped `.app`.
#[test]
fn treats_a_picked_bundle_as_the_app() {
    let base = tempdir("picked-bundle");
    let bundle = base.join("Signal.app");
    write(&bundle.join("Contents/Info.plist"), b"<plist/>");

    let app = find_app(&bundle, Platform::Macos).expect("the picked bundle is the app");
    assert_eq!(app.root, bundle);
    fs::remove_dir_all(&base).ok();
}

/// The UI only unwraps `.app` children one level down, so a picked folder may
/// still wrap the bundle deeper. Analysing the picked folder itself would read
/// a non-existent `Contents/Info.plist` and report an app with nothing in it.
#[test]
fn finds_a_bundle_nested_below_the_picked_root() {
    let base = tempdir("find-nested");
    write(&base.join("Apps/Signal.app/Contents/Info.plist"), b"<plist/>");

    let app = find_app(&base, Platform::Macos).expect("nested bundle should be found");
    assert_eq!(app.root, base.join("Apps/Signal.app"));
    fs::remove_dir_all(&base).ok();
}

/// A folder holding no bundle must report nothing rather than describing the
/// folder itself as an app.
#[test]
fn reports_no_bundle_when_the_folder_holds_none() {
    let base = tempdir("find-no-bundle");
    write(&base.join("notes.txt"), b"hello");

    assert!(find_app(&base, Platform::Macos).is_none());
    fs::remove_dir_all(&base).ok();
}

/// The zip wraps the app in a folder, and the folder holds several `.exe`s.
/// The one named after its directory is the app; the rest are helpers.
#[test]
fn finds_the_windows_executable_by_name() {
    let base = tempdir("find-windows");
    let root = base.join("Slack");
    write(&root.join("slack.exe"), &pe(1024));
    // Bigger, but an updater — must not win.
    write(&root.join("Update.exe"), &pe(8192));
    write(&root.join("squirrel.exe"), &pe(8192));
    write(&root.join("resources/app.asar"), b"asar");

    let app = find_app(&base, Platform::Windows).expect("app should be found");
    assert_eq!(app.root, root);
    assert_eq!(
        app.executable.as_deref(),
        Some(root.join("slack.exe").as_path())
    );
    // Windows keys an app on its executable, as desktop discovery does.
    assert_eq!(app.path, root.join("slack.exe"));
    assert_eq!(app.name.as_deref(), Some("Slack"));
    fs::remove_dir_all(&base).ok();
}

/// Nothing is named after the directory, so the largest non-helper binary wins
/// — the main binary dwarfs the helpers it ships beside.
#[test]
fn falls_back_to_the_largest_executable() {
    let base = tempdir("find-largest");
    write(&base.join("bin/helper.exe"), &pe(128));
    write(&base.join("bin/main-app.exe"), &pe(65536));

    let app = find_app(&base, Platform::Windows).expect("app should be found");
    assert_eq!(
        app.executable.as_deref(),
        Some(base.join("bin/main-app.exe").as_path())
    );
    fs::remove_dir_all(&base).ok();
}

#[test]
fn finds_the_linux_executable_and_skips_shared_objects() {
    let base = tempdir("find-linux");
    let root = base.join("obsidian");
    // Larger than the binary, but a shared object is never the entry point.
    write(&root.join("libffmpeg.so"), &elf(65536));
    write(&root.join("libEGL.so.1"), &elf(65536));
    write(&root.join("obsidian"), &elf(4096));
    write(&root.join("chrome-sandbox"), &elf(32768));
    write(&root.join("resources.pak"), &[0u8; 65536]);

    let app = find_app(&base, Platform::Linux).expect("app should be found");
    assert_eq!(app.root, root);
    assert_eq!(
        app.executable.as_deref(),
        Some(root.join("obsidian").as_path())
    );
    fs::remove_dir_all(&base).ok();
}

/// A non-ELF file must never be mistaken for the executable, however large.
#[test]
fn linux_ignores_non_elf_files() {
    let base = tempdir("find-linux-nonelf");
    write(&base.join("app/resources.pak"), &[0u8; 65536]);
    write(&base.join("app/README"), b"hello");

    assert!(find_app(&base, Platform::Linux).is_none());
    fs::remove_dir_all(&base).ok();
}

/// Squirrel installs leave only `Update.exe` at the root and put the real app
/// in a versioned subdirectory, so the search has to descend past a directory
/// whose own executables were all filtered out as helpers.
#[test]
fn descends_past_a_squirrel_stub_root() {
    let base = tempdir("find-squirrel");
    write(&base.join("Update.exe"), &pe(8192));
    write(&base.join("packages/full.nupkg"), b"nupkg");
    write(&base.join("app-1.2.3/gitkraken.exe"), &pe(4096));

    let app = find_app(&base, Platform::Windows).expect("app should be found");
    assert_eq!(app.root, base.join("app-1.2.3"));
    assert_eq!(
        app.executable.as_deref(),
        Some(base.join("app-1.2.3/gitkraken.exe").as_path())
    );
    fs::remove_dir_all(&base).ok();
}

// ---- static-scan target ------------------------------------------------

#[test]
fn locates_the_asar_per_platform() {
    let base = tempdir("asar");

    let mac = base.join("Foo.app");
    write(&mac.join("Contents/Resources/app.asar"), b"asar");
    assert_eq!(
        locate_scan_target(&mac, Platform::Macos),
        Some(mac.join("Contents/Resources/app.asar"))
    );
    // The bundle layout's path must not be found under the portable one.
    assert_eq!(locate_scan_target(&mac, Platform::Windows), None);

    let win = base.join("Foo");
    write(&win.join("resources/app.asar"), b"asar");
    assert_eq!(
        locate_scan_target(&win, Platform::Windows),
        Some(win.join("resources/app.asar"))
    );
    assert_eq!(
        locate_scan_target(&win, Platform::Linux),
        Some(win.join("resources/app.asar"))
    );

    fs::remove_dir_all(&base).ok();
}

/// Apps that ship `resources/app/` unpacked (VS Code) have no archive to read,
/// so the scan targets the directory instead.
#[test]
fn locates_an_unpacked_app_directory() {
    let base = tempdir("unpacked");
    let root = base.join("VSCode");
    write(&root.join("resources/app/package.json"), b"{}");

    assert_eq!(
        locate_scan_target(&root, Platform::Linux),
        Some(root.join("resources/app"))
    );
    fs::remove_dir_all(&base).ok();
}
