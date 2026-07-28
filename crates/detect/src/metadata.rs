//! Per-OS application metadata: name, version, identifier, and the primary
//! executable. macOS reads `Info.plist` (see [`crate::bundle`]); Windows reads
//! the PE version resource; Linux uses the name carried from the `.desktop`
//! entry by discovery.

use vfs::Platform;

use crate::app::DiscoveredApp;
use crate::bundle::BundleInfo;

/// Read whatever metadata the platform exposes for `app`, falling back to
/// fields already present on the [`DiscoveredApp`].
pub fn read(app: &DiscoveredApp) -> BundleInfo {
    match vfs::platform() {
        // The `.app` carries everything in Info.plist.
        Platform::Macos => {
            let mut info = crate::bundle::read(&app.root);
            if info.executable.is_none() {
                info.executable = app.executable.clone();
            }
            info
        }
        Platform::Windows => {
            let mut info = app
                .executable
                .as_deref()
                .map(windows::read_pe_metadata)
                .unwrap_or_default();
            info.display_name = info.display_name.or_else(|| app.name.clone());
            info.executable = info.executable.or_else(|| app.executable.clone());
            info
        }
        // `.desktop` `Name=` is the only reliable display name; the binary
        // rarely embeds one.
        Platform::Linux => BundleInfo {
            display_name: app.name.clone(),
            bundle_id: None,
            bundle_version: None,
            executable: app.executable.clone(),
        },
    }
}

/// Builds that can actually be handed a PE to read: a real Windows host, and
/// wasm (where the browser may be given a Windows app). macOS / Linux desktop
/// builds never meet one, so they skip `pelite` entirely.
mod windows {
    use std::path::Path;

    use crate::bundle::BundleInfo;

    /// Read the PE `VS_VERSIONINFO` resource for product name / version /
    /// company. Best effort — a binary with no version resource yields an
    /// empty [`BundleInfo`], as does a build without `pelite`.
    pub fn read_pe_metadata(exe: &Path) -> BundleInfo {
        let info = BundleInfo {
            executable: Some(exe.to_path_buf()),
            ..BundleInfo::default()
        };

        #[cfg(any(target_os = "windows", target_arch = "wasm32"))]
        {
            read_version_resource(exe, info)
        }
        #[cfg(not(any(target_os = "windows", target_arch = "wasm32")))]
        {
            info
        }
    }

    #[cfg(any(target_os = "windows", target_arch = "wasm32"))]
    fn read_version_resource(exe: &Path, mut info: BundleInfo) -> BundleInfo {
        let Some(bytes) = pe_bytes(exe) else {
            return info;
        };
        let Ok(image) = pelite::PeFile::from_bytes(bytes.as_ref()) else {
            return info;
        };
        let Ok(resources) = image.resources() else {
            return info;
        };
        let Ok(version_info) = resources.version_info() else {
            return info;
        };

        // Pick the first translation the file ships.
        if let Some(lang) = version_info.translation().first().copied() {
            let value = |key: &str| {
                version_info
                    .value(lang, key)
                    .filter(|s| !s.trim().is_empty())
            };

            let product = value("ProductName").or_else(|| value("FileDescription"));
            let company = value("CompanyName");
            info.display_name = product.clone();
            info.bundle_version = value("ProductVersion").or_else(|| value("FileVersion"));
            // Synthesise a stable-ish identifier from company + product.
            info.bundle_id = match (company, product) {
                (Some(c), Some(p)) => Some(format!("{c}.{p}")),
                (None, Some(p)) => Some(p),
                _ => None,
            };
        }

        info
    }

    /// Bytes to parse: a read-only mmap on a real Windows host (these binaries
    /// run to hundreds of MB and only the headers + resource tree are touched),
    /// an owned buffer from the in-memory upload tree on wasm.
    #[cfg(target_os = "windows")]
    fn pe_bytes(exe: &Path) -> Option<impl AsRef<[u8]>> {
        pelite::FileMap::open(exe).ok()
    }

    #[cfg(target_arch = "wasm32")]
    fn pe_bytes(exe: &Path) -> Option<impl AsRef<[u8]>> {
        vfs::read(exe).ok()
    }
}
