//! Which OS's application layout the analysis should assume.
//!
//! On the desktop this is simply the host OS, known at compile time — [`platform`]
//! is a `const fn`, so every `match vfs::platform()` in the analysis crates folds
//! to the host arm and the other layouts are optimised away.
//!
//! In the browser there is no host OS to speak of: the wasm entry point analyses
//! whatever the user dropped in, which may be a macOS `.app`, a Windows install
//! directory, or a Linux app tree. There the platform is *ambient state* set with
//! [`set_platform`] before analysis runs, alongside the [`MemTree`](crate::MemTree)
//! it describes — the tree and the layout convention that reads it belong
//! together, which is why this lives in `vfs`.

/// The application-layout convention the analysis crates should follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// `.app` directory: `Contents/{MacOS,Frameworks,Resources}` + `Info.plist`.
    Macos,
    /// Install directory: `.exe` + sibling `.dll`s + `resources/`.
    Windows,
    /// App directory: ELF binary + sibling `.so`s + `resources/`.
    Linux,
}

impl Platform {
    /// True for the macOS `.app` bundle layout, false for the "executable plus
    /// sibling files" layout Windows and Linux share. The single question most
    /// layout probes actually ask.
    pub const fn is_bundle(self) -> bool {
        matches!(self, Platform::Macos)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Platform::Macos => "macos",
            Platform::Windows => "windows",
            Platform::Linux => "linux",
        }
    }

    /// Parse a platform name (`"macos"` / `"windows"` / `"linux"`), as passed
    /// across the JS boundary. Case-insensitive; `None` if unrecognised.
    pub fn parse(name: &str) -> Option<Platform> {
        match name.trim().to_ascii_lowercase().as_str() {
            "macos" | "mac" | "osx" | "darwin" => Some(Platform::Macos),
            "windows" | "win" | "win32" => Some(Platform::Windows),
            "linux" => Some(Platform::Linux),
            _ => None,
        }
    }
}

/// The host OS's layout. Other unixes analyse like Linux — an ELF binary plus
/// sibling shared objects — which is what the portable path already assumed.
#[cfg(not(target_arch = "wasm32"))]
const HOST: Platform = if cfg!(target_os = "macos") {
    Platform::Macos
} else if cfg!(target_os = "windows") {
    Platform::Windows
} else {
    Platform::Linux
};

/// The layout the analysis should assume. A compile-time constant on native.
#[cfg(not(target_arch = "wasm32"))]
#[inline]
pub const fn platform() -> Platform {
    HOST
}

#[cfg(target_arch = "wasm32")]
mod ambient {
    use super::Platform;
    use std::cell::Cell;

    thread_local! {
        static PLATFORM: Cell<Platform> = const { Cell::new(Platform::Macos) };
    }

    /// The layout the analysis should assume for the ambient tree. Defaults to
    /// [`Platform::Macos`] until the entry point says otherwise.
    pub fn platform() -> Platform {
        PLATFORM.with(|p| p.get())
    }

    /// Declare the layout of the tree about to be analysed. Set this *before*
    /// running detection, next to [`set_ambient`](crate::set_ambient).
    pub fn set_platform(platform: Platform) {
        PLATFORM.with(|p| p.set(platform));
    }
}

#[cfg(target_arch = "wasm32")]
pub use ambient::{platform, set_platform};
