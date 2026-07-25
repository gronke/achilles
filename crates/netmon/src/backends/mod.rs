//! OS capture backends behind the [`CaptureSource`](crate::source::CaptureSource)
//! trait, plus process enumeration (target picker) and PID-tree resolution.

use sysinfo::{ProcessesToUpdate, System};

use crate::model::RunningProcess;
use crate::source::{CaptureError, CaptureSource};

/// Platforms with a libpcap/Npcap capture backend.
#[cfg(target_os = "macos")]
mod pcap_backend;

/// macOS privileged-helper client (connects to the root daemon's socket).
#[cfg(target_os = "macos")]
mod helper;

/// True when a capture backend is compiled in for this build/OS.
#[cfg(target_os = "macos")]
const HAS_CAPTURE: bool = true;
#[cfg(not(target_os = "macos"))]
const HAS_CAPTURE: bool = false;

/// The capture backend for this platform (libpcap; macOS uses the `pktap`
/// interface for per-PID attribution). Returns [`CaptureError::Unavailable`]
/// when built without `capture` or on an unsupported OS.
pub fn default_source() -> Result<Box<dyn CaptureSource>, CaptureError> {
    // macOS: prefer the privileged helper (root, per-app attribution, no sudo)
    // when it's actually reachable; otherwise fall back to direct pcap. Probing
    // connectability (not mere socket-file presence) matters — a dead helper
    // leaves its socket file behind, and connecting to that would fail the whole
    // capture instead of falling back here.
    #[cfg(target_os = "macos")]
    {
        if helper_reachable() {
            Ok(Box::new(helper::HelperSource))
        } else {
            Ok(Box::new(pcap_backend::PcapSource::new()))
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(CaptureError::Unavailable(
            "packet capture is not available on this platform yet".into(),
        ))
    }
}

/// The direct (in-process) libpcap source, bypassing helper selection. Used by
/// the privileged helper binary itself (which must not recurse into the helper).
#[cfg(target_os = "macos")]
pub fn direct_capture_source() -> Box<dyn CaptureSource> {
    Box::new(pcap_backend::PcapSource::new())
}

/// Whether this build can capture traffic (for the UI to disable Record).
pub fn capture_available() -> bool {
    HAS_CAPTURE
}

/// Whether the privileged helper is actually reachable — the daemon is alive and
/// listening, not merely that a socket file exists. The app uses this to decide
/// whether the helper is serving vs. offering install/approval.
///
/// A Unix-socket file lingers on disk after its listener dies, so an
/// `exists()` check reports a dead helper as present — which is exactly what
/// made an unregistered helper keep showing as "active". Probe by connecting: a
/// live listener accepts instantly, a stale or absent socket fails at once
/// (`ECONNREFUSED` / `ENOENT`), so no timeout is needed.
pub fn helper_reachable() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::os::unix::net::UnixStream::connect(crate::wire::HELPER_SOCKET_PATH).is_ok()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// List running processes for the target picker (those with a resolvable name).
pub fn list_processes() -> Vec<RunningProcess> {
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut out: Vec<RunningProcess> = sys
        .processes()
        .iter()
        .map(|(pid, p)| RunningProcess {
            pid: pid.as_u32(),
            name: p.name().to_string_lossy().into_owned(),
            exe_path: p.exe().map(|e| e.to_string_lossy().into_owned()),
        })
        .filter(|p| !p.name.is_empty())
        .collect();
    out.sort_by_key(|p| p.name.to_lowercase());
    out
}

/// Resolve the PID set to capture: the root PID plus, if requested, all of its
/// descendants (so helper/renderer child processes are included).
#[cfg(target_os = "macos")]
pub(crate) fn collect_pids(filter: crate::source::PidFilter) -> std::collections::HashSet<u32> {
    let mut pids = std::collections::HashSet::new();
    pids.insert(filter.root_pid);
    if !filter.include_children {
        return pids;
    }
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    // Repeatedly absorb any process whose parent is already in the set.
    loop {
        let mut added = false;
        for (pid, proc_) in sys.processes() {
            let child = pid.as_u32();
            if pids.contains(&child) {
                continue;
            }
            if let Some(parent) = proc_.parent() {
                if pids.contains(&parent.as_u32()) {
                    pids.insert(child);
                    added = true;
                }
            }
        }
        if !added {
            break;
        }
    }
    pids
}
