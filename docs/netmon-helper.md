# Privileged capture helper (macOS)

Passive per-app packet capture on macOS uses the `pktap` interface, and creating
it (`SIOCIFCREATE`) is **root-only**. Rather than run Achilles itself as root, a
tiny **root helper daemon** does the capture and streams events back to the app
over a local socket. The helper is installed and launched via **`SMAppService`**,
which — unlike a Network Extension — needs **no special Apple entitlement**: it
works within the existing Developer-ID signing + notarization that
`.github/workflows/publish.yml` already performs, and ships inside the `.app` so
the Tauri updater delivers helper updates automatically.

## Architecture

```
Achilles.app (user)                     achilles-netmon-helper (root LaunchDaemon)
  netmon::HelperSource  ──connect──▶  /var/run/dev.crabnebula.achilles.netmon.sock
     └ send PidFilter ──────────────▶  reads filter, captures target via pktap
     ◀───────────────── CapturedEvent  streams length-prefixed JSON frames
```

- Wire protocol: `crates/netmon/src/wire.rs` (length-prefixed JSON frames).
- App side: `netmon::backends::helper::HelperSource` (connects, sends
  `PidFilter`, yields `CapturedEvent`s). `default_source()` prefers it whenever
  the socket exists, else falls back to direct pcap (needs sudo) / host-wide.
- Helper: `crates/netmon-helper` (`achilles-netmon-helper` binary) — reuses
  `netmon::direct_capture_source()` (pktap) and serves the socket.

## Shipping (already wired)

- **Build + stage the helper per target** — `scripts/stage-netmon-helper.sh`,
  run automatically as the `beforeDevCommand` / `beforeBuildCommand` in
  `src-tauri/tauri.macos.conf.json`. It builds `netmon-helper` for
  `$TAURI_ENV_TARGET_TRIPLE` (falling back to the host triple) and stages it at
  `src-tauri/binaries/achilles-netmon-helper-<target-triple>`. The triple suffix
  is mandatory: Tauri resolves sidecars per target and strips it when copying
  into the bundle. Nothing to do by hand, locally or in CI.
- **Embed + sign** via `src-tauri/tauri.macos.conf.json` → `bundle.externalBin`
  (`binaries/achilles-netmon-helper`). Tauri copies sidecars to
  `Contents/MacOS/achilles-netmon-helper` — the path the LaunchDaemon plist's
  `BundleProgram` points at — and **signs each one as an executable**: Developer
  ID + hardened runtime + secure timestamp. `externalBin` is a cross-platform
  key, so it lives in the macOS-only config file; otherwise the Linux/Windows
  jobs would demand a helper binary for their own triples.
  - The daemon plist still rides along via `bundle.macOS.files` →
    `Library/LaunchDaemons/dev.crabnebula.achilles.netmon.plist`. That's fine:
    it's not a Mach-O, so it needs no signature of its own, and it's copied
    before the app is sealed.
  - ⚠️ Do **not** ship the helper via `bundle.macOS.files`. Those files are
    copied but never added to the bundler's sign list, so the helper reaches
    notarization unsigned and Apple rejects the archive with "not signed with a
    valid Developer ID certificate" / "does not include a secure timestamp" /
    "does not have the hardened runtime enabled".
- **Notarization** already runs in `publish.yml`; the embedded helper +
  LaunchDaemon are covered because they're inside the bundle at sign time.

## Auto-install (wired — needs a signed build to validate end-to-end)

`src-tauri/src/helper_mac.rs` (macOS only, via `objc2`, `objc2-foundation`,
`objc2-service-management`) wraps `SMAppService` for the daemon plist and is
exposed as three Tauri commands in `commands.rs`:

| command | does |
| --- | --- |
| `helper_status` | returns `{ status, socketReady }` — `status` is the `SMAppService` state (`enabled` / `requiresApproval` / `notRegistered` / `notFound` / `unknown`, `unsupported` off-macOS), `socketReady` is `netmon::helper_reachable()` |
| `helper_install` | `register()`s the daemon; idempotent (no-op when already `enabled`) |
| `helper_uninstall` | `unregister()`s the daemon (status → `notRegistered`); idempotent, and makes the install/approval flow re-testable |
| `helper_open_settings` | `openSystemSettingsLoginItems()` for the approval step |

`socketReady` **probes connectability** (`UnixStream::connect`), not socket-file
presence: a Unix-socket file outlives its listener, so a stopped/unregistered
daemon leaves a root-owned socket in `/var/run` that the user-level app can't
delete — an `exists()` check would keep reporting it "ready" until the next
reboot. The helper also removes its own socket on `SIGTERM` for good measure.

Both signals matter: `status` flips to `enabled` the moment the user approves,
but the socket — the thing a capture actually needs — appears once launchd has
started the daemon. The UI keys its banner on `socketReady`, falling back to
`status` to decide *which* prompt to show.

**When registration happens**

- **On pressing Record** (`ensureHelperForRecording` in `ui/main.js`) — the
  moment privileges actually matter. If the socket is down and the daemon isn't
  registered yet, it registers right there. This never blocks the capture: the
  first registration only parks the daemon in System Settings awaiting approval,
  so recording proceeds on the pcap fallback meanwhile.
- **On launch, re-validation only** (`helper_mac::revalidate_on_launch()` from
  the `setup` hook) — re-`register()`s when status is already `enabled`, so an
  in-place updater swap of the bundled helper keeps working. Same-Team signature
  → no re-approval. It deliberately does **not** register from scratch: merely
  launching Achilles should never plant a root daemon.
- **On demand**, from the banner's "Install capture helper" button.

**Banner states** (`helperBanner()`, shown in the idle, process-picker, and
recording views so it stays visible exactly while it's actionable):

| state | banner |
| --- | --- |
| `socketReady` | none — helper is serving |
| `enabled`, no socket | "approved — waiting for it to start…" + *Check again* |
| `requiresApproval` | "approve it in System Settings…" + *Open Settings* / *Check again* |
| otherwise | "install the privileged helper…" + *Install capture helper* |

Approval happens outside the app and emits no event, hence the explicit *Check
again* button; `startRecording` also re-checks on every attempt. Once enabled,
launchd starts the daemon as root, the socket appears, and `default_source()`
transparently switches to `HelperSource`. No workflow-secret changes are
required.

Still unvalidated: the approval flow only exercises from a **signed `.app`** —
`SMAppService` validates that the app and the embedded helper carry a valid
signature under the same Team ID, so ad-hoc/unsigned won't register. Notarization
is *not* part of that check; a locally `cargo tauri build`-ed bundle signed with
`APPLE_SIGNING_IDENTITY` is enough to test. Under `cargo tauri dev` there's no
bundle at all, so `status` reports `notFound` and the UI degrades to the
host-wide fallback with a notice.

Notarization still matters for anything distributed: Gatekeeper blocks an
unnotarized download outright, and a quarantined app runs translocated from a
randomized read-only path — which breaks the bundle-relative `BundleProgram` a
registration points at. Test from `/Applications`, and strip quarantine
(`xattr -dr com.apple.quarantine`) from any bundle that round-tripped through a
download.

## Security notes

- The helper socket is currently `0666`; a hardening pass should restrict it to
  the console user's uid via `LOCAL_PEERCRED`, and the helper should validate the
  connecting client.
- The daemon runs continuously (`KeepAlive`) but only captures while the app is
  connected and has sent a target PID.

## Fallback (already implemented)

Without the helper (or during development), `PcapSource` tries `pktap` and, if
that's denied, falls back to the default interface (needs only BPF/ChmodBPF
access) capturing **host-wide** with an in-UI notice. For full per-app capture in
dev without the helper, run the built binary with `sudo`.
