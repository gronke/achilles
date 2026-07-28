// Web/WASM adapter for the Achilles UI.
//
// The desktop build runs under Tauri, which injects `window.__TAURI__` and
// services the `invoke(...)` calls in Rust. In the browser there is no Tauri,
// so this module installs a `window.__TAURI__` shim that routes the same calls
// into the `achilles-wasm` module instead — letting `main.js` run unchanged.
//
// Loaded as a module *before* `main.js`. It installs `window.__TAURI__`
// SYNCHRONOUSLY (so main.js's top-level destructure of `window.__TAURI__.core`
// succeeds) and loads the wasm in the background; `invoke` awaits a `ready`
// promise before touching it. (A top-level `await` here would not work: the
// browser runs the next module script, main.js, during the suspension.)
//
// On the desktop build this detects real Tauri and does nothing — it never
// even fetches the wasm — so the same `index.html` serves both targets.

if (!window.__TAURI_INTERNALS__ && !window.__TAURI__) {
  installWebShim();
}

function installWebShim() {
  // Mark the host so the stylesheet can gate desktop-only chrome (the
  // traffic-light window controls) off the web build.
  document.documentElement.dataset.host = "web";

  // `wasm` is filled in once the module loads; `ready` gates anything that
  // needs it. main.js can destructure `window.__TAURI__` immediately because
  // we assign it synchronously at the end of this function.
  let wasm = null;
  let markReady;
  const ready = new Promise((resolve) => (markReady = resolve));

  // Achilles' analysis core is WebAssembly; some environments (notably Safari
  // Lockdown Mode) remove the `WebAssembly` global entirely, so we detect that
  // and explain it rather than failing with a raw ReferenceError.
  const WASM_UNAVAILABLE =
    "Achilles needs WebAssembly, which this browser has disabled — most often " +
    "Safari Lockdown Mode. Turn off Lockdown Mode for this site, or open Achilles " +
    "in a Chromium browser on desktop. (On iOS every browser uses WebKit, so only " +
    "disabling Lockdown Mode helps.)";

  // ---- per-app analysis cache -------------------------------------------
  // `analyze_app` / `Analyzer.finish()` return { detection, audit, staticScan }
  // in one pass, but the UI asks for `audit` / `static_scan` separately per
  // row. Cache each app's result and serve the slices from it.
  const analyzed = new Map(); // detection.path -> { detection, audit, staticScan }
  const rootToPath = new Map(); // detection.root -> detection.path

  function cacheResult(result, fallbackName) {
    let det = result?.detection;
    if (!det?.path) {
      // A bare `app.asar` has no bundle, so detection is null. Synthesize a
      // minimal Electron detection (an .asar is Electron-specific) so its
      // static-scan + dependency results still get a row to live under —
      // otherwise the scan runs but nothing shows in the UI.
      if (!result?.staticScan) return null; // genuinely nothing to show
      const name = fallbackName || "app.asar";
      det = {
        path: name,
        root: name,
        name,
        framework: "electron", // makes the UI run static_scan for this row
        confidence: "low", // inferred from the .asar, not a full bundle detection
        versions: {},
        bundle_id: null,
        executable: null,
      };
      result.detection = det;
    }
    analyzed.set(det.path, result);
    if (det.root) rootToPath.set(det.root, det.path);
    return det;
  }

  // ---- event bus (Tauri `listen` / emit) --------------------------------
  const listeners = new Map(); // event name -> Set<handler>
  function listen(event, handler) {
    let set = listeners.get(event);
    if (!set) listeners.set(event, (set = new Set()));
    set.add(handler);
    return Promise.resolve(() => set.delete(handler));
  }
  function emit(event, payload) {
    for (const h of listeners.get(event) ?? []) {
      try {
        h({ payload });
      } catch (e) {
        console.error("listener error", e);
      }
    }
  }

  // ---- Tauri `Channel` (cve_lookup streaming) ---------------------------
  class Channel {
    onmessage = () => {};
    // The Rust side calls this with each progressively-complete snapshot.
    _send(msg) {
      try {
        this.onmessage(msg);
      } catch (e) {
        console.error("channel onmessage error", e);
      }
    }
  }

  // ---- settings (localStorage; lookups still use OSV+EUVD on the web) ----
  const SETTINGS_KEY = "achilles.settings";
  function defaultSettings() {
    return {
      sources: {
        osv: { enabled: true },
        // NVD/GHSA can't run from the browser (CORS + client-side secrets).
        nvd: { enabled: false, api_key: null },
        euvd: { enabled: true },
        ghsa: { enabled: false, token: null },
      },
      filters: { max_age_years: 5 },
    };
  }
  function loadSettings() {
    try {
      return JSON.parse(localStorage.getItem(SETTINGS_KEY)) ?? defaultSettings();
    } catch {
      return defaultSettings();
    }
  }
  function saveSettings(s) {
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
    } catch {
      /* private mode / disabled storage — ignore */
    }
  }

  // ---- EUVD snapshot client (background fetch + offline cache) -----------
  // EUVD blocks browser-origin requests, so the web build reads a pre-fetched
  // snapshot from the same origin. The updater runs here on the page: it loads
  // any cached snapshot into wasm immediately (offline-first) and refreshes it
  // in the background. Each tab fetches independently — the snapshot is small,
  // content-addressed, and HTTP/Cache-Storage-cached, so redundant fetches are
  // cheap and no cross-tab coordination is needed. "Offline mode" (read the
  // snapshot instead of the live API) is mandatory in the browser.
  const EUVD_AUTO_KEY = "achilles.euvd.autoUpdate";
  const FOCUS_THROTTLE_MS = 5 * 60 * 1000;
  const PERIODIC_MS = 30 * 60 * 1000;
  const euvdState = { version: null, generatedAt: null, status: "idle", lastCheck: 0 };
  let euvdUpdater = null; // lazily-imported euvd-updater.js
  let euvdChecking = false;

  function euvdAutoUpdate() {
    try {
      return localStorage.getItem(EUVD_AUTO_KEY) !== "0";
    } catch {
      return true;
    }
  }
  function euvdModule() {
    return (euvdUpdater ??= import("./euvd-updater.js"));
  }
  function euvdStatus() {
    return {
      // The browser is always offline-mode and can't change it (no direct EUVD).
      offlineMode: true,
      offlineModeLocked: true,
      autoUpdate: euvdAutoUpdate(),
      version: euvdState.version,
      generatedAt: euvdState.generatedAt,
      status: euvdState.status,
      lastCheck: euvdState.lastCheck || null,
    };
  }
  function euvdNotifyUi() {
    emit("euvd_status", euvdStatus());
  }

  // Load whatever snapshot is in Cache Storage into this tab's wasm. Runs at
  // startup (offline-first) and after each successful update.
  async function euvdLoadFromCache() {
    if (!wasm) return;
    try {
      const mod = await euvdModule();
      const snap = await mod.readSnapshot();
      if (!snap || snap.shards.length === 0) return;
      for (const s of snap.shards) {
        wasm.euvd_set_shard(s.vendor, s.product, new Uint8Array(s.bytes));
      }
      wasm.euvd_commit(snap.version);
      euvdState.version = snap.version;
      euvdState.generatedAt = snap.generatedAt;
      euvdNotifyUi();
    } catch (e) {
      console.warn("euvd: loading cached snapshot failed", e);
    }
  }

  // Check the same-origin HEAD for a fresh snapshot; on change, cache it and
  // load it into wasm. A real page fetch, so it's visible in the Network panel.
  async function euvdCheck(force) {
    if (euvdChecking) return;
    euvdChecking = true;
    euvdState.status = "checking";
    euvdNotifyUi();
    try {
      const mod = await euvdModule();
      const r = await mod.checkAndUpdate({ force });
      euvdState.lastCheck = Date.now();
      euvdState.status = "idle";
      if (r.changed) {
        await euvdLoadFromCache();
        euvdState.version = r.version;
        euvdState.generatedAt = r.generatedAt;
        // Let main.js refresh an open app whose runtime just changed.
        emit("euvd_updated", {
          changedShards: r.changedShards ?? [],
          version: r.version,
          generatedAt: r.generatedAt,
        });
      }
      euvdNotifyUi();
    } catch (e) {
      console.warn("euvd: update check failed", e);
      euvdState.status = "error";
      euvdNotifyUi();
    } finally {
      euvdChecking = false;
    }
  }

  function euvdUpdateNow() {
    void euvdCheck(true);
  }
  function euvdSetAutoUpdate(on) {
    try {
      localStorage.setItem(EUVD_AUTO_KEY, on ? "1" : "0");
    } catch {
      /* private mode — ignore */
    }
    euvdNotifyUi();
  }

  async function euvdSetup() {
    if (!wasm) return;
    // 1) Offline-first: load any cached snapshot into wasm right away.
    await euvdLoadFromCache();
    // 2) Refresh in the background. With auto-update off we still seed once if
    //    nothing is cached, so EUVD works at all; otherwise we leave refreshes
    //    to an explicit "Update now".
    const mod = await euvdModule();
    const haveCached = !!(await mod.currentManifest());
    if (euvdAutoUpdate() || !haveCached) void euvdCheck(false);
    // 3) Catch up promptly on reconnect / refocus, throttled.
    window.addEventListener("online", () => {
      if (euvdAutoUpdate()) void euvdCheck(false);
    });
    document.addEventListener("visibilitychange", () => {
      if (
        document.visibilityState === "visible" &&
        euvdAutoUpdate() &&
        Date.now() - euvdState.lastCheck > FOCUS_THROTTLE_MS
      ) {
        void euvdCheck(false);
      }
    });
    setInterval(() => {
      if (euvdAutoUpdate()) void euvdCheck(false);
    }, PERIODIC_MS);
  }
  function euvdAgo(when) {
    if (when == null) return "never";
    const then = typeof when === "number" ? when : Date.parse(when);
    if (Number.isNaN(then)) return "unknown";
    const secs = Math.max(0, (Date.now() - then) / 1000);
    for (const [name, size] of [
      ["year", 31536000],
      ["month", 2592000],
      ["day", 86400],
      ["hour", 3600],
      ["minute", 60],
    ]) {
      const n = Math.floor(secs / size);
      if (n >= 1) return `${n} ${name}${n === 1 ? "" : "s"} ago`;
    }
    return "just now";
  }

  // The EUVD snapshot controls live in the settings dialog, but only on the web
  // build — so they're injected here rather than baked into the shared
  // index.html. They sit directly under the existing EUVD source entry and
  // collapse when it's unchecked. Offline mode is shown checked + disabled: the
  // browser can't reach EUVD directly, so reading the bundled snapshot is
  // mandatory.
  function injectEuvdSettings() {
    const form = document.querySelector("#settings-form");
    if (!form || form.querySelector("#euvd-snapshot-settings")) return;
    const euvdBox = form.elements["euvd"];
    const euvdSection = euvdBox?.closest("section");
    if (!euvdSection) return;

    const box = document.createElement("div");
    box.id = "euvd-snapshot-settings";
    box.innerHTML = `
      <label title="Required in the browser — EUVD blocks direct access from web pages">
        <input type="checkbox" id="euvd-offline" checked disabled />
        Offline mode <span class="muted">— read a bundled snapshot (required in the browser)</span>
      </label>
      <label>
        <input type="checkbox" id="euvd-auto" />
        Auto-update vulnerability databases
      </label>
      <p class="muted" id="euvd-updated-label">Checking…</p>
      <button type="button" id="euvd-update-now">Update now</button>
      <p class="muted">
        Vulnerability data: European Union Agency for Cybersecurity (ENISA),
        <a href="https://euvd.enisa.europa.eu/" target="_blank" rel="noopener noreferrer">EUVD</a>,
        licensed <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">CC BY 4.0</a>
        — bundled snapshot, modified subset.
      </p>
    `;
    euvdSection.appendChild(box);

    // Collapse the snapshot config unless EUVD is the active source. Track the
    // checkbox live, and re-sync when the dialog opens — main.js sets the
    // checkbox from saved settings there without firing a `change` event.
    const syncVisibility = () => {
      box.hidden = !euvdBox.checked;
    };
    euvdBox.addEventListener("change", syncVisibility);
    const dialog = document.querySelector("#settings-dialog");
    if (dialog) {
      new MutationObserver(syncVisibility).observe(dialog, {
        attributes: true,
        attributeFilter: ["open"],
      });
    }
    syncVisibility();

    const autoEl = box.querySelector("#euvd-auto");
    const labelEl = box.querySelector("#euvd-updated-label");
    const updateBtn = box.querySelector("#euvd-update-now");
    const render = (st) => {
      if (!st) return;
      autoEl.checked = st.autoUpdate !== false;
      const checking = st.status === "checking";
      updateBtn.disabled = checking;
      updateBtn.textContent = checking ? "Updating…" : "Update now";
      // Track the last *check* (which advances on every "Update now"), not the
      // snapshot's build time — so a manual check always shows visible feedback,
      // even when the data turns out to be unchanged.
      if (checking) labelEl.textContent = "Checking for updates…";
      else if (st.status === "error") labelEl.textContent = "Update failed — will retry.";
      else if (!st.version) labelEl.textContent = "Not downloaded yet.";
      else if (st.lastCheck) labelEl.textContent = `Last checked ${euvdAgo(st.lastCheck)}.`;
      else labelEl.textContent = `Snapshot from ${euvdAgo(st.generatedAt)}.`;
    };
    autoEl.addEventListener("change", () =>
      void invoke("euvd_set_auto_update", { enabled: autoEl.checked }),
    );
    updateBtn.addEventListener("click", () => void invoke("euvd_update_now"));
    void listen("euvd_status", ({ payload }) => render(payload));
    render(euvdStatus());
  }

  // ---- the `invoke` surface ---------------------------------------------
  async function invoke(cmd, args = {}) {
    await ready; // wasm is loaded asynchronously; never touch it before it's up
    switch (cmd) {
      case "scan":
        return webScan();
      case "discover":
        return [];
      case "detect_one":
        return analyzed.get(args.path)?.detection ?? null;
      case "audit":
        return analyzed.get(args.path)?.audit ?? { error: "not analysed" };
      case "static_scan": {
        const path = rootToPath.get(args.root);
        return analyzed.get(path)?.staticScan ?? null;
      }
      // Side-effects live on the host filesystem, not in a user-provided bundle.
      case "sideeffects":
        return null;
      case "cve_lookup": {
        // Surface "EUVD not loaded yet" so an empty EUVD bucket never reads as a
        // clean bill of health while the snapshot is still downloading (or was
        // never downloaded, offline). It self-heals: the first snapshot commit
        // emits `euvd_updated`, which re-runs the lookup.
        const noSnapshot = !wasm.euvd_snapshot_version();
        const markEuvd = (rep) => {
          if (noSnapshot && rep && !(rep.unavailable ?? []).includes("EUVD")) {
            rep.unavailable = [...(rep.unavailable ?? []), "EUVD"];
          }
          return rep;
        };
        const ch = args.onUpdate;
        const onUpdate =
          ch && typeof ch._send === "function"
            ? (snap) => ch._send(markEuvd(JSON.parse(snap)))
            : null;
        const json = await wasm.cve_lookup(JSON.stringify(args.versions ?? {}), onUpdate);
        return markEuvd(JSON.parse(json));
      }
      case "dependency_scan": {
        const json = await wasm.dependency_scan(JSON.stringify(args.deps ?? []));
        return JSON.parse(json);
      }
      case "get_settings":
        return loadSettings();
      case "set_settings":
        saveSettings(args.settings);
        return;
      case "settings_path":
        return null;
      // EUVD snapshot controls for the settings dialog.
      case "euvd_status":
        return euvdStatus();
      case "euvd_update_now":
        euvdUpdateNow();
        return;
      case "euvd_set_auto_update":
        euvdSetAutoUpdate(!!args.enabled);
        return;
      // Journaling is host-side persistence; not wired up in the browser yet.
      case "journal_save":
        return null;
      case "journal_latest":
        return null;
      case "journal_list":
        return [];
      case "journal_path":
        return null;
      case "set_zoom":
        document.body.style.zoom = String(args.factor ?? 1);
        return;
      default:
        console.warn("achilles web shim: unhandled invoke", cmd, args);
        return null;
    }
  }

  // ---- scanning: File System Access (Chromium) or a selected file (any browser) --

  // What a single upload may be. Achilles reads macOS, Windows, and Linux apps
  // alike — the wasm side infers which from the tree — so the accepted shapes
  // are "an app folder", "a zip of one", "a Linux package", or "a lone binary".
  const SUPPORTED_FILES =
    "a zipped app (.zip), a Linux package (.AppImage, .snap, .deb, .rpm, .tar.gz), " +
    "a Windows .exe, a Linux executable, or an app.asar";
  const SUPPORTED_DROP = `an app folder (.app / a Windows or Linux app directory), ${SUPPORTED_FILES}`;
  // Extensions we accept as a single-file upload. The Linux package formats are
  // unpacked wasm-side before the usual analysis runs — see the `pkg` crate.
  const FILE_RE =
    /\.(zip|asar|exe|appimage|snap|deb|rpm|tar|tgz|txz|tbz2?|tzst|tar\.(gz|xz|bz2|zst|lz4|lzma))$/i;
  // …but a Linux app binary carries no extension at all, so an extension-less
  // file is a candidate too. The wasm side reads its magic and rejects it with
  // a specific message if it turns out not to be an app, so guessing generously
  // here costs nothing and is the only way those uploads are reachable.
  const isUploadCandidate = (name) => FILE_RE.test(name) || !/\.[^.\\/]+$/.test(name);

  function setStatus(text) {
    const el = document.querySelector("#status");
    if (el) el.textContent = text;
  }

  // ---- which OS's layout to read an upload as ---------------------------
  // The wasm side sniffs this from the tree, but the markers aren't always
  // decisive — a Linux app that ships .NET assemblies looks like a Windows
  // install, and a sniff that guesses wrong then finds no executable at all.
  // This is the escape hatch: force the layout and scan again.
  const PLATFORM_LABELS = { macos: "macOS", windows: "Windows", linux: "Linux" };
  /** `""` means "let the wasm side sniff it". */
  let forcedPlatform = "";
  /** The wasm bindings take `Option<String>`, so absent must be `undefined`. */
  const platformArg = () => forcedPlatform || undefined;
  const platformLabel = (p) => PLATFORM_LABELS[p] ?? p;

  /**
   * Final status line for a scan, replacing main.js's plain "done: N".
   *
   * Reports the layout each app was read as whenever it was inferred rather
   * than chosen, so a wrong guess is visible instead of silently producing an
   * empty row — and points at the control that fixes it.
   *
   * @param count   apps that produced a row
   * @param used    Set of platform names the wasm side reported
   * @param empty   names that held no application
   * @param failed  error messages, one per upload that threw
   */
  function reportScan(count, used, empty, failed) {
    const problems = empty.length
      ? [`no application found in ${empty.join(", ")}`, ...failed]
      : [...failed];
    const read = [...used].map(platformLabel).join(", ");

    if (!problems.length) {
      if (!forcedPlatform && read) {
        setStatus(`done: ${count} app${count === 1 ? "" : "s"} — read as ${read}`);
      }
      return;
    }
    const done = count ? `done: ${count} app${count === 1 ? "" : "s"}. ` : "";
    // Only "found nothing app-shaped" points at a bad sniff. A file we couldn't
    // read at all already carries its own explanation from the wasm side.
    const hint =
      empty.length && !forcedPlatform
        ? " — if that's the wrong OS layout, choose it under ‘Read as’ and scan again"
        : "";
    setStatus(`${done}${problems.join("; ")}${hint}`);
  }

  // `scan` fires on boot (and from the desktop Rescan, which is hidden on the
  // web) — never with the transient activation the pickers need — so it only
  // sets the ingest hint. Actual ingestion runs through the injected header
  // controls and the dropzone.
  async function webScan() {
    setStatus(
      window.showDirectoryPicker
        ? `Click ‘Open folder’ to pick one (e.g. /Applications), or ‘Open file…’ for ${SUPPORTED_FILES}.`
        : `Click ‘Open’ to choose ${SUPPORTED_FILES}.`,
    );
  }

  // A picked folder is read as one of two things: a *container* of macOS `.app`
  // bundles (/Applications), or a single application root. Windows and Linux
  // apps are just a directory of files with no naming convention to key on, so
  // there's nothing to enumerate — the folder itself is the app. The wasm side
  // works out which platform's layout it follows from the files inside.
  function appsInPickedDirectory(dir, childBundles) {
    if (dir.name.endsWith(".app") || childBundles.length === 0) return [dir];
    return childBundles;
  }

  // ---- ingest budget ----------------------------------------------------
  // Everything the analysis reads is copied into wasm's linear memory, which
  // tops out at 4 GB — and an allocation that fails there aborts the whole
  // module rather than raising a catchable error, taking every later scan with
  // it until the page reloads. Since "the folder itself is the app" now accepts
  // any directory, a mis-pick can be a source tree or a 20 GB build directory,
  // so measure before ingesting: file handles carry `.size` without reading a
  // byte, which makes refusing one of those cost a directory walk instead of an
  // out-of-memory abort.
  //
  // The ceiling is far above any real desktop app (the biggest Electron apps
  // land around 600 MB) and far below where wasm gets into trouble — the tree
  // is not the only claim on that memory, since each binary the analysis parses
  // is cloned out of it. The file cap is not about memory but about bounding
  // the walk itself; an app with unpacked `node_modules` can hold tens of
  // thousands of files legitimately, so it sits well clear of that.
  const MAX_APP_BYTES = 2 * 1024 ** 3;
  const MAX_APP_FILES = 50_000;

  function tooLargeMessage(name, overflow) {
    const limit =
      overflow === "count"
        ? `more than ${MAX_APP_FILES.toLocaleString()} files`
        : `more than ${MAX_APP_BYTES / 1024 ** 3} GB`;
    return (
      `${name} holds ${limit} — too much for the browser to load. Pick the ` +
      `folder holding the app's own executable rather than a parent directory.`
    );
  }

  /**
   * Walk one app directory and collect a `File` per entry. Only metadata is
   * touched here — `getFile()` does not read contents — so the budget is
   * checked before anything is pulled into memory. Stops at the first entry
   * that breaks it and reports which limit was hit.
   *
   * @returns `{ files: [{ path, file }], overflow: null | "size" | "count" }`
   */
  async function collectAppFiles(dirHandle, basePath) {
    const files = [];
    let bytes = 0;
    let overflow = null;
    const walk = async (handle, base) => {
      for await (const [name, child] of handle.entries()) {
        if (overflow) return;
        const path = `${base}/${name}`;
        if (child.kind === "directory") {
          await walk(child, path);
        } else {
          const file = await child.getFile();
          bytes += file.size;
          files.push({ path, file });
          if (files.length > MAX_APP_FILES) overflow = "count";
          else if (bytes > MAX_APP_BYTES) overflow = "size";
        }
      }
    };
    await walk(dirHandle, basePath);
    return { files, overflow };
  }

  async function scanViaDirectoryPicker() {
    await ready;
    if (!wasm) return setStatus(WASM_UNAVAILABLE);
    const dir = await window.showDirectoryPicker({ mode: "read" });

    const bundles = [];
    if (!dir.name.endsWith(".app")) {
      for await (const [name, handle] of dir.entries()) {
        if (handle.kind === "directory" && name.endsWith(".app")) bundles.push(handle);
      }
    }
    const apps = appsInPickedDirectory(dir, bundles);

    emit("scan_event", { event: "started", total: apps.length });
    let count = 0;
    const used = new Set();
    const empty = [];
    const failed = [];
    for (const appHandle of apps) {
      try {
        const root = `/scan/${appHandle.name}`;
        setStatus(`reading ${appHandle.name}…`);
        const { files, overflow } = await collectAppFiles(appHandle, root);
        if (overflow) {
          failed.push(tooLargeMessage(appHandle.name, overflow));
          continue;
        }
        const analyzer = new wasm.Analyzer(root, platformArg());
        for (const { path, file } of files) {
          analyzer.add_file(path, new Uint8Array(await file.arrayBuffer()));
        }
        const result = JSON.parse(analyzer.finish());
        if (result.platform) used.add(result.platform);
        const det = cacheResult(result, appHandle.name);
        if (det) {
          emit("scan_event", { event: "detected", ...det });
          count++;
        } else {
          // Nothing app-shaped in there — a Windows or Linux folder only
          // announces itself as an app by the binary inside it, so this is
          // only knowable after reading it. Report it instead of listing a row.
          empty.push(appHandle.name);
        }
      } catch (e) {
        console.warn("failed to analyse", appHandle.name, e);
        failed.push(`${appHandle.name}: ${e?.message ?? e}`);
        emit("scan_event", { event: "error", message: String(e) });
      }
    }
    emit("scan_event", { event: "finished", count });
    reportScan(count, used, empty, failed);
  }

  async function scanViaFile(file) {
    await ready;
    if (!wasm) return setStatus(WASM_UNAVAILABLE);
    if (file.size > MAX_APP_BYTES) return setStatus(tooLargeMessage(file.name, "size"));
    setStatus(`analysing ${file.name}…`);
    emit("scan_event", { event: "started", total: 1 });
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const result = JSON.parse(wasm.analyze_app(bytes, file.name, platformArg()));
      const det = cacheResult(result, file.name);
      if (det) emit("scan_event", { event: "detected", ...det });
      emit("scan_event", { event: "finished", count: det ? 1 : 0 });
      reportScan(
        det ? 1 : 0,
        new Set(result.platform ? [result.platform] : []),
        det ? [] : [file.name],
        [],
      );
    } catch (e) {
      console.warn("failed to analyse file", e);
      emit("scan_event", { event: "error", message: String(e) });
      emit("scan_event", { event: "finished", count: 0 });
      // The wasm side names what it couldn't read (an unrecognised file, a
      // Mach-O, a broken zip); that message is the whole answer, so show it
      // rather than sending the user to the console.
      reportScan(0, new Set(), [], [`${file.name}: ${e?.message ?? e}`]);
    }
  }

  // ---- inject the web-only scan controls into the header ----------------
  function injectControls() {
    const header = document.querySelector("header");
    if (!header) return;
    // Ingestion is the browser build's primary action: its controls go in
    // front of the shared Export/Settings buttons.
    const anchor = document.querySelector("#export-all") ?? header.lastElementChild;

    // `<select>` gets no styling from styles.css (the desktop build has none),
    // so match the header buttons here.
    const style = document.createElement("style");
    style.textContent = `
      #achilles-platform {
        background: var(--bg-3); color: var(--fg);
        border: 1px solid transparent; border-radius: 4px;
        padding: 4px 6px; font-size: 12px; font-family: inherit; cursor: pointer;
      }
      #achilles-platform:hover { border-color: var(--accent); }
    `;
    document.head.appendChild(style);

    const platformSelect = document.createElement("select");
    platformSelect.id = "achilles-platform";
    platformSelect.title =
      "Which OS's application layout to read uploads as. Auto-detect infers it " +
      "from the files; choose one explicitly if it guesses wrong.";
    for (const [value, label] of [
      ["", "Auto-detect OS"],
      ["macos", "Read as macOS"],
      ["windows", "Read as Windows"],
      ["linux", "Read as Linux"],
    ]) {
      const opt = document.createElement("option");
      opt.value = value;
      opt.textContent = label;
      platformSelect.appendChild(opt);
    }
    platformSelect.addEventListener("change", () => {
      forcedPlatform = platformSelect.value;
    });

    const fileInput = document.createElement("input");
    fileInput.type = "file";
    // Deliberately unfiltered: a Linux app binary has no extension and no MIME
    // type to name it, so any `accept` list would hide exactly the uploads that
    // are hardest to arrive at another way. The wasm side does the rejecting.
    fileInput.style.display = "none";
    fileInput.id = "achilles-file-input";
    fileInput.addEventListener("change", () => {
      const file = fileInput.files?.[0];
      if (file) void scanViaFile(file);
      fileInput.value = "";
    });

    // Capability-aware ingestion: the directory picker where the browser has
    // one (a `.app` bundle is itself a directory, so that covers single apps
    // too), the plain file picker everywhere else. A directory picker can't
    // select files, so browsers that got one carry a second button for
    // zipped .apps / bare asars — the labels explain the split themselves.
    const openBtn = document.createElement("button");
    openBtn.type = "button";
    if (window.showDirectoryPicker) {
      openBtn.textContent = "Open folder";
      openBtn.title =
        "Pick a folder: /Applications scans every .app in it, any other folder " +
        "(a Windows install directory, a Linux app tree, one .app) is scanned as a single app";
      openBtn.addEventListener("click", () => {
        void scanViaDirectoryPicker().catch((e) => {
          if (e?.name !== "AbortError") setStatus(`scan failed: ${e}`);
        });
      });
    } else {
      openBtn.textContent = "Open";
      openBtn.title = `Choose ${SUPPORTED_FILES}`;
      openBtn.addEventListener("click", () => fileInput.click());
    }
    header.insertBefore(openBtn, anchor);

    // A directory picker can't select files, so browsers that got one keep a
    // second button for single-file uploads.
    if (window.showDirectoryPicker) {
      const archiveBtn = document.createElement("button");
      archiveBtn.type = "button";
      archiveBtn.textContent = "Open file…";
      archiveBtn.title = `Select ${SUPPORTED_FILES}`;
      archiveBtn.addEventListener("click", () => fileInput.click());
      header.insertBefore(archiveBtn, anchor);
    }

    // Which OS layout uploads are read as; applies to folders and files alike.
    header.insertBefore(platformSelect, anchor);

    // Clear: main.js owns the list state and empties it on this event; the
    // analysis caches here go with it so a re-opened app re-analyses fresh.
    const clearBtn = document.createElement("button");
    clearBtn.type = "button";
    clearBtn.textContent = "Clear";
    clearBtn.title = "Empty the list and drop the analysis results";
    clearBtn.addEventListener("click", () => {
      window.dispatchEvent(new CustomEvent("achilles:clear"));
      analyzed.clear();
      rootToPath.clear();
      void webScan(); // reset the status line to the ingest hint
    });
    header.insertBefore(clearBtn, anchor);

    header.appendChild(fileInput);
  }

  // ---- drag-and-drop: a dashed-border overlay + folder/file dropzone ----
  // An inviting overlay appears while a file/folder is dragged over the page;
  // on drop it scans an app folder (a `.app`, a Windows install directory, a
  // Linux app tree), a folder of `.app`s, a zip of any of those, a bare `.exe`
  // or Linux executable, or a bare `app.asar`, and warns + refuses anything else.
  function injectDropzone() {
    if (document.querySelector("#achilles-dropzone")) return;

    const style = document.createElement("style");
    style.textContent = `
      #achilles-dropzone {
        position: fixed; inset: 0; z-index: 99999; display: none;
        align-items: center; justify-content: center;
        background: rgba(18, 14, 24, 0.78); pointer-events: none;
      }
      #achilles-dropzone.show { display: flex; }
      #achilles-dropzone .dz-box {
        margin: 24px; padding: 44px 64px; max-width: 78vw; text-align: center;
        border: 3px dashed #cba6ff; border-radius: 16px;
        background: rgba(30, 23, 40, 0.55);
      }
      #achilles-dropzone .dz-msg { margin: 0; font-size: 22px; color: #f4eefe; }
      #achilles-dropzone .dz-sub { margin: 10px 0 0; font-size: 14px; color: #c3b3df; }
      #achilles-dropzone.reject .dz-box { border-color: #ff6b6b; }
      #achilles-dropzone.reject .dz-msg { color: #ff8a8a; }
    `;
    const el = document.createElement("div");
    el.id = "achilles-dropzone";
    el.innerHTML =
      '<div class="dz-box"><p class="dz-msg"></p><p class="dz-sub"></p></div>';
    document.head.appendChild(style);
    document.body.appendChild(el);

    const msg = el.querySelector(".dz-msg");
    const sub = el.querySelector(".dz-sub");
    function show(reject) {
      msg.textContent = reject ? "Unsupported" : "Drop to scan";
      sub.textContent = reject ? `Need ${SUPPORTED_DROP}.` : SUPPORTED_DROP;
      el.classList.toggle("reject", !!reject);
      el.classList.add("show");
    }
    const hide = () => el.classList.remove("show", "reject");

    let depth = 0;
    const isFileDrag = (e) => [...(e.dataTransfer?.types ?? [])].includes("Files");
    window.addEventListener("dragenter", (e) => {
      if (!isFileDrag(e)) return;
      e.preventDefault();
      depth += 1;
      show(false);
    });
    window.addEventListener("dragover", (e) => {
      if (!isFileDrag(e)) return;
      e.preventDefault();
      if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
    });
    window.addEventListener("dragleave", (e) => {
      if (!isFileDrag(e)) return;
      depth = Math.max(0, depth - 1);
      if (depth === 0) hide();
    });
    window.addEventListener("drop", (e) => {
      e.preventDefault();
      depth = 0;
      // The DataTransfer is cleared once this handler returns, so capture the
      // entries / files synchronously and analyse them afterwards.
      const items = [...(e.dataTransfer?.items ?? [])].filter(
        (it) => it.kind === "file",
      );
      const entries = items.map((it) => it.webkitGetAsEntry?.()).filter(Boolean);
      const looseFiles = [...(e.dataTransfer?.files ?? [])];
      void handleDrop(entries, looseFiles, show, hide);
    });
  }

  // Read every entry of a dropped directory (the reader returns them in batches).
  function readDirEntries(dirEntry) {
    const reader = dirEntry.createReader();
    return new Promise((resolve, reject) => {
      const all = [];
      const step = () =>
        reader.readEntries((batch) => {
          if (batch.length) {
            all.push(...batch);
            step();
          } else {
            resolve(all);
          }
        }, reject);
      step();
    });
  }
  // Resolve a dropped file entry to its File. The File stays valid afterwards,
  // unlike the entry itself, which Safari invalidates once the drop settles.
  function entryFile(entry) {
    return new Promise((resolve, reject) => entry.file(resolve, reject));
  }
  // Collect one app directory into { name, files: [{ path, file }], overflow },
  // with `path` relative to the app root. The whole tree is walked up front,
  // before any unrelated `await`, for the same Safari-invalidation reason —
  // and, as with the folder picker, only file metadata is touched, so a dropped
  // build directory is refused on its size rather than loaded until wasm dies.
  async function collectApp(appEntry) {
    const files = [];
    let bytes = 0;
    let overflow = null;
    const walk = async (entry, rel) => {
      if (overflow) return;
      if (entry.isDirectory) {
        for (const child of await readDirEntries(entry)) {
          await walk(child, `${rel}/${child.name}`);
        }
      } else {
        const file = await entryFile(entry);
        bytes += file.size;
        files.push({ path: rel, file });
        if (files.length > MAX_APP_FILES) overflow = "count";
        else if (bytes > MAX_APP_BYTES) overflow = "size";
      }
    };
    for (const child of await readDirEntries(appEntry)) {
      await walk(child, `/${child.name}`);
    }
    return { name: appEntry.name, files, overflow };
  }

  async function handleDrop(entries, looseFiles, show, hide) {
    if (typeof WebAssembly === "undefined") {
      hide();
      setStatus(WASM_UNAVAILABLE);
      return;
    }

    // Read the dropped tree into memory FIRST. Safari invalidates dropped
    // directory entries once the drop settles, so we must not `await` anything
    // slow (e.g. the wasm load) before walking them.
    const apps = []; // [{ name, files: [{ path, file }] }]
    const files = []; // bare .zip / .asar / .exe / extension-less File objects
    try {
      for (const entry of entries) {
        if (entry.isDirectory) {
          // Same rule as the folder picker: a folder of `.app`s is a container,
          // anything else is one app (macOS, Windows, or Linux — the wasm side
          // works out which from the files).
          const bundles = entry.name.endsWith(".app")
            ? []
            : (await readDirEntries(entry)).filter(
                (child) => child.isDirectory && child.name.endsWith(".app"),
              );
          for (const app of bundles.length ? bundles : [entry]) {
            apps.push(await collectApp(app));
          }
        } else if (isUploadCandidate(entry.name)) {
          files.push(await entryFile(entry));
        }
      }
      // Browsers without the Entries API only give us plain files.
      if (!entries.length) {
        for (const f of looseFiles) {
          if (isUploadCandidate(f.name)) files.push(f);
        }
      }
    } catch (err) {
      console.warn("failed to read the dropped item", err);
      show(true);
      setStatus(
        "Couldn't read the dropped folder — Safari can't reliably read dropped " +
        "directories. Zip the app folder and drop (or ‘Open’) the .zip instead.",
      );
      setTimeout(hide, 4000);
      return;
    }

    if (apps.length + files.length === 0) {
      show(true); // unsupported — warn and refuse
      setStatus(`Unsupported drop — use ${SUPPORTED_DROP}.`);
      setTimeout(hide, 2000);
      return;
    }
    hide();

    await ready;
    if (!wasm) return setStatus(WASM_UNAVAILABLE);

    emit("scan_event", { event: "started", total: apps.length + files.length });
    let count = 0;
    const used = new Set();
    const empty = [];
    const failed = [];
    for (const app of apps) {
      try {
        if (app.overflow) {
          failed.push(tooLargeMessage(app.name, app.overflow));
          continue;
        }
        const root = `/scan/${app.name}`;
        const analyzer = new wasm.Analyzer(root, platformArg());
        for (const { path, file } of app.files) {
          analyzer.add_file(`${root}${path}`, new Uint8Array(await file.arrayBuffer()));
        }
        const result = JSON.parse(analyzer.finish());
        if (result.platform) used.add(result.platform);
        const det = cacheResult(result, app.name);
        if (det) {
          emit("scan_event", { event: "detected", ...det });
          count += 1;
        } else {
          empty.push(app.name); // held no application — reported below
        }
      } catch (err) {
        console.warn("failed to analyse", app.name, err);
        failed.push(`${app.name}: ${err?.message ?? err}`);
        emit("scan_event", { event: "error", message: String(err) });
      }
    }
    for (const file of files) {
      try {
        if (file.size > MAX_APP_BYTES) {
          failed.push(tooLargeMessage(file.name, "size"));
          continue;
        }
        const bytes = new Uint8Array(await file.arrayBuffer());
        const result = JSON.parse(wasm.analyze_app(bytes, file.name, platformArg()));
        if (result.platform) used.add(result.platform);
        const det = cacheResult(result, file.name);
        if (det) {
          emit("scan_event", { event: "detected", ...det });
          count += 1;
        } else {
          empty.push(file.name);
        }
      } catch (err) {
        // Includes the extension-less files we let through on the chance they
        // were Linux binaries; the wasm side says exactly what it couldn't read.
        console.warn("failed to analyse file", err);
        failed.push(`${file.name}: ${err?.message ?? err}`);
        emit("scan_event", { event: "error", message: String(err) });
      }
    }
    emit("scan_event", { event: "finished", count });
    reportScan(count, used, empty, failed);
  }

  // ---- export: native save-dialog + writeTextFile → Blob download -------
  let pendingName = "achilles-export.json";
  async function save(opts) {
    pendingName = opts?.defaultPath || pendingName;
    return pendingName; // non-null so main.js proceeds to writeTextFile
  }
  async function writeTextFile(path, contents) {
    const blob = new Blob([contents], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = path || pendingName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  // ---- install the shim SYNCHRONOUSLY (before main.js evaluates) --------
  window.__TAURI__ = {
    core: { invoke, Channel },
    event: { listen },
    dialog: { save },
    fs: { writeTextFile },
    // The updater/process plugins don't exist on the web; stub the bits the UI
    // touches so `updater?.check` and friends no-op cleanly.
    updater: { check: async () => null },
    process: { relaunch: async () => {} },
  };

  // ---- register the service worker (installable PWA + offline shell) ----
  if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
      navigator.serviceWorker
        .register("./sw.js")
        .catch((e) => console.warn("service worker registration failed", e));
    });
  }

  // ---- load the wasm in the background, then enable scanning ------------
  (async () => {
    if (typeof WebAssembly === "undefined") {
      // e.g. Safari Lockdown Mode strips `WebAssembly`; the analysis can't run.
      console.warn("achilles web shim:", WASM_UNAVAILABLE);
      markReady(); // unblock invoke(); the scan paths guard on `wasm` being null
      const showUnavailable = () => {
        injectControls();
        injectDropzone();
        setStatus(WASM_UNAVAILABLE);
      };
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", showUnavailable, { once: true });
      } else {
        showUnavailable();
      }
      return;
    }
    try {
      const mod = await import("./pkg/achilles_wasm.js");
      await mod.default();
      wasm = mod;
      markReady();
      euvdSetup(); // background: fetch/cache the EUVD snapshot, load it into wasm
      const inject = () => {
        injectControls();
        injectDropzone();
        injectEuvdSettings();
      };
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", inject, { once: true });
      } else {
        inject();
      }
    } catch (e) {
      console.error("achilles web shim: failed to load wasm", e);
      setStatus(`failed to load analysis engine: ${e}`);
    }
  })();
}
