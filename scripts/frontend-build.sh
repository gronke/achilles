#!/usr/bin/env bash
#
# Build the servable frontend tree with web-modules: compile ui/*.scss, copy the
# static files, vendor the npm dependencies from ui/package.json into
# <out>/web_modules/, and validate every bare import against the generated map.
#
#   scripts/frontend-build.sh [OUT]     # OUT defaults to dist
#
# The out dir must be absent, empty, or a previous build's output (web-modules
# stages next to it and replaces it atomically). Desktop builds call this via
# tauri's before commands; ui/pkg (the wasm build for the browser target) is
# optional input — copy-through when present, not required.
#
# Prerequisite: cargo install web_modules --features full  (binary: web-modules)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
out="${1:-dist}"

# web-modules' reject presets do not filter node_modules/ — a stray install
# would be copied wholesale into the output. Bootstrap uses --lockfile-only;
# refuse to build around a mistake.
if [ -e ui/node_modules ]; then
  echo "error: ui/node_modules exists; remove it (dependency changes use 'web-modules npm install --dir ui --lockfile-only …')" >&2
  exit 1
fi

exec web-modules build ui --out "$out" --manifest ui/package.json
