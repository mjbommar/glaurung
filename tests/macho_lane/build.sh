#!/usr/bin/env bash
# Rebuild the Mach-O lane fixtures.
#
# COMMITTED so the lane runs without zig. `zig cc -target <arch>-macos` produces
# real Mach-O with its bundled darwin linker -- no macOS machine and no Xcode.
set -euo pipefail
cd "$(dirname "$0")"
command -v zig >/dev/null || { echo "need zig (0.15.2 verified)" >&2; exit 1; }
for t in x86_64 aarch64; do
  zig cc -target "$t-macos" -shared -O1 -o "lib_$t.dylib" macho_src.c
done
python3 - <<'PY'
import hashlib, json, pathlib
m = json.loads(pathlib.Path("MANIFEST.json").read_text())
for p in sorted(pathlib.Path(".").glob("*.dylib")):
    m[p.name] = {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "size": p.stat().st_size}
pathlib.Path("MANIFEST.json").write_text(json.dumps(m, indent=2) + "\n")
print("MANIFEST.json refreshed")
PY
