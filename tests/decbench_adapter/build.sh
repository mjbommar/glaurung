#!/usr/bin/env bash
# Rebuild the committed PE32 resolver fixture.
#
# The .dll is COMMITTED, like tests/decompiler_fixtures/canary/: the resolver
# tests must run on a fresh clone with no Windows toolchain. Rerun this only to
# change what the fixture contains, then refresh MANIFEST.json's sha256.
#
# i686-w64-mingw32-gcc, because the whole point is REAL i386 stdcall decoration
# (`_name@N`). Hand-writing a symbol table would test the test.
set -euo pipefail
cd "$(dirname "$0")"
command -v i686-w64-mingw32-gcc >/dev/null || {
  echo "need i686-w64-mingw32-gcc (apt install gcc-mingw-w64-i686)" >&2
  exit 1
}
i686-w64-mingw32-gcc -shared -O1 -o stdcall_symbols.dll stdcall_symbols.c
python3 - <<'PY'
import hashlib, json, pathlib
d = pathlib.Path(__file__).resolve().parent if "__file__" in dir() else pathlib.Path(".")
p = pathlib.Path("stdcall_symbols.dll")
m = json.loads(pathlib.Path("MANIFEST.json").read_text())
m["sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
m["size"] = p.stat().st_size
pathlib.Path("MANIFEST.json").write_text(json.dumps(m, indent=2) + "\n")
print("MANIFEST.json refreshed:", m["sha256"][:16], m["size"], "bytes")
PY
