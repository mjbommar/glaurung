#!/usr/bin/env bash
# Rebuild the committed PE32+/PDB type-recovery fixture.
#
# COMMITTED (dll 2.5 KB + pdb 72 KB) so the lane runs on a clone with no
# Windows toolchain. clang-cl + lld-link produce real PE/COFF and a real PDB on
# Linux, with three caveats learned the hard way:
#
#   1. /nodefaultlib is REQUIRED -- the MSVC runtime import libraries are not
#      present, so lld-link cannot resolve libcmt.lib/oldnames.lib. Every
#      fixture in this lane is therefore freestanding.
#   2. Freestanding means CRT symbols must be supplied by hand: `_fltused` for
#      any TU using float/double (and `_tls_index` for __declspec(thread)).
#   3. lld-link emits no TLS data directory for such a DLL at all, so this lane
#      cannot produce a TLS fixture.
set -euo pipefail
cd "$(dirname "$0")"
for t in clang-cl lld-link; do
  command -v "$t" >/dev/null || { echo "need $t" >&2; exit 1; }
done
clang-cl /c /Z7 /Od types.c -o types.obj
lld-link /dll /debug /noentry /nodefaultlib /out:types.dll /pdb:types.pdb types.obj
rm -f types.obj
python3 - <<'PY'
import hashlib, json, pathlib
m = json.loads(pathlib.Path("MANIFEST.json").read_text())
for n in ("types.dll", "types.pdb"):
    m[n] = {"sha256": hashlib.sha256(pathlib.Path(n).read_bytes()).hexdigest(),
            "size": pathlib.Path(n).stat().st_size}
pathlib.Path("MANIFEST.json").write_text(json.dumps(m, indent=2) + "\n")
print("MANIFEST.json refreshed")
PY
