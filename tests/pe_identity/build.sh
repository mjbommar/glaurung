#!/usr/bin/env bash
# Rebuild the PE32/PE32+ identity fixtures.
#
# COMMITTED so the lane runs on a clone with no Windows toolchain. `helperN.dll`
# exists to make the IMPORT real: linking against its generated import library
# is what puts `imported_helper` in ident's import table, rather than a
# synthesized entry that would only test the test.
#
# /nodefaultlib is required (no MSVC runtime import libraries here), so the
# sources are freestanding and define `_fltused` themselves.
set -euo pipefail
cd "$(dirname "$0")"
for t in clang-cl lld-link; do
  command -v "$t" >/dev/null || { echo "need $t" >&2; exit 1; }
done
for bits in 32 64; do
  if [ "$bits" = 32 ]; then m=-m32; mach=X86; else m=-m64; mach=X64; fi
  clang-cl $m /c /Z7 /Od helper.c -o helper$bits.obj
  lld-link /dll /debug /noentry /nodefaultlib /machine:$mach \
    /out:helper$bits.dll /implib:helper$bits.lib /pdb:helper$bits.pdb helper$bits.obj
  clang-cl $m /c /Z7 /Od ident.c -o ident$bits.obj
  lld-link /dll /debug /noentry /nodefaultlib /machine:$mach \
    /out:ident$bits.dll /pdb:ident$bits.pdb ident$bits.obj helper$bits.lib
  rm -f helper$bits.obj ident$bits.obj helper$bits.lib helper$bits.pdb
done
python3 - <<'PY'
import hashlib, json, pathlib
m = json.loads(pathlib.Path("MANIFEST.json").read_text())
for n in sorted(p.name for p in pathlib.Path(".").glob("*.dll")) + \
         sorted(p.name for p in pathlib.Path(".").glob("*.pdb")):
    p = pathlib.Path(n)
    m[n] = {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "size": p.stat().st_size}
pathlib.Path("MANIFEST.json").write_text(json.dumps(m, indent=2) + "\n")
print("MANIFEST.json refreshed")
PY
