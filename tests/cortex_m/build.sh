#!/usr/bin/env bash
# Rebuild the committed Cortex-M object.
#
# COMMITTED, like tests/decompiler_fixtures/canary/: the regression test must
# run on a clone with no ARM toolchain. It is an unlinked .o on purpose --
# 1.1 KB, and the defect it pins is in instruction DECODING, which needs no
# link. Rerun only to change what it contains, then refresh MANIFEST.json.
set -euo pipefail
cd "$(dirname "$0")"
command -v arm-none-eabi-gcc >/dev/null || {
  echo "need arm-none-eabi-gcc (apt install gcc-arm-none-eabi)" >&2; exit 1; }
arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -O1 -c -o rtos.o rtos.c
python3 - <<'PY'
import hashlib, json, pathlib
p = pathlib.Path("rtos.o")
m = json.loads(pathlib.Path("MANIFEST.json").read_text())
m["sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
m["size"] = p.stat().st_size
pathlib.Path("MANIFEST.json").write_text(json.dumps(m, indent=2) + "\n")
print("MANIFEST.json refreshed:", m["sha256"][:16], m["size"])
PY
