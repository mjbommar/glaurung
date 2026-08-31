#!/usr/bin/env bash
# Clone the third-party reference checkouts on demand.
#
# These were git submodules until 2026-08-31. They had ZERO code consumers --
# nothing in src/, python/, tools/ or the build reads them; only prose in docs/
# cites them -- but `uv` and `pip` clone a git dependency WITH its submodules, so
# `uvx --from git+https://github.com/mjbommar/glaurung.git` spent minutes pulling
# ILSpy, Ghidra and 41 others before it could build. Installing the tool should
# not clone a reverse-engineering library collection.
#
# reference/specifications/ is NOT here: those 114 files are tracked in the repo
# and have real consumers.
#
# Usage:  scripts/fetch-reference.sh [name ...]     (default: all)
set -euo pipefail
cd "$(dirname "$0")/.."
declare -A REPOS=(
  [Cutter]="https://github.com/rizinorg/cutter.git"
  [Detect-It-Easy]="https://github.com/horsicq/Detect-It-Easy.git"
  [HyperDbg]="https://github.com/HyperDbg/HyperDbg.git"
  [LIEF]="https://github.com/lief-project/LIEF.git"
  [REDasm]="https://github.com/REDasmOrg/REDasm.git"
  [Triton]="https://github.com/JonathanSalwan/Triton.git"
  [alea-preprocess]="https://github.com/alea-institute/alea-preprocess.git"
  [angr]="https://github.com/angr/angr.git"
  [b2r2]="https://github.com/B2R2-org/B2R2.git"
  [bddisasm]="https://github.com/bitdefender/bddisasm.git"
  [binary-inspector]="https://github.com/aboutcode-org/binary-inspector.git"
  [capa]="https://github.com/mandiant/capa.git"
  [capstone]="https://github.com/capstone-engine/capstone.git"
  [capstone-rs]="https://github.com/capstone-rust/capstone-rs.git"
  [claripy]="https://github.com/angr/claripy.git"
  [cle]="https://github.com/angr/cle.git"
  [demangle-mode]="https://github.com/liblit/demangle-mode.git"
  [falcon]="https://github.com/falconre/falcon.git"
  [ghidra]="https://github.com/NationalSecurityAgency/ghidra.git"
  [goblin]="https://github.com/m4b/goblin.git"
  [iced]="https://github.com/icedland/iced.git"
  [ilspy]="https://github.com/icsharpcode/ILSpy.git"
  [keystone]="https://github.com/keystone-engine/keystone.git"
  [kuna]="https://github.com/Noelo-Lab/kuna.git"
  [lingua-rs]="https://github.com/pemistahl/lingua-rs.git"
  [manticore]="https://github.com/trailofbits/manticore.git"
  [miasm]="https://github.com/cea-sec/miasm.git"
  [object]="https://github.com/gimli-rs/object.git"
  [pharos]="https://github.com/cmu-sei/pharos.git"
  [pwndbg]="https://github.com/pwndbg/pwndbg.git"
  [pycdc]="https://github.com/zrax/pycdc.git"
  [radare2]="https://github.com/radareorg/radare2.git"
  [reko]="https://github.com/uxmal/reko.git"
  [retdec]="https://github.com/avast/retdec.git"
  [rizin]="https://github.com/rizinorg/rizin.git"
  [snowman]="https://github.com/x64dbg/snowman.git"
  [spirv-tools]="https://github.com/KhronosGroup/SPIRV-Tools.git"
  [symbolic]="https://github.com/getsentry/symbolic.git"
  [unicorn]="https://github.com/unicorn-engine/unicorn.git"
  [wabt]="https://github.com/WebAssembly/wabt.git"
  [xed]="https://github.com/intelxed/xed.git"
  [z3]="https://github.com/Z3Prover/z3.git"
  [zydis]="https://github.com/zyantific/zydis.git"
)
want=("$@"); [ ${#want[@]} -eq 0 ] && want=("${!REPOS[@]}")
for name in "${want[@]}"; do
  url="${REPOS[$name]:-}"
  [ -z "$url" ] && { echo "unknown: $name" >&2; continue; }
  dest="reference/$name"
  if [ -d "$dest/.git" ]; then echo "have $name"; continue; fi
  echo "cloning $name ..."
  git clone --depth 1 "$url" "$dest"
done
