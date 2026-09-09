# WP3 coalesced x86 storage identity

Status: bounded production consumer migration landed at `1f58963c` on
`master`.

## Result

X86 prologue and epilogue recognition now classify physical register storage
through the identity sidecar's unambiguous physical base rather than requiring
one exact SSA value. Legal coalescing of multiple versions of one register can
therefore retain callee-save classification, restore-register matching, and the
`rsp` padding exclusion.

Mixed physical bases and missing identity evidence still decline. An
identity-aware path never reparses a misleading display name; no-sidecar
compatibility behavior remains unchanged.

## Focused evidence

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  typed_callee_save_classification_accepts_one_physical_base --quiet
1 passed; 0 failed; 4,755 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib 'ir::x86_prologue::tests::' --quiet
45 passed; 0 failed; 4,711 filtered out; 0.20 s

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  VIRTUAL_ENV=/home/mjbommar/projects/personal/glaurung/.venv \
  uvx maturin develop --release
release build completed in 37.24 s

TMPDIR=/home/mjbommar/.cache/glaurung/tmp GLAURUNG_ALLOW_STALE=1 \
  PYTHONPATH=/home/mjbommar/.cache/glaurung/verify-b04e0b78/python \
  pytest -q \
  'python/tests/test_linux_x86_64_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O0-gcc]' \
  'python/tests/test_linux_x86_64_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O2-gcc]'
2 passed
```

The coalesced-same-base unit contract was observed red before implementation.
The focused module slice retains mixed-base and misleading-display-name
refusals.

The Hello checks imported
`/home/mjbommar/.cache/glaurung/verify-b04e0b78/python/glaurung/_native.cpython-312-x86_64-linux-gnu.so`
from detached commit `1f58963c`; its SHA-256 is
`d9223d0f76d9e5eb5058b5c6862b0cf748a9660b8d62e6a684c991c360c6e9cb`.
`GLAURUNG_ALLOW_STALE=1` bypassed only the main-tree mtime comparison; the
detached commit, import path, and native-module hash were checked directly.

## Measurement boundary

Only the owning Rust module and two directly relevant x86-64 GCC symbols/PIE
Hello cells ran. No broad Rust/Python suite, 72-cell Hello grid, fixture matrix,
DecBench, Joern, GED, performance, or corpus-wide measurement ran. The broader
six-cell x86-64/AArch64/ARMv7 O0/O2 checkpoint remains green from the preceding
output-changing WP3 increments.

## Remaining scope

This closes x86 prologue recognition's physical-register storage lookup. WP3
remains open: remaining exact-identity consumers require case-by-case
classification, fail-closed contracts, and bounded production validation.
