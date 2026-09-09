# WP3 coalesced return-storage type refinement

Status: bounded WP3/WP6 consumer migration landed at `eed616e3` on
`master`.

## Result

Calling-convention-aware return refinement now recognizes a destination as ABI
result storage through the identity sidecar's unambiguous physical base rather
than requiring one exact SSA value. When several coalesced candidates all use
the return register and agree on one narrow definition width, a later scalar
return can override an earlier pointer interpretation.

Mixed physical bases and mixed or missing width evidence still decline. The
change does not merge SSA values or infer a width from display spelling: return
storage and definition width remain two separate conservative facts.

## Focused evidence

The behavior-level regression first proved that raw recovery classified the
coalesced value as a pointer. Before implementation, the final assertion then
failed with `Pointer { pointee_width: 1 }` instead of the required four-byte
integer. After implementation:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  coalesced_return_storage_uses_unambiguous_base_and_width --quiet
1 passed; 0 failed; 4,756 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib return_refinement --quiet
1 passed; 0 failed; 4,756 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  return_type_narrowed_from_last_definition --quiet
1 passed; 0 failed; 4,756 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  VIRTUAL_ENV=/home/mjbommar/projects/personal/glaurung/.venv \
  uvx maturin develop --release
release build completed in 36.83 s

PYTHONPATH=/home/mjbommar/.cache/glaurung/verify-b04e0b78/python \
  python tools/dectest.py \
  '194_narrow_return_widths:gcc:O0:nrw194_i8_divide' \
  --show --allow-stale
1 of 838 lanes selected; no regression in scope

TMPDIR=/home/mjbommar/.cache/glaurung/tmp GLAURUNG_ALLOW_STALE=1 \
  PYTHONPATH=/home/mjbommar/.cache/glaurung/verify-b04e0b78/python \
  pytest -q \
  'python/tests/test_linux_x86_64_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O0-gcc]' \
  'python/tests/test_linux_x86_64_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O2-gcc]'
2 passed
```

The exact release checks imported
`/home/mjbommar/.cache/glaurung/verify-b04e0b78/python/glaurung/_native.cpython-312-x86_64-linux-gnu.so`
from detached commit `eed616e3`; its SHA-256 is
`f192788bac907f0653801acf9adf6e6d424d4821ce57e0908cbef2e5b50f52bf`.
The main-tree timestamp guard required an explicit stale override because
concurrent main sources had newer mtimes. Commit identity, import path, and
native-module hash were checked directly.

## Measurement boundary

Only three named Rust tests, one fixture-194 GCC O0 lane, and two x86-64 GCC
symbols/PIE Hello cells ran. No broad Rust/Python suite, complete Hello grid,
fixture matrix, DecBench, Joern, GED, performance, or corpus-wide measurement
ran. An attempted historical `strops:str_len` selector was rejected because
`strops` is not in the current manifest and is not counted as evidence.

## Remaining scope

This closes return refinement's physical-storage lookup while preserving its
independent unambiguous-width gate. WP3 and WP6 remain open. Entry-value,
frame-version, and packed-lane consumers remain exact by design; the remaining
identity consumers still require case-by-case classification and bounded
proof.
