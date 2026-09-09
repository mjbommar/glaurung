# WP3 coalesced scalar-float storage identity

Status: bounded production consumer migration landed at `51780adb` on
`master`.

## Result

The whole-function scalar-float gate now classifies ARM VFP, x86 SSE, and x87
register storage through the identity sidecar's unambiguous physical base
rather than requiring one exact SSA value. Legal coalescing of multiple
versions of one physical float register can therefore retain modeled scalar
float lowering.

Mixed physical bases and missing identity evidence still decline. A misleading
float-like display name backed by an integer register remains rejected, and
identity-aware production paths do not fall back to display spelling.

## Focused evidence

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  'ir::ast::float_gate::tests::' --quiet
2 passed; 0 failed; 4,754 filtered out; 0.00 s

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  VIRTUAL_ENV=/home/mjbommar/projects/personal/glaurung/.venv \
  uvx maturin develop --release
release build completed in 37.27 s

PYTHONPATH=/home/mjbommar/.cache/glaurung/verify-b04e0b78/python \
  python tools/dectest.py \
  '197_homogeneous_float_aggregates:gcc:O2:hfa197_tagged_control' \
  --show --allow-stale
1 of 838 lanes selected; no regression in scope
```

The coalesced-same-base unit contract was observed red before implementation.
The focused test retains mixed-base and misleading-display-name refusals.

The real-binary check imported
`/home/mjbommar/.cache/glaurung/verify-b04e0b78/python/glaurung/_native.cpython-312-x86_64-linux-gnu.so`
from detached commit `51780adb`; its SHA-256 is
`3d993817d337edd0f41cfff636dfd9f6fec90fcb6912dab08d48443d442ddd60`.
The main-tree timestamp guard required `--allow-stale` because concurrent main
sources had newer mtimes. Commit identity, import path, and native-module hash
were checked directly before accepting the result.

## Measurement boundary

Only the owning Rust module and one directly related GCC O2 x86-64 fixture lane
ran. No broad Rust/Python suite, Hello grid, fixture matrix, DecBench, Joern,
GED, performance, or corpus-wide measurement ran. The immediately preceding
x86-64 GCC O0/O2 symbols/PIE Hello checkpoint remains green.

## Remaining scope

This closes the scalar-float gate's physical-register lookup. WP3 remains open.
Packed-lane lowering retains exact version-sensitive identity, while remaining
physical-storage, exact-value, and entry-version consumers continue to require
separate classification and bounded evidence.
