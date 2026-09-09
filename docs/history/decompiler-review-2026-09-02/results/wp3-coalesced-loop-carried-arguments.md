# WP3 coalesced loop-carried call arguments

Status: bounded production consumer migration landed at `28e70130` on
`master`.

## Result

Loop-carried ABI argument discovery no longer requires one exact SSA identity.
A coalesced loop value is accepted only when all candidates classify to one ABI
argument slot, every candidate is a non-entry version, and the pre-loop
initializer carries the same nonempty stable `ValueId` set. A call must still
precede the back-edge update.

Mixed ABI slots, entry-version candidates, differently initialized values,
missing value IDs, and misleading display names all decline. The no-sidecar
compatibility path remains unchanged.

## Focused evidence

The coalesced same-slot regression was observed red before implementation: slot
zero remained `None` instead of naming `opaque_loop`. After implementation:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  loop_carried_input_uses_stable_identity_set_not_display_spelling --quiet
1 passed; 0 failed; 4,757 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib loop_carried --quiet
18 passed; 0 failed; 4,740 filtered out; 0.17 s

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib 'ir::call_args::tests::' --quiet
130 passed; 0 failed; 4,628 filtered out; 0.19 s

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  VIRTUAL_ENV=/home/mjbommar/projects/personal/glaurung/.venv \
  uvx maturin develop --release
release build completed in 38.29 s

PYTHONPATH=/home/mjbommar/.cache/glaurung/verify-b04e0b78/python \
  python tools/dectest.py \
  '11_call_shapes:gcc:O2:call_chain_in_loop' \
  '11_call_shapes:aarch64:O2:call_chain_in_loop' \
  --jobs 2 --show --allow-stale
2 of 3,304 lanes selected; no regressions in scope
```

The identity contract covers same-slot coalescing, mixed-slot refusal, and a
misleading `rdi` display name backed by `rax`.

The fixture checks imported
`/home/mjbommar/.cache/glaurung/verify-b04e0b78/python/glaurung/_native.cpython-312-x86_64-linux-gnu.so`
from detached commit `28e70130`; its SHA-256 is
`8fa623c39ef09c013fff0cacd037eb4da38008fb25f41889b091cd749fed4a6d`.
The main-tree timestamp guard required `--allow-stale` because concurrent main
sources had newer mtimes. Commit identity, import path, and module hash were
checked directly.

## Measurement boundary

Only the owning Rust module, its 18 loop-carried tests, and two directly related
O2 fixture lanes ran. No broad Rust/Python suite, complete Hello grid, fixture
matrix, DecBench, Joern, GED, performance, or corpus-wide measurement ran. The
recent exact-release x86-64 GCC O0/O2 symbols/PIE Hello checkpoint remains
green.

## Remaining scope

This closes loop-carried argument discovery's singleton-identity limitation.
WP3 remains open. Exact reaching definitions still require a uniquely named
version at a specific program point; other physical-role, ABI-slot, and stable-
value comparisons continue to require case-by-case migration.
