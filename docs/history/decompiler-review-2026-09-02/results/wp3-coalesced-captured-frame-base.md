# WP3 coalesced captured frame-base identity

Status: bounded production consumer migration landed at `df7a9b46` on
`master`.

## Result

Stable captured frame-load analysis now recognizes a fixed `rbp`/`ebp` address
through the identity sidecar's unambiguous physical base rather than requiring
one exact SSA value. Legal coalescing of multiple versions of the same frame
register can therefore retain safe call-argument substitution.

The same proof guards fixed-frame reads, intervening frame writes, and
frame-base invalidation. Mixed physical bases, missing identity evidence, and
misleading display names still decline. No-sidecar compatibility callers retain
the spelling fallback.

## Focused evidence

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  stable_frame_load_uses_unambiguous_identity_not_display_spelling --quiet
1 passed; 0 failed; 4,755 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib 'ir::call_args::tests::' --quiet
129 passed; 0 failed; 4,627 filtered out; 0.20 s

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  VIRTUAL_ENV=/home/mjbommar/projects/personal/glaurung/.venv \
  uvx maturin develop --release
release build completed in 36.63 s

PYTHONPATH=/home/mjbommar/.cache/glaurung/verify-b04e0b78/python \
  python tools/dectest.py \
  '11_call_shapes:clang:O0:call_into_spill' --show --allow-stale
1 of 838 lanes selected; no regression in scope
```

The coalesced-same-base contract was observed red before the implementation.
The focused slice also retains the mixed-base and misleading-spelling refusal
cases.

The real-binary check imported
`/home/mjbommar/.cache/glaurung/verify-b04e0b78/python/glaurung/_native.cpython-312-x86_64-linux-gnu.so`
from detached commit `df7a9b46`; its SHA-256 is
`b25401ba0eac4b0ece23f7425db74ae87b7bf23421025305d131288705fb1ff4`.
The main-tree timestamp guard required `--allow-stale` because concurrent main
sources had newer mtimes. Commit identity, import path, and module hash were
checked directly before accepting the result.

## Measurement boundary

Only the owning Rust module and one directly related Clang O0 x86-64 fixture
lane ran. No broad Rust/Python suite, fixture matrix, DecBench, Joern, GED,
performance, or corpus-wide measurement ran. The last periodic Hello checkpoint
remains the six passing x86-64/AArch64/ARMv7 O0/O2 cells recorded at
`29b202a9`/`57a6b936`; this output-neutral identity migration did not repeat it.

## Remaining scope

This closes the captured fixed-frame-address physical-storage classifier. WP3
remains open: each remaining exact-identity consumer still needs classification
as physical storage, exact value equality, or entry/version-specific semantics,
followed by its own fail-closed migration and bounded production control.
