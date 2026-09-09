# WP3 coalesced SSE argument-slot blocking

Status: bounded production consumer migration landed at `a9e9b0ab` on
`master`.

## Result

Partial recovered call-layout folding now classifies every candidate identity
of an SSE destination by ABI argument slot. Multiple packed-lane identities
that all belong to one carrier, such as `xmm0_d0` and `xmm0_d1`, block the same
`xmm0` slot. The fold can no longer substitute a stale enclosing `xmm0` value
after such a write.

Candidates that disagree on the ABI slot fail closed by blocking the complete
storage set. Missing sidecar evidence retains the existing conservative
identity-aware behavior, and the compatibility path continues to parse only
when no sidecar is present.

## Focused evidence

Before implementation, the behavior contract folded the call and invented the
stale enclosing SSE argument. After implementation:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  coalesced_sse_lane_write_blocks_stale_enclosing_layout_value --quiet
1 passed; 0 failed; 4,757 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib 'ir::call_args::tests::' --quiet
130 passed; 0 failed; 4,628 filtered out; 0.19 s

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  VIRTUAL_ENV=/home/mjbommar/projects/personal/glaurung/.venv \
  uvx maturin develop --release
release build completed in 37.98 s

PYTHONPATH=/home/mjbommar/.cache/glaurung/verify-b04e0b78/python \
  python tools/dectest.py \
  '197_homogeneous_float_aggregates:gcc:O2:hfa197_pair2d_roundtrip' \
  --show --allow-stale
1 of 838 lanes selected; no regression in scope
```

The unit contract covers both two lane identities resolving to one SSE slot and
two candidates resolving to different SSE slots. A declined fold is also
required to leave the body byte-for-byte unchanged.

The real-binary check imported
`/home/mjbommar/.cache/glaurung/verify-b04e0b78/python/glaurung/_native.cpython-312-x86_64-linux-gnu.so`
from detached commit `a9e9b0ab`; its SHA-256 is
`bad5018d47879a125289f3ccd4c1c4684fc71a532ee6f1e14fbfbe39d632ca96`.
The main-tree timestamp guard required `--allow-stale` because concurrent main
sources had newer mtimes. Commit identity, import path, and module hash were
checked directly.

## Measurement boundary

Only the owning Rust module and one directly related GCC O2 aggregate/SSE call
fixture ran. No broad Rust/Python suite, complete Hello grid, fixture matrix,
DecBench, Joern, GED, performance, or corpus-wide measurement ran. The
immediately preceding exact-release x86-64 GCC O0/O2 symbols/PIE Hello
checkpoint remains green.

## Remaining scope

This closes the SSE write-blocking proof used by partial recovered call
layouts. WP3 remains open. Exact reaching definitions, incoming values, and
packed-vector reconstruction remain version-sensitive; other storage-role and
slot-classification consumers still require separate fail-closed audits.
