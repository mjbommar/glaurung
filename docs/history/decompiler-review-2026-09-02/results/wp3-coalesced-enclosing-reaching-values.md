# WP3 coalesced enclosing reaching values

Status: bounded production consumer migration landed at `b0ba8189` on
`master`.

## Result

`EnclosingSlots::advance_reaching` now records a coalesced top-level assignment
when every candidate belongs to one complete ABI storage slot and every
candidate is a non-entry SSA version. Calls inside a nested branch or loop can
therefore retain the exact displayed value and its instruction origins instead
of losing the argument solely because phi coalescing produced several identity
candidates.

Candidates spanning multiple ABI slots, mixing packed lanes with whole
registers, or carrying malformed/non-canonical storage clear all stale reaching
state. Multiple packed lanes belonging to one SSE carrier remain derived values
and do not overwrite a previously proven whole-register definition. A
non-argument assignment leaves argument state unchanged, and the no-sidecar
compatibility path retains its existing versioned-name rule.

## Focused evidence

Before implementation, the upgraded contract both failed to record the
coalesced same-slot value and preserved stale state across ambiguous/malformed
assignments. After implementation:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  enclosing_reaching_state_uses_one_authoritative_storage_slot --quiet
1 passed; 0 failed; 4,757 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  origin_wrappers_do_not_hide_enclosing_reaching_definitions --quiet
1 passed; 0 failed; 4,757 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib \
  a_proven_table_call_reads_the_enclosing_reaching_definitions --quiet
1 passed; 0 failed; 4,757 filtered out

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib 'ir::call_args::tests::' --quiet
130 passed; 0 failed; 4,628 filtered out; 0.20 s

TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  VIRTUAL_ENV=/home/mjbommar/projects/personal/glaurung/.venv \
  uvx maturin develop --release
release build completed in 37.04 s

PYTHONPATH=/home/mjbommar/.cache/glaurung/verify-b04e0b78/python \
  python tools/dectest.py \
  '189_effectful_select:gcc:O2:se189_select_call' \
  --show --allow-stale
1 of 838 lanes selected; no regression in scope
```

The exact release check imported
`/home/mjbommar/.cache/glaurung/verify-b04e0b78/python/glaurung/_native.cpython-312-x86_64-linux-gnu.so`
from detached commit `b0ba8189`; its SHA-256 is
`d355c9c4baacfb4cb73ce3d67c8714da6d5f0c276833cf45ac226fe3e98f4bb9`.
The main-tree timestamp guard required `--allow-stale` because concurrent main
sources had newer mtimes. Commit identity, import path, and module hash were
checked directly.

## Measurement boundary

Only three named Rust controls, the owning 130-test `call_args` module, and one
directly related GCC O2 nested-call fixture ran. No broad Rust/Python suite,
complete Hello grid, fixture matrix, DecBench, Joern, GED, performance, or
corpus-wide measurement ran. The recent exact-release x86-64 GCC O0/O2 Hello
checkpoint remains green.

## Remaining scope

This closes the enclosing call-context singleton-identity limitation. WP3
remains open. The recorded value is still point-specific and must be cleared at
calls, transfers, joins, entry candidates, incomplete lane writes, and
ambiguous storage. Other exact-identity consumers require their own semantic
classification and bounded proof.
