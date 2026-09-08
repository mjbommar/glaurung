# WP3 canary-storage identities

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `2d53096b` removes the production stack-canary collapse pass's reliance
on a promoted object's `stack_` display spelling. The pipeline and late
DecBench-style renderer now supply `ValueIdentities`; an opaque object owned by
stack promotion is accepted, while an unowned value named `stack_4` fails
closed. The legacy no-sidecar entry point retains compatibility behavior.

This is a bounded WP3 identity-consumer migration, not WP3 completion. It does
not change canary recognition before stack promotion, the exit-check proof, or
the remaining value-identity and naming work.

## Focused evidence

Only tests belonging to this change were run:

```text
cargo test --features python-ext identity_aware_canary_save -- --nocapture
2 passed; 0 failed

cargo test --features python-ext ir::canary::tests -- --nocapture
24 passed; 0 failed

uv run maturin develop
uv run python tools/build_guard.py
fresh

uv run pytest -q \
  'python/tests/test_decompiler_canary.py::test_each_canary_decompiles_to_something_structural[07_packet_parser-gcc-O2.so]'
1 passed

uv run pytest python/tests/test_test_census.py -q
6 passed
```

The regenerated census records 5,158 declared Rust tests and zero tests outside
every gate. No broad Rust/Python suite, fixture matrix, corpus, DecBench, or
Joern run was made. The four-cell x86-64/AArch64 O0/O2 Hello checkpoint was not
repeated because it passed immediately before this metadata seam.

## Next ordered increment

Continue the WP3 audit with the next enabled production consumer that grants
semantic meaning from display spelling. Keep pre-sidecar compatibility paths
separate, and keep expression ownership and non-contiguous rewrite policy open.
