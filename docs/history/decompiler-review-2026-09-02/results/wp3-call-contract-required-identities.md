# WP3 call-contract refinement requires identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `4e6c333d` removes the no-sidecar compatibility entry point from nominal
pointer refinement at canonical call boundaries. A register passed to a known
library function can now refine its caller's recovered parameter type only when
the pipeline-owned `ValueIdentities` sidecar assigns that exact value one
unambiguous source-parameter slot. A displayed name such as `arg0` is no longer
semantic evidence.

The sole production caller already supplies the prepared AST's projected
identity sidecar. The positive and conflict unit contracts now construct their
parameter identity explicitly, while the existing negative contract proves
that an unowned register spelled `arg0` remains unchanged.

## Focused evidence

The owning Rust module passed after the edit:

```text
cargo test --lib --features python-ext 'ir::call_contracts::tests::'
25 passed; 0 failed; 4,811 filtered out
```

A fresh release extension build completed, and `tools/build_guard.py` reported
`fresh` with native SHA-256
`7b0735b153c802070187f40ea7d74c66d51c6d94fcc35cfd2a9f959b0320f97b`.
The directly owning libc-pointer file then passed end to end:

```text
uv run --no-sync pytest -q python/tests/test_libc_pointer_roundtrip.py
3 passed; 0 failed
```

One adjacent project-local `int *` forwarding fixture was also sampled and
failed with `forward_pointer(long arg0)`. This is not a behavior of the nominal
opaque-pointer pass: its contract deliberately rejects `int *`, and the release
build contained concurrent uncommitted changes elsewhere under `src/`. The red
cell is therefore recorded without attributing or masking it; it needs owner
isolation in the corresponding direct-callee/high-variable lane.

No broad Rust, Python, fixture, DecBench, or Joern suite ran.

## Scope

This closes the canonical nominal call-contract consumer's dependence on
display-name parsing. It does not complete WP3 invalidation and origins, nor the
remaining declaration-planning and naming consumers.
