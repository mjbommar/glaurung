# WP3 frame parameter homes through expression carriers

> **Kind:** record · **Date:** 2026-09-10

## Outcome

Commit `221bfeea` closes the frame-array half of parameter-spill expression
ownership. Parameter-home discovery, exact-reload proof, store removal, and
reload rewriting now compare the semantic frame address rather than treating
instruction-origin carriers as part of storage identity. Reload discovery and
rewriting also traverse `NumericConvert` and value-producing `Call`
expressions, matching the expression forms already traversed by the pass's
rename phase.

This is deliberately narrower than alias analysis. Access width and semantic
frame address must still match exactly, the home must have one store, and the
store source must retain authoritative parameter ownership whenever an
identity sidecar is present. The replacement mutates only the semantic node,
so an owner attached to the surviving reload expression remains attached.

## Observed-red and focused verification

`differently_attributed_frame_addresses_are_coalesced` was observed red first:
the store and reload used the same `StackAddr`, but different expression
owners made the pass retain both the redundant store and dereference. After
the repair, the store is removed and the reload becomes the source parameter
without losing its owner. A second contract covers a reload nested under a
numeric conversion inside a value-producing call.

```text
cargo test --features python-ext --lib \
  ir::ast::param_spills::tests::differently_attributed_frame_addresses_are_coalesced \
  -- --exact
1 passed; 0 failed; 4,778 filtered out

cargo test --features python-ext --lib ir::ast::param_spills::tests::
8 passed; 0 failed; 4,772 filtered out
```

Filtered tests were not executed.

## Exact release checkpoints

A clean detached worktree at exact commit `221bfeea` was release-built. The
build guard reported fresh with native SHA-256
`e35842bab5621500293e4add427b55ab37cf949510695be1a98d4258013363c5`.

The directly adjacent ARM hard-float execution round trip passes. A clean
release build of parent `56470350` passes the same test, so this is a retained
control rather than an attributable product-output improvement.

```text
uv run --no-sync pytest -q \
  python/tests/test_cli_decompile.py::test_real_arm_hard_float_call_round_trip
1 passed
```

The periodic canonical Hello World checkpoint selected dynamic symbols/PIE
O0 and O2 cells from both owning test modules. All 16 selected nodes pass
across GCC/Clang x86-64 and GCC AArch64/ARMv7.

```text
uv run --no-sync pytest -q \
  python/tests/test_linux_x86_64_hello_canonical.py \
  python/tests/test_linux_arm_hello_canonical.py \
  -k 'dynamic_hello_is_canonical and symbols and pie and (O0 or O2)'
16 passed
```

The repository-required whole-Python checkpoint terminated red. Its final
aggregate line was clipped by the terminal transport, so no pass/skip totals
are claimed; pytest's completed-run cache contains 157 failing node IDs. Those
failures span the repository's existing architecture, baseline, dialect,
documentation, inventory, and variadic debts. Neither new parameter-spill
test is in that set. The run also regenerated two stale committed inventories:
the test census moves from 5,198 to 5,317 declared Rust tests, and the facet
manifest adds two already-committed Python test files. Those exact-clean-tree
generator outputs are committed with this record rather than being generated
from the concurrently dirty shared checkout.

This red checkpoint is not evidence that the whole repository is green, and
without a matched parent run it is not a broad regression comparison. No
DecBench or Joern gate was run for this bounded increment.

## Next boundary

Continue the enabled WP3 expression-consumer audit. Keep semantic storage
equality distinct from display spelling and from provenance, and require an
observed product or unit failure before broadening another consumer.
