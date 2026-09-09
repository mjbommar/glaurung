# WP3 stack-address expression origins

Date: 2026-09-08

Commit: `e1e3784e`

## Defect

The stack-local pass already traversed statement provenance with
`Stmt::semantic()`, but its shared address-recovery layer matched the enclosed
expressions literally. Once WP3 attached an `Expr::Origin` to an address such
as `rsp + 64`, coordinate propagation could no longer recognize it. That could
prevent the address definition and later indexed access from rejoining the same
promoted stack object.

This was a production semantic-reader omission, not a renderer-only spelling
issue. Patching only `collect_stack_address_defs` would have left the same
failure in memory, escape, and liveness consumers.

## Change

`src/ir/stack_locals/address_recovery.rs` now uses the canonical semantic view
at each classification boundary:

- scalar and displaced stack addresses;
- scaled or shifted dynamic indices;
- reconstructed arithmetic memory addresses;
- direct and escaping frame addresses; and
- constant frame-address components.

`src/ir/stack_locals/coordinate_flow.rs` applies the same rule when deciding
whether a later expression still roots at a frame coordinate. The AST and its
origin sets are not stripped or rebuilt: only the read-only classification sees
through the carrier.

## RED/GREEN evidence

The new end-to-end stack-promotion contract is:

```text
ir::stack_locals::tests::expression_origin_wrapped_stack_alias_still_promotes_an_indexed_object
```

Before the resolver repair, it failed because the attributed alias remained an
ordinary assignment rather than becoming the expected 40-byte `StackAddr`.
After the repair:

```text
running 1 test
test ir::stack_locals::tests::expression_origin_wrapped_stack_alias_still_promotes_an_indexed_object ... ok
test result: ok. 1 passed; 0 failed; 4675 filtered out
```

The owning module was then run directly from the clean isolated build, avoiding
the thousands of unrelated repository tests:

```text
running 115 tests
test result: ok. 115 passed; 0 failed; 4561 filtered out
```

Formatting and patch integrity:

```bash
rustfmt --edition 2021 \
  src/ir/stack_locals.rs \
  src/ir/stack_locals/address_recovery.rs \
  src/ir/stack_locals/coordinate_flow.rs
git diff --check -- \
  src/ir/stack_locals.rs \
  src/ir/stack_locals/address_recovery.rs \
  src/ir/stack_locals/coordinate_flow.rs
```

## Release fixture evidence

The shared checkout contained an unrelated in-flight decoder module whose
compile-time corpus was incomplete. Validation therefore used a detached clean
worktree at the parent commit with only this increment applied, a separate
cache-backed target directory, and its own virtual environment. This neither
modified nor installed over the shared checkout's extension.

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
export CARGO_TARGET_DIR=/home/mjbommar/.cache/glaurung/wp3-origin-release-target
uv sync --locked --dev
uv run maturin develop --release
uv run python tools/dectest.py \
  20_graph_bfs:gcc:O2:graph_bfs --show
```

Result:

```text
SCOPED: 1 lane of 838 (0%) - no regressions in scope
```

This proves the focused stack-address fixture remains at its committed green
baseline on a release build. It is deliberately not a claim about the full
fixture corpus or every remaining expression-origin consumer.
