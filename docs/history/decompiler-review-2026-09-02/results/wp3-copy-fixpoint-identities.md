# WP3 copy-fixpoint identities

Commit `f273123e` repairs a dropped identity sidecar at the main AST
copy/constant fixpoint.

`prepare_for_decbench_with_output_and_protected_locals_and_report` already
accepted `ValueIdentities` and passed it to constant folding and many adjacent
copy consumers. Its bounded fixpoint nevertheless called the identity-free
`propagate_copies`, so the central copy-propagation and dead-copy transaction
could still classify storage from presentation spelling. In particular, an
opaque stack object that promotion owned was deleted as an unobserved scratch.

The fixpoint now selects `propagate_copies_with_identities` whenever the
production caller supplies the sidecar. The compatibility preparation API keeps
the identity-free path. A preparation-level regression constructs an opaque
promoted object and proves its write survives the complete fixpoint. This test
was observed red before the repair (`1` statement remained instead of `2`) and
green afterward.

Focused validation used the debug Rust/Python build:

```text
cargo test --features python-ext --lib \
  ir::ast::prepare::fixpoint_tests::preparation_fixpoint_uses_promoted_storage_identity \
  -- --exact
1 passed

cargo test --features python-ext --lib ir::ast::prepare::fixpoint_tests::
4 passed; 4,658 filtered out

cargo test --features python-ext --lib ir::copy_prop::tests::
34 passed; 4,628 filtered out

uv run maturin develop
success
```

The requested periodic dynamic Hello World canary was also sampled narrowly at
symbols/non-PIE O0 and O2. AArch64 passed both cells. Host GCC failed both
because the string remained address `0x402004`; an A/B rebuild with this exact
patch reversed reproduced both failures unchanged. ARMv7 also retained two
existing failures: unresolved string addresses plus O0 frame artifacts and O2
signature over-recovery. These are current roadmap debt, not regressions from
this increment, and the Hello matrix is not green.

The isolated exact-source census records 5,192 declared tests, 2,487 in IR, and
zero tests outside every gate; all six census checks pass after committing the
generated baseline in the isolated archive.

No broad suite, fixture corpus, DecBench, or Joern ran. This makes production
AST copy propagation consume the identity sidecar it was already given, but it
does not yet move copy propagation before AST lowering or complete WP3.
