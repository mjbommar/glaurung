# WP3 caller stack-arity identities

Commit `ebcd6440` removes display-name classification from the separate
caller-derived fixed-arity pipeline.

`src/program/caller_environment.rs` now retains `ValueIdentities` when it
value-numbers and lowers each direct caller. `src/ir/caller_arity.rs` threads
that authority through recursive AST traversal and proves:

- each outgoing stack push uses actual `rsp` storage;
- the post-call cleanup consumes the matching byte count;
- an optional alignment word is real stack adjustment; and
- unrelated intervening assignments are skipped by identity rather than text.

Missing or ambiguous identity evidence fails closed. The old no-sidecar
helpers remain available only to their local tests and are absent from release
builds.

The exact regression follows an opaque value backed by `rsp` across allocation,
store, and cleanup, while correctly ignoring a value named `rsp#...` whose
identity is actually `rax`.

Focused validation only:

```text
cargo test --features python-ext --lib \
  ir::caller_arity::tests::caller_stack_arity_uses_exact_identity_not_display_spelling \
  -- --exact
# 1 passed; 4,489 filtered out

cargo test --features python-ext --lib ir::caller_arity::tests::
# 4 passed; 4,486 filtered out

cargo test --features python-ext --lib \
  ir::call_args::tests::sysv_stack_area_uses_exact_identity_not_display_spelling \
  -- --exact
# 1 passed; 4,489 filtered out

uv run maturin develop
uv run python tools/build_guard.py
# fresh

uv run python tools/dectest.py \
  06_calling_conventions:gcc:O0:sum_arg7 --show
# SCOPED: 1 lane of 838; no regressions in scope
```

No broad Rust/Python suite, fixture matrix, DecBench run, or Joern run was used
for this bounded increment.
