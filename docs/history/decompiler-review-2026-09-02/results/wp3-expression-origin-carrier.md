# WP3 expression origin carrier

Commit `9b10f06e` introduces direct instruction ownership for C-like AST
expressions. This is the model and consumer-transparency foundation for
production expression attribution; it does not claim that lowering already
attaches origins to every expression.

## Contract

- `Expr::Origin` carries the same sorted, deduplicated `OriginSet` used by
  statements.
- Repeated attribution unions origins without nesting wrappers.
- `semantic`, `semantic_mut`, `into_semantic_with_origins`,
  `with_optional_origins`, and `merge_origins` provide one shared ownership
  boundary for later rewrites.
- Read-only consumers recurse through the semantic expression. Mutating
  consumers recurse inside the carrier, retaining ownership. The two existing
  expression-rebuilding substitutions explicitly restore and union ownership.
- Plain C, typed C, and DecBench rendering ignore the carrier and retain
  byte-identical text.

Adding the enum variant made Rust enumerate 87 initially non-exhaustive
consumer sites: 84 in the production library and three test-only helpers that
surfaced when the exact unit test compiled. Every one was migrated explicitly;
no wildcard fallback was added to hide an unreviewed semantic decision.

## Focused evidence

Production-library compilation is green:

```text
cargo check --features python-ext --lib
```

The exact new carrier/rendering test passes:

```text
cargo test --features python-ext --lib \
  expression_origins_union_without_nesting_and_render_transparently -- --nocapture

1 passed; 0 failed; 4346 filtered out
```

The complete origin module passes without running unrelated Rust tests:

```text
cargo test --features python-ext --lib ir::ast::origin::tests:: -- --nocapture

6 passed; 0 failed; 4341 filtered out
```

The required release extension rebuild completed in 35.44 seconds. The exact
GCC O0 `01_conditional_polarity::classify` output SHA-256 was identical before
and after the rebuild:

```text
352b9dcea12c84f1a5c9e2b1340bd2017080aa6e36b4276d122652e5e1c33e1c
```

Its one exact execution lane also passes:

```text
uv run python tools/dectest.py \
  '01_conditional_polarity:gcc:O0:classify' --full --show

SCOPED: 1 lane of 838 - no regressions in scope
```

No broad Rust/Python suite, fixture matrix, corpus sweep, or DecBench run was
used for this bounded identity-only increment.

## Remaining boundary

The next work is to attach instruction origins at the expression-reconstruction
boundary, preserve exact unions through folds/substitutions, and audit
non-exhaustive `if let`/`matches!` consumers that the Rust exhaustiveness
checker cannot enumerate. Until those are complete, statement mappings remain
the production line-mapping authority and universal expression attribution is
not claimed.
