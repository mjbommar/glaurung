# WP3 integer-call expression-origin rendering — 2026-09-08

> **Kind:** record · **Date:** 2026-09-08

Commit `2be32b51` closes the integer half of the typed call-boundary origin
audit. It does not complete WP3's universal production attribution or replace
WP6's general constraint-based type solver.

## Defect and boundary

Typed call rendering already removes only conversions proven to be identities:
a chain of views may disappear when none is narrower than the parameter, and a
literal may lose its explicit cast only when the parameter type represents it
exactly. The three helpers implementing those proofs matched the raw expression
tree. Provenance carriers therefore caused safe cleanup to refuse even though
the underlying value and every width check were unchanged.

The new contract covers three arguments in one call:

1. an attributed 32-bit declared register inside attributed 32- and 64-bit
   non-narrowing views;
2. an attributed integer literal represented exactly by `int`; and
3. the same register behind an attributed one-byte narrowing view.

Before the production repair, the exact test emitted:

```c
consume_three((int)((unsigned long)((unsigned int)(arg0))),
              (int)(7),
              (int)((unsigned char)(arg0)));
```

Afterward it emits:

```c
consume_three(arg0, 7, (int)((unsigned char)(arg0)));
```

The byte view stays because it can discard information. The repair makes the
existing view walk, final register/global-load read, and redundant-cast match
transparent to `Expr::Origin`; it does not weaken any width, declared-type,
global-extent, or literal-range proof.

## Focused verification

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
cargo test --features python-ext --lib \
  ir::ast::tests::attributed_integer_call_arguments_drop_only_proven_identity_views \
  -- --exact
cargo test --features python-ext --lib \
  ir::ast::tests::declared_pointer_call_keeps_parameter_types_when_result_needs_conversion \
  -- --exact
uv run maturin develop --release
uv run --no-sync pytest \
  python/tests/test_cli_decompile.py::test_real_arm_mixed_hard_float_call_round_trip -q
```

Results: both exact Rust contracts pass with 4,671 unrelated tests filtered
out, and the one selected ARM mixed hard-float round trip compiles, decompiles,
recompiles, and executes successfully. No broad fixture matrix or whole
repository suite was run for this bounded renderer change.

## Next action

Continue the WP3 audit at the destination-side typed renderer. Preserve each
pointer, aggregate, float, and narrowing refusal while making only origin
carriers transparent to the already-proven semantic rules.
