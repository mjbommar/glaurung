# WP3 signed-comparison expression-origin rendering — 2026-09-08

> **Kind:** record · **Date:** 2026-09-08

Commit `098e7035` closes two bounded expression-origin consumer gaps in the
typed C renderer. It does not complete WP3's universal production attribution
or WP6's general constraint-based type solver.

## Defect and boundary

The renderer already had two deliberately narrow signed-comparison rules:

- remove a value-preserving explicit widening only when the declared signed
  width and the opposite literal prove that the comparison is unchanged; and
- preserve an authoritative unsigned parameter declaration while spelling an
  exact signed machine edge as a same-width signed cast at that use.

Both rules matched the raw expression tree. Once provenance wrapped a constant,
cast, or register in `Expr::Origin`, the proof failed and the output either
regressed to a redundant widening or lost the necessary per-use signed cast.
The repair uses `Expr::semantic()` only at those five reads. It does not discard
origins, change declaration authority, broaden either rule to composite
expressions, or change the existing literal-width refusal.

## Observed RED and focused verification

With origins added to the existing positive contracts, both exact tests failed
before the production change:

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
cargo test --features python-ext --lib \
  ir::ast::tests::signed_comparison_drops_only_a_value_preserving_declared_widening \
  -- --exact
cargo test --features python-ext --lib \
  ir::ast::tests::signed_machine_comparison_casts_an_authoritative_unsigned_parameter_per_use \
  -- --exact
```

The first emitted `((long)(arg0) < 100)` instead of the proven direct
comparison. The second emitted `arg0 < 0x100000000` without the signed per-use
interpretation. After the repair, both exact tests pass; each run filters out
4,669 unrelated tests. Their existing adjacent assertions continue to cover a
too-wide literal and a non-authoritative recovered declaration.

The release extension was rebuilt and one matching real-binary lane was run:

```bash
uv run maturin develop --release
uv run python tools/dectest.py \
  215_switch_on_wide_selector:clang:O2:wide_selector_high_labels \
  --full --show
```

Result: one selected lane passes with no regression in scope. No broad fixture
matrix or whole repository suite was run for this bounded renderer change.

## Next action

Continue the WP3 audit one expression consumer at a time: first strengthen an
existing exact contract with real origin carriers, observe the failure, make
only the semantic read transparent, and run the smallest real fixture that
exercises the same rule.
