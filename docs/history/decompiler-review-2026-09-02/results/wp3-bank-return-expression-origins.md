# WP3 bank-return expression origins

Date: 2026-09-08

Commit: `1c37e83d`

## Defect and repair

The callee bank-return pass reconstructs SysV SSE-pair and split-bank results,
plus AAPCS64 homogeneous-float aggregates, only when every return and the
second-bank write prove one complete object. Its statement transformations
already retained origins, but several return values, promoted stores, object
addresses, and register projections were still matched as raw expressions.
An origin carrier could therefore make the all-or-nothing proof decline.

`src/ir/callee_return_bank.rs` now reads those values through
`Expr::semantic()`. Object identity and extent, second-bank offset, declared
return class, exact carrier identity, and all-return-path requirements are
unchanged. When a stack-backed return is rewritten to the canonical
whole-object load, the new expression inherits the original returned
expression's origin set; the evidence is not discarded after recognition.

## Focused validation

The existing attributed stack-return contract now places an independent origin
on its returned load. It was observed red before the repair because composition
declined. The test also asserts that the synthesized whole-object load retains
that exact expression owner. The attributed register-projection contract now
exercises a wrapped return carrier as well. The complete owning module passes:

```text
running 23 tests
.......................
test result: ok. 23 passed; 0 failed; 0 ignored; 4673 filtered out
```

No repository-wide Rust or Python suite ran. Release validation used a detached
clean worktree at the implementation commit and a cache-backed build directory:

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
export CARGO_TARGET_DIR=/home/mjbommar/.cache/glaurung/wp3-arm-anchor-release-target
uv sync --locked --dev
uv run maturin develop --release
uv run python tools/build_guard.py
uv run python tools/dectest.py \
  197_homogeneous_float_aggregates:gcc:O0:hfa197_make_trio3f --show
```

Result:

```text
native extension: fresh
SCOPED: 1 lane of 838 (0%) - no regressions in scope
```

This is one exact AArch64 O0 homogeneous-float aggregate return lane, not the
full aggregate or repository suite. It closes the known raw-expression readers
in callee bank-return composition; universal WP3 attribution and explicit
invalidation remain open.
