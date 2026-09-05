# WP7B bounded signed-predicate recovery

> **Kind:** record · **Date:** 2026-09-04

## Result

Commit `9c9c607c73e671b040c5499a1c817d3ab63d8bf1` recovers the terminal x86
signed-greater-than flag spelling used by the review's `classify` example:

```text
((u64)(u32)x == K | (i64)(i32)x < K) == 0
```

becomes the source-like equivalent `K < (i64)(i32)x`. The rule is deliberately
narrow. Both comparisons must name the same expression and constant through
strict widening casts with identical source and outer widths. Equality must use
the unsigned view, less-than must use the signed view, the constant must be
non-negative and signed-representable at the source width, and the complete
flag expression must be observed through equality to zero. The pass does not
merge the intermediate mixed-view OR, because doing so previously damaged
switch recovery.

This is the bounded pre-WP3 exception permitted by PLAN WP7B, not the general
SSA-idiom framework. It fixes the loop predicate. It does not yet infer a signed
return for stripped binaries or remove every redundant unsigned return cast;
those remain WP6 work.

## Proof and refusal tests

Commands:

```bash
cargo test --features python-ext terminal_mixed_view -- --nocapture
cargo test --features python-ext ir::const_fold::tests -- --nocapture
```

Results:

- 10 focused predicate tests passed;
- all 52 `const_fold` tests passed;
- exhaustive input-value checks passed at 8 and 16 bits for zero, low,
  midpoint, and maximum signed constants;
- boundary-complete plus 4,096 seeded values per constant passed at 32 and 64
  bits; and
- exact refusal tests passed for a negative/out-of-domain constant, different
  values, different constants, unsigned less-than, mixed widths, the wrong
  terminal polarity, and missing extension provenance.

## Real compiler and execution evidence

After an optimized extension build:

```bash
uv run maturin develop --release
uv run pytest python/tests/test_classify_signed_loop.py -q
```

Result: 2 parameterized tests passed, covering four binaries:

| compiler | optimization | debug state | predicate | differential |
|---|---|---|---|---:|
| GCC | O0 | DWARF | `100 < (long)(...)` | 34/34 |
| GCC | O0 | stripped debug | `100 < (long)(...)` | 34/34 |
| Clang | O0 | DWARF | `100 < (long)(...)` | 34/34 |
| Clang | O0 | stripped debug | `100 < (long)(...)` | 34/34 |

Every cell rejects the expanded `== 100) |` spelling, carries no definition
verification diagnostic, compiles with the host C syntax checker, and executes
the boundary differential successfully. The check covers negative, zero, 100,
101, repeated-subtraction, and integer-boundary inputs through
`tools/diff_decompile.py`'s deterministic 34-case set.

The scoped release corpus command was:

```bash
uv run python tools/dectest.py \
  @loops @polarity @switch @widths --jobs 8 --full
```

Result: 24 of 838 fixture lanes selected, all printed function verdicts passed,
and the harness reported zero regressions in scope. This specifically covers
the switch-ladder risk that motivates retaining the mixed-view intermediate
expression unless the complete terminal predicate is present.

## Repository gates

The required Rust gate was run in a clean detached worktree at the exact commit:

```bash
cargo test --features python-ext
```

The library reported 4,027 passed, 5 ignored, and 0 failed. Every integration
and documentation target also passed.

The required whole Python gate was started in the same clean worktree with a
fresh locked environment and native build:

```bash
uv sync --locked --dev
uv run maturin develop
uv run pytest python/tests/ \
  --junitxml="$HOME/.cache/glaurung/tmp/pytest-9c9c607c.xml"
```

That run was externally terminated with exit status 143 before pytest emitted a
terminal summary or JUnit file. It therefore supplies no whole-Python result.
The focused and scoped evidence above remains valid, but this record does not
claim a green repository-wide Python gate. A later exact-commit run must be
reported independently.
