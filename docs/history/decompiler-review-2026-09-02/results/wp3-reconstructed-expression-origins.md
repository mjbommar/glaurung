# WP3 reconstructed-expression origin attribution

Commit `3c5c74b9` is the first bounded production attachment of the
expression-origin carrier introduced by `9b10f06e`. When expression
reconstruction removes a single-use temporary definition and substitutes its
right-hand side into the adjacent consumer, the inserted expression subtree
now retains the definition instruction's canonical origins. The surviving
statement continues to own the union of definition and consumer origins.

This is not universal expression attribution and does not complete WP3. It
covers the adjacent reconstruction transaction only. Other expression
producers, remaining identity consumers, and conservative SSA invalidation
migrations remain open.

## Design boundary

An initial experiment attached statement origins to every expression root at
the AST-lowering boundary. It was rejected before commit: dozens of later
passes still use structural expression matching, so universal wrapping would
have forced a big-bang consumer migration and obscured which transformation
owned each origin.

The landed rule attaches origins at the transformation that removes the
definition. This makes ownership compositional: a removed fact transfers its
origin to the exact replacement subtree, and the containing statement retains
the complete contributing set.

The new carrier exposed four consumers that had to become transparent without
discarding attribution:

- pure-copy classification in `src/ir/copy_prop/env.rs`;
- copy propagation in `src/ir/copy_prop.rs`;
- algebraic, Boolean, and typed-comparison folding in
  `src/ir/const_fold.rs`;
- control-condition rendering in `src/ir/ast/dec_render/stmt.rs`.

Attributed `Select` expressions remain protected from the unsafe
single-use-inline path by matching their semantic expression rather than their
outer carrier.

## Observed-red evidence

The exact reconstruction test was first observed red: the surviving statement
had the expected union, but the substituted expression subtree had no origin.
After the bounded attachment it passes.

The first release-built real-binary A/B exposed a readability regression:
copy propagation and folding no longer saw through the new carrier, producing
temporary names and machine-flag arithmetic. The affected consumers were
migrated one at a time. The final output for
`01_conditional_polarity:gcc:O0:classify` is byte-for-byte equal to the clean
parent output, while the substituted subtree now retains its machine origin.
The cell remains execution-correct.

## Narrow validation

Only tests coupled to the changed modules and one exact fixture family were
run during this increment. Seven exact tests pass: reconstruction ownership,
the existing single-use control, attributed copy propagation, XOR folding,
zero-test inversion, typed comparison, and control-condition rendering.

The touched-module slices also pass:

```text
ir::expr_reconstruct::tests::  12 passed
ir::copy_prop::tests::         26 passed
ir::const_fold::tests::        57 passed
ir::ast::origin::tests::        7 passed
```

After the required release extension rebuild, the exact real-fixture family
passed all four compiler/optimization lanes and all 48 functions:

```text
uv run python tools/dectest.py 01_conditional_polarity --full
4 lanes, 48 functions, all passed
```

No full Rust, Python, architecture, fixture, or DecBench sweep was run at this
bounded iteration boundary. Cargo's filtered-out counts are not reported as
executed tests.

## Next boundary

Continue production expression attribution one producer at a time. For each
producer, add an observed-red ownership test, migrate only the consumers it
exposes, and run the touched modules plus the smallest representative real
binary. Broad gates belong at the next coherent WP3 integration boundary, not
after every carrier migration.
