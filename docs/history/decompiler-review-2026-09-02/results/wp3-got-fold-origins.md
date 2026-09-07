# WP3 GOT-fold origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `18ef9fdc` makes relocation-proven GOT pointer folding transparent to
statement origins. The pass had begun matching the raw statement enum after
origin carriers entered the production AST, so every attributed statement was
silently outside its transformation surface. It now reaches the semantic
statement while retaining the original owner.

The same migration closes previously omitted expression locations in indirect
transfers, pushes, throws, nested `try`/`catch` bodies, and expression-form
calls. This is a bounded WP3 consumer migration; it does not add expression
origins or complete the remaining wildcard-consumer audit.

## Evidence

Two new tests were observed red before the production change and green after
it. The complete focused module is green:

```text
cargo test --features python-ext got_fold::tests -- --nocapture
6 passed; 0 failed
```

Release build and complete stripped/debug differential:

```text
uv run maturin develop --release
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 17 improvements; 0 infrastructure problems
```

The complete JSON map is byte-for-byte identical to the preceding select-fold
boundary. The complete Rust gate is green:

```text
cargo test --features python-ext
library: 4,272 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The mandatory whole Python suite completed red, but its normalized 218-node
failure set is exactly identical to the preceding boundary:

```text
218 failed; 4,587 passed; 77 skipped; 128 deselected; 876 xfailed
0 added failure nodes; 0 removed failure nodes
```

## Next ordered increment

Continue the actual production pass-order audit. The next omission is
function-table proof tracking: expression rewriting already sees through
origin wrappers, but attributed definitions are not entered into its proof map
and exception bodies are skipped.
