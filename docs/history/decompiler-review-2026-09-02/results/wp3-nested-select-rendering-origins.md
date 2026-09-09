# WP3 nested-select rendering through expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `c61c32e0` closes a visible scored-text regression in both generic AST
renderers. A `Select` nested under recovered control flow is intentionally
rendered as a two-armed `if`/`else`: evaluating either arm early can be unsafe,
and preserving both arms is structurally faithful. An expression-origin carrier
previously hid the `Select`, causing the same AST to render instead as an eager
initializer plus a one-armed `if`.

Both `src/ir/ast/ctx_render.rs` and `src/ir/ast/c_render.rs` now inspect the
semantic expression for this classification. They retain the original
expression and its owner; only recognition is carrier-transparent. Top-level
safe one-armed rendering and its eager-evaluation proof are unchanged.

This is a bounded WP3 renderer-consumer migration. It does not complete
universal expression attribution or the remaining semantic-consumer audit.

## Observed-red and focused verification

`attributed_select_nested_under_control_flow_is_render_byte_neutral` was
observed red first. The plain AST rendered a nested two-arm `if`/`else`, while
the attributed AST rendered `result = no; if (inner) result = yes;` in both
generic renderers. After the two semantic lookups, the outputs are byte-equal.

```text
cargo test --features python-ext --lib \
  ir::ast::tests::attributed_select_nested_under_control_flow_is_render_byte_neutral \
  -- --exact
1 passed; 0 failed; 4,708 filtered out

cargo test --features python-ext --lib ir::ast::tests::a_select
5 passed; 0 failed; 4,704 filtered out
```

Filtered tests were not executed.

## Release fixture checkpoint

A clean detached worktree at exact commit `c61c32e0` was release-built. The
build guard reported fresh with native SHA-256
`1dbcd1822c5bf5a6c04dd4272b8ff2b86ccd2dabfbadb4003e59f4424df7fe97`.

```text
uv run python tools/dectest.py \
  '189_effectful_select:*:*:se189_select_pure' \
  '189_effectful_select:*:*:se189_select_one_arm'
SCOPED: 4 lanes of 838 (0%) - no regressions in scope
```

Those four GCC/Clang O0/O2 lanes contain eight selected function verdicts.
This is a focused select-rendering canary, not a broad architecture claim. No
full Rust, Python, fixture, architecture, DecBench, or Joern suite was run.

## Next boundary

Continue the renderer-side audit with stack-frame and call-argument shape
classifiers that still destructure nested expressions directly. Each migration
needs an observed-red byte-neutrality contract before production attachment can
be widened.
