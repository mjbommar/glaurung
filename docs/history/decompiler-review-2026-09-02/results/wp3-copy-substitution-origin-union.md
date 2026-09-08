# WP3 canonical copy-substitution origin unions

Commit `e3b29fe3` makes the shared copy-substitution boundary preserve one
canonical ownership carrier when an attributed register use is replaced by an
attributed definition. The surviving expression receives the deterministic
union of both contributors instead of retaining the use owner outside a nested
definition owner.

Flattening occurs only after an actual substitution. Unchanged expressions are
not rewritten, so the pass's change report remains exact.

## Focused evidence

The focused regression was observed red before the production change. The
outer expression exposed only the use-site address and contained a second
`Expr::Origin` carrier around the substituted constant.

```text
cargo test --features python-ext --lib \
  ir::copy_prop::tests::substitution_unions_attributed_use_and_definition \
  -- --exact

1 passed; 0 failed; 4,390 filtered out; test body 0.00s
```

The complete touched module then passed:

```text
cargo test --features python-ext --lib ir::copy_prop::

61 passed; 0 failed; 4,330 filtered out; test bodies 0.00s
```

No fixture matrix, full Rust/Python suite, DecBench, or Joern run was used for
this bounded increment.
