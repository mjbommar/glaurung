# WP3 signed-return expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `1e424109` restores destination-typed signed-return cleanup when the
return expression carries WP3 instruction origins. `expr_ctype`, the signed
ABI-transport recognizer, and the typed return-fold pass now inspect semantic
expressions through `Expr::Origin` without discarding provenance.

When the pass removes a redundant outer machine-width cast and inner unsigned
transport cast, both removed owners are unioned onto the surviving signed
expression. The enclosing return statement retains its separate statement
owner. Existing width, signedness, and non-transport refusal boundaries are
unchanged.

This closes one bounded WP3 expression-consumer regression and the concrete
signed-return output debt recorded after `edd529a6`. It does not complete
universal expression attribution, the general WP6 type solver, or WP3.

## Focused verification

The attributed signed-return contract was observed red first: the origin
carrier hid the cast tree from both type inspection and ABI-transport cleanup.
After the repair:

```text
cargo test --features python-ext --lib \
  ir::ast::return_ctype::tests::attributed_signed_return_transport_folds_and_unions_cast_origins \
  -- --exact
1 passed; 0 failed; 4,702 filtered out

cargo test --features python-ext --lib \
  'ir::ast::return_ctype::tests::' --quiet
6 passed; 0 failed; 4,697 filtered out
```

The existing focused signed-fold and unsigned-preservation contracts were also
run individually and passed. Filtered tests were not executed.

## Release fixture checkpoint

A clean detached worktree at exact commit `1e424109` was release-built. The
build guard reported fresh with native SHA-256
`cf727c9b37851ef97e7565fdad931689b457286521cf5164ac93d1e1143cc637`.

```text
uv run pytest -q python/tests/test_classify_signed_loop.py
2 passed
```

Those two parameters cover GCC and Clang O0, debug and stripped binaries, C
syntax, and execution differentials. Both now render a signed `int classify`,
retain the clean `while (100 < n)`, emit direct `return -1`, and avoid the
redundant unsigned return cast. The genuinely unsigned sibling remains
unsigned and passes its execution differential.

At the preceding `edd529a6` checkpoint the same command failed both parameters:
GCC selected an unsigned return and Clang retained unsigned casts. This is
therefore a direct 0/2 to 2/2 closure for the owning fixture, rather than a
suite-wide quality claim.

No full Rust, Python, fixture, architecture, DecBench, or Joern suite was run.

## Next boundary

Continue the bounded WP3 expression-consumer audit. Keep general signedness
inference and conflicting-evidence behavior under WP6; do not generalize this
destination-proved ABI-transport cleanup into a renderer guess.
