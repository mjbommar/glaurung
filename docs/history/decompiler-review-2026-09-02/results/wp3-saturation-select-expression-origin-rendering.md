# WP3 saturation-select expression-origin rendering

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `d6e13a8e` makes the two exact saturation-select render recognizers
transparent to expression-origin carriers. An attributed one-call-times-two
arm still receives the existing lazy-call spelling, and an attributed unsigned
cast of `-1` still receives the width-specific all-ones literal. The change
does not make either rule more permissive: the first still requires exactly one
call multiplied by exactly two, and the second still requires an unsigned cast
of the exact constant `-1`.

Ordinary unsigned casts remain outside this canonicalization. The existing
pointer-width contract continues to distinguish 32-bit from 64-bit call
results.

## Focused TDD

The strengthened saturation contract wrapped both select arms in independent
`OriginSet` carriers after structuring. Before the production repair, the exact
test failed and rendered the raw forms:

```text
(saturating_add(capacity, 1) * 2)
(unsigned long)(-1)
```

After the repair:

```text
cargo test --features python-ext --lib \
  ir::lazy_call_select::tests::unsigned_max_spelling_is_scoped_to_the_saturation_select \
  -- --exact
1 passed; 0 failed; 4,672 filtered out; 0.24 s test execution

cargo test --features python-ext --lib ir::lazy_call_select::tests -- --nocapture
18 passed; 0 failed; 4,655 filtered out; 0.22 s test execution
```

The module slice includes the ordinary-cast refusal, active pointer-width
selection, effect-counting refusals, unique-use requirements, and the five
existing origin-preservation contracts.

## Release real-binary evidence

The required release extension rebuilt successfully. The established
effectful-select fixture then remained green:

```text
uv run python tools/dectest.py 189_effectful_select --full --jobs 4
20 functions passed across 4 GCC/Clang O0/O2 lanes; no regression in scope
```

The release build included unrelated concurrent Rust edits in the shared
worktree. This result therefore establishes behavior on that shared snapshot;
it is not a clean-tip performance measurement and no broad baseline was
refreshed.

## Scope

This is one bounded WP3 expression-origin consumer. It does not complete
universal expression attribution, migrate another semantic pass, or broaden
the saturation pattern beyond its existing proof obligations.
