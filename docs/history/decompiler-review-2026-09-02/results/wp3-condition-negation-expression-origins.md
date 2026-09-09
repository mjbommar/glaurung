# WP3 condition-negation expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `1b915c0d` makes the shared condition-negation helper and call-driven
loop rotation transparent to expression-origin carriers.

An attributed comparison is now negated semantically, so `item == 0` becomes
`item != 0` rather than the noisier `(item == 0) == 0`, and its exact owner
stays on the replacement comparison. The effectful-loop recognizer also sees
an attributed constant-true header. Its existing safety boundaries—one
result-producing call, an adjacent break guard, and no bypassing label/goto—are
unchanged.

This is a bounded WP3 expression-consumer migration. It improves a shared
structuring primitive but does not complete universal production attribution,
the remaining wildcard audit, or WP3.

## Focused verification

Both omissions were observed red before their respective production changes:

- `negating_an_attributed_comparison_preserves_its_owner` lost the owner and
  produced a wrapped equality instead of the inverted comparison.
- `attributed_effectful_header_preserves_composed_origins` left the attributed
  loop unrotated.

After repair:

```text
ir::ast::lower_conds::tests::negating_an_attributed_comparison_preserves_its_owner
1 passed; 0 failed; 4,703 filtered out

ir::effectful_loop::tests::attributed_effectful_header_preserves_composed_origins
1 passed; 0 failed; 4,703 filtered out

ir::ast::lower_conds::tests::
10 passed; 0 failed; 4,694 filtered out

ir::effectful_loop::tests::
3 passed; 0 failed; 4,701 filtered out
```

Filtered tests were not executed.

## Release integration and Hello checkpoint

A clean detached worktree at exact commit `1b915c0d` was release-built. The
build guard reported fresh with native SHA-256
`6eef97357ed3e8a03eb22e5ab6303c4b55e26dd5cd736c5a937df56287191284`.

The directly owning integration test passed:

```text
uv run pytest -q python/tests/test_effectful_loop_rotation.py
1 passed
```

The periodic canonical Hello checkpoint covered 72 x86-64, AArch64, and ARMv7
compiler/optimization/layout nodes:

```text
uv run pytest -q --tb=no \
  python/tests/test_linux_x86_64_hello_canonical.py \
  python/tests/test_linux_arm_hello_canonical.py
54 passed; 18 failed
```

All x86-64 and AArch64 nodes passed. All 18 failures are ARMv7: 16 dynamic
GCC-layout nodes across O0-O3, PIE/non-PIE, and symbols/stripped, plus the two
stripped-static O0/O2 nodes. Their output retains the already tracked ARMv7
frame/argument/string recovery debts. This checkpoint is current-state
evidence, not a claim that `1b915c0d` introduced or repaired those independent
failures; no parent A/B was run.

No full Rust, Python, fixture, architecture, DecBench, or Joern suite was run.

## Next boundary

Continue the non-exhaustive WP3 expression-consumer audit. Keep the 18 ARMv7
Hello failures visible for their owning WP6/WP9 frame and ABI work rather than
expanding this provenance increment beyond its semantic boundary.
