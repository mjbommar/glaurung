# WP3: Thumb leaf frame recovery

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `f1bc085d` closes the real ARM Thumb leaf-frame regression that had been
the first ordinary Python-suite failure at 11%. GCC Cortex-M O0 functions may
save only `r7`, keep `lr` live, and return through it; ARM32 frame recovery no
longer incorrectly requires every valid frame to save `lr`.

The epilogue recognizer also follows a bounded chain of exact, straight-line
SSA definitions when GCC leaves `sp = &frame + width` expanded through
temporaries used by flag calculations. Each recursive step must have one exact
identity and move strictly backward. The `stack_top` restore alias is accepted
only when that resolved address is exactly the first saved `r7` slot and the
remaining stack adjustment balances.

The compiled fixture's output changed from an undefined machine-save artifact:

```c
unsigned char local_18[24];
long var0;
*(int *)((&local_18[0] + 20)) = var0;
```

to a clean source-level entry:

```c
int thumb_leaf_frame(int wait) {
    signed char value = 0;
```

The full output contains no fake frame array, `var0`, machine save, or unmatched
frame operation.

## Red/green evidence

The existing real-binary regression was observed red before the repair and
green afterward:

```text
uv run pytest \
  python/tests/test_cli_decompile.py::test_real_thumb_leaf_frame_save_does_not_become_a_source_local -q
1 passed

cargo test --features python-ext ir::arm32_prologue::tests:: --lib -q
14 passed; 0 failed; 4829 filtered out

cargo test --features python-ext ir::stack_locals::arm32_tests:: --lib -q
6 passed; 0 failed; 4837 filtered out

uv run maturin develop
exit 0

uv run python tools/build_guard.py
fresh
```

The required post-source-commit Python gate was run once, fail-fast. It passed
the former Thumb blocker and exposed the next ordinary failure, still at 11%:

```text
uv run pytest python/tests/ -q -x
test_real_arm_hard_float_compare_does_not_erase_three_call_args: failed
```

That independent ARM hard-float output contains an undefined `var5` in the
third call argument. No fixture matrix, DecBench, Joern, or corpus sweep was
run.

## Remaining boundary

This closes one real ARM32 frame-recovery/output defect, not WP3 or WP9. The
newly exposed hard-float argument-identity failure is the next narrow regression
to diagnose; the wider WP3 invalidation, origin, and consumer audit remains
open.
