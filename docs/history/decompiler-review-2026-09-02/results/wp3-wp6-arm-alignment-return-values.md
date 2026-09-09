# WP3/WP6 ARM alignment padding through explicit returns

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `1ce64267` closes the remaining canonical ARMv7 Hello signature defect.
GCC uses `push {r3, lr}` / `pop {r3, pc}` as balanced eight-byte call-frame
alignment in these functions. The existing input-evidence classifier already
excluded that saved `r3` when no later instruction observed the restored value,
but only if the final LLIR operation was operand-free `Return`.

Prototype recovery correctly upgrades a proven scalar result to
`ReturnValue(r0)`. That representation-only improvement made the alignment
proof decline, so the initial save of caller-saved `r3` became false `arg3`
evidence and expanded the contiguous signature to `arg0` through `arg3`.

The classifier now treats both `Return` and `ReturnValue` as unconditional
terminal returns. It still scans the explicit returned operand: returning or
otherwise observing restored `r3` disqualifies the padding proof. Calls,
branches, indirect transfers, conditional exits, mismatched stack slots, and
unbalanced save groups retain their existing refusals.

This is a bounded WP3 representation/identity repair at WP6's prototype-input
boundary. It closes the measured Hello capability but does not complete either
package.

## Observed-red and focused verification

`arm_r3_alignment_padding_survives_explicit_return_materialization` was observed
red first: the balanced save produced false slot 3 after the terminal operation
became `ReturnValue(r0)`. After the repair, the new contract and the existing
restored-use and conditional-exit controls pass:

```text
cargo test --features python-ext --lib arm_r3_ --quiet
3 passed; 0 failed

cargo test --features python-ext --lib \
  ir::value_number::tests::real_arm_alignment_save_does_not_invent_four_parameters \
  -- --exact --quiet
1 passed; 0 failed; 4,715 filtered out
```

Filtered tests were not executed.

## Exact-release ARMv7 and periodic Hello checkpoints

A clean detached worktree at exact commit `1ce64267` was built with
`uv sync --locked --dev` and `uv run maturin develop --release`.

First, the 16-node dynamic ARMv7 slice covered GCC O0-O3, PIE/non-PIE, and
symbols/stripped:

```text
uv run pytest \
  python/tests/test_linux_arm_hello_canonical.py::test_dynamic_hello_is_canonical \
  -k armv7 -q --tb=short
16 passed
```

Then the complete requested periodic canonical Hello checkpoint ran:

```text
uv run pytest -q --tb=short \
  python/tests/test_linux_x86_64_hello_canonical.py \
  python/tests/test_linux_arm_hello_canonical.py
72 passed
```

This moves the last confirmed full checkpoint from 54/72 to 72/72. It covers
x86-64 and AArch64 compiler/optimization/layout nodes, all 16 dynamic ARMv7
nodes, and the stripped-static ARM nodes. It is not evidence for unrelated
fixtures or the broad Python suite.

No broad Rust, Python, fixture, DecBench, or Joern suite was run.

## Next boundary

Return to WP3's remaining production semantic-reader audit and universal origin
attribution. Keep the canonical Hello files as a periodic 72-node canary, not as
the iteration loop for unrelated changes.
