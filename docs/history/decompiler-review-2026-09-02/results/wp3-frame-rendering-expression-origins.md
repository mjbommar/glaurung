# WP3 frame rendering through expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `bd2b8486` makes generic frame-size and stack-pointer rendering
transparent to expression-origin carriers. An attributed `rsp = rsp - 32`
previously lost the `// frame: 32 bytes` summary. In typed output it also
regressed from the deliberately narrow `%rsp = (%rsp - 32)` spelling to noisy
pointer annotations on both sides.

The shared stack-arithmetic classifier and `compute_frame_size` now inspect the
semantic root and operands. Their behavioral boundaries are unchanged:
recognized `sp`/`esp`/`rsp` addition and subtraction contribute to the frame;
malformed self-arithmetic stops the scan; unrelated prologue assignments remain
neutral; and real work still terminates prologue accounting.

This is a bounded WP3 renderer-consumer migration. It does not solve the
separate ARMv7 frame model or complete universal expression attribution.

## Observed-red and focused verification

`attributed_stack_adjustment_preserves_frame_rendering` was observed red first.
The attributed function omitted its frame summary, and its typed rendering
exposed `(u8*)%rsp` annotations that were absent from the identical plain AST.
After the repair, both generic renderer outputs are byte-equal.

```text
cargo test --features python-ext --lib \
  ir::ast::tests::attributed_stack_adjustment_preserves_frame_rendering \
  -- --exact
1 passed; 0 failed; 4,709 filtered out

cargo test --features python-ext --lib frame_size
3 passed; 0 failed; 4,707 filtered out
```

Filtered tests were not executed.

## Release and periodic Hello checkpoint

A clean detached worktree at exact commit `bd2b8486` was release-built. The
build guard reported fresh with native SHA-256
`28ab238d8e349984eaf5ba2f4a99efbb88e35e58c90ae0c5d93ba1407bb236be`.

```text
uv run pytest -q --tb=no \
  python/tests/test_linux_x86_64_hello_canonical.py \
  python/tests/test_linux_arm_hello_canonical.py
54 passed; 18 failed
```

All x86-64 and AArch64 compiler/optimization/layout nodes pass. The same 18
ARMv7 nodes remain red: 16 dynamic GCC-layout nodes across O0-O3,
PIE/non-PIE, and symbols/stripped, plus the two stripped-static O0/O2 nodes.
They remain assigned to the WP6/WP9 ARMv7 ABI, frame, and string-recovery debt.
This current-state checkpoint does not attribute those independent failures to
this WP3 change, and no parent A/B was run.

No full Rust, Python, fixture, architecture, DecBench, or Joern suite was run.

## Next boundary

Continue the bounded renderer audit at call-argument shape classifiers. Keep
ARMv7 Hello remediation in its owning ABI/target-model package rather than
widening this provenance increment.
