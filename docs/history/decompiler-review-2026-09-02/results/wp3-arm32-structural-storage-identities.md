# WP3 ARM32 structural frame-storage identities

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `78b31b39` fixes a production ARM32 frame-recognition defect exposed by
the canonical Hello matrix. Stack-pointer arithmetic intentionally retains the
structural spelling `sp` across multiple SSA versions. The frame recognizer
required `ValueIdentities::exact(sp)`, so the correct multi-version candidate
set looked ambiguous and a Thumb `push {r7, lr}` / `pop {r7, pc}` leaked as an
eight-byte source array, `lr`, and an undefined local.

Frame recognition asks which architectural storage a value denotes, not which
transient SSA version it holds. It now consumes the existing
`unambiguous_physical_base` sidecar fact. Several versions of one `sp` remain a
valid stack-pointer identity; candidates spanning different physical bases
still decline.

The first attempted diagnosis, commit `47c5eb0b`, treated the rendered
`// frame: 8 bytes` summary as an AST statement. Exact release measurement
showed no real improvement, so `78b31b39` removes that path and replaces it with
the stable storage-identity repair. No claim relies on the rejected attempt.

This advances WP3 identity consumption and WP9's residual ARM32 frame/storage
axis. It does not complete either package.

## Observed-red and focused verification

The exact release-built `symbols-pie-O0-armv7` Hello cell was observed red with
the following non-source output before the stable-identity repair:

```c
unsigned char local_8[8];
long lr;
long var0;
*(int *)(&local_8[0]) = var0;
*(int *)((&local_8[0] + 4)) = lr;
```

`structural_sp_versions_share_one_machine_frame_storage_identity` reproduces
the owning boundary with three SSA versions of `sp` sharing one physical base.
After the repair:

```text
cargo test --features python-ext --lib ir::arm32_prologue::tests:: --quiet
13 passed; 0 failed; 4,702 filtered out

uv run pytest python/tests/test_decompiler_arm_frame_spills.py -q
1 passed
```

Filtered tests were not executed.

## Exact-release ARMv7 Hello checkpoint

A clean detached worktree at exact commit `78b31b39` was built with
`uv sync --locked --dev` and `uv run maturin develop --release`. The dynamic
ARMv7 slice covered GCC O0-O3, PIE/non-PIE, and symbols/stripped:

```text
uv run pytest \
  python/tests/test_linux_arm_hello_canonical.py::test_dynamic_hello_is_canonical \
  -k armv7 -q --tb=short
4 passed; 12 failed
```

All four O0 cells now produce the canonical `int main(void)` body and pass. All
12 O1-O3 cells recover the exact canonical call, string, and return, but render
`int main(long arg0, long arg1, long arg2, long arg3)`. That cleanly assigns the
next defect to ARM prototype inference rather than frame or string recovery.

The last complete 72-node checkpoint was 54/72. These four newly green cells
project 58/72, with the 12 dynamic signature cells and two stripped-static
ARMv7 cells remaining. This projection is not a replacement for a future full
72-node run.

No broad Rust, Python, fixture, DecBench, or Joern suite was run.

## Next boundary

Trace why the no-argument `main` entry contract loses to four untouched AAPCS
live-ins at O1-O3. Fix the prototype evidence or confidence boundary, not the C
renderer, and retain a genuinely four-argument ARM function as the refusal
control.
