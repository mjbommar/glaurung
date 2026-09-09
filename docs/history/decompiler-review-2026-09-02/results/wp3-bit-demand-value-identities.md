# WP3 bit-demand facts keyed by stable identity

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `e0d55e45` moves the persistent value-mask store in
`BitDemandOracle` from semantic `SsaValue` keys to the opaque `ValueId` owned
by its originating `SsaInfo` snapshot. The oracle copies the snapshot lookup
once, then accumulates demand under those stable IDs. Its per-use masks remain
in `OperandGrid<u64>` because instruction address plus source-order operand is
already the correct dense identity for that fact.

This is an authority migration, not a new demand rule, and is intended to be
output-neutral. Local phi propagation still uses `SsaValue` while walking the
SSA graph; no persistent fact is keyed by a rendered or numbered name.

## Focused validation

```text
cargo test --features python-ext --lib ir::definedness::tests --quiet
6 passed; 0 failed

cargo test --features python-ext --lib ir::prototype_width::tests --quiet
6 passed; 0 failed
```

The existing complete-low-byte demand test now additionally proves that the
stored mask is under the exact ID assigned by `SsaInfo` and that semantic
lookup resolves through the snapshot map.

## Exact release and output checks

A detached clean worktree at `e0d55e45` produced a fresh release extension.
The build guard reported `fresh`, import resolved inside that exact worktree,
and the native extension SHA-256 was
`e04380aaf191421763e257026d75cd73036d5d8c016278a2874e7f34e54f18b7`.
Three symbols/PIE GCC-O2 canonical Hello cells passed across x86-64, AArch64,
and ARMv7.

The directly adjacent four-cell `141_atomics::atomic_flag_round_trip` slice
reported one pass and three failures, including two changes classified as
regressions against the committed baseline. An exact parent build at
`f4b7374f` (native SHA-256
`cf6d57214f4cbf2e8e3a028199f5e1b3620506b9594f88ce4d0eb0059abfed44`)
reported the identical pass/fail pattern and the same two baseline
regressions. They are therefore current parent debt, not evidence against this
identity migration, but they remain real failures and are not called green.

No broad Rust suite, whole Python suite, fixture corpus, DecBench, or Joern ran.
Both detached worktrees were removed and `uv sync --locked` restored the main
checkout as the editable Python package.
