# Phase 0 — IR Hardening (Foundation)

**Goal:** turn the lossy LLIR into a total, precisely-typed, executable IR
**without breaking** existing consumers (decompiler, SSA, dataflow,
`ioctl_taint`). Spec: [`../02-architecture/executable-llir.md`](../02-architecture/executable-llir.md).

**Feature gate:** none — changes live in `src/ir`. **Risk:** breaking existing
consumers (mitigated by the verifier + the existing test suite).

## Tasks

- **0.1 Width type & typed values.** Add `Width(u16)`; change `Value::Const(i64)`
  → `Const { value: u128, width }` (raw bits; sign is an op property). Add width
  to `Reg`. *Test:* unit tests on `Value` round-trip + `Display`.
- **0.2 Width on ops.** Add `width` to `Bin`/`Un`/`Cmp`/`Assign`; define all
  arithmetic as modular at `width`. *Test:* construction + display snapshots.
- **0.3 Explicit width-change ops.** Add `ZExt`/`SExt`/`Trunc`/`Extract`/`Concat`/
  `Ite` to `Op`. *Test:* per-op unit tests.
- **0.4 `MemOp.endian`.** Add `Endian` enum + field; default little-endian.
- **0.5 `Op::Intrinsic`.** Add the footprint-declaring intrinsic
  (`name,ins,outs,reads_mem,writes_mem`). Keep `Unknown` as a deprecated alias
  that lowers to a maximally-conservative `Intrinsic`.
- **0.6 IR verifier (`src/ir/verify.rs`).** Assert operand-width agreement, every
  read defined-or-input, no residual `Unknown` post-lift. *Test:* runs over every
  `samples/`/`tests/fixtures/` binary; fails loudly on malformed IR.
- **0.7 Thread widths through `lift_x86`.** Use `iced-x86` operand sizes to fill
  widths; emit explicit `ZExt 32→64` on 32-bit register writes; emit `Intrinsic`
  (not `Unknown`) for unmodeled instructions; flags via explicit predicate ops.
  *Test:* differential IR snapshots on fixture functions; verifier passes.
- **0.8 Flag producer/consumer DCE.** Extend `src/ir/dce.rs` so a flag's
  predicate op is materialized only when consumed. *Test:* DCE unit tests +
  existing decompiler tests still pass.
- **0.9 Migrate consumers.** Update SSA/use-def/dataflow/decompiler/`ioctl_taint`
  construction & match sites for the new shapes. *Test:* the **entire existing
  suite** (`cargo test` + `uvx pytest`) green.

## Deliverables

- Hardened `src/ir/types.rs`, updated `src/ir/lift_x86.rs`, new `src/ir/verify.rs`,
  extended `src/ir/dce.rs`.
- `arm64` lifter widths deferred to Phase 2 (x86-64 is the Phase 1 target), but
  `Unknown`→`Intrinsic` applies to it now to keep the verifier honest.

## Tests

- New: width round-trip, each new op, verifier-over-corpus, intrinsic lowering.
- Regression: **all** existing `src/ir` + decompiler + `ioctl_taint` tests pass
  (the safety net for the migration).

## Exit criteria

- Every lifted op carries an explicit width; `endian` on memory; no `Op::Unknown`
  emitted by the x86 lifter (only `Intrinsic`).
- `ir::verify` passes on the whole sample corpus.
- `cargo test` and `uvx pytest python/tests/` fully green; `ruff`/`ty` clean on any
  touched Python.

## Notes

This phase recovers information the decoder *already has* (operand sizes) but the
IR currently discards — it is largely mechanical once the types change. The
verifier is the highest-value deliverable: it makes every later phase's
correctness assumptions checkable on real binaries.
