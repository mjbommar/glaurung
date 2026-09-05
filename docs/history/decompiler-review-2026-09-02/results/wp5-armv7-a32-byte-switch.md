# WP5 ARMv7 A32 compact-byte switch evidence — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

Behavioral commit `76cce5d1` recovers GCC's optimized A32 compact switch
encoding without treating arbitrary PC arithmetic as control flow. The real
fixture-206 instruction sequence is:

```asm
ldr   r3, [pc, #literal]
add   r3, pc, r3
cmp   r0, #bound
bhi   default
ldrb  r0, [r3, r0]
add   pc, pc, r0, lsl #2
```

The first literal is a signed PC-relative table offset. Each table byte is an
unsigned displacement, scaled by four from the architectural PC value at the
terminal `add`. Table address, terminal target base, selector, bound, and ARM
execution mode remain separate typed facts.

## Implementation boundary

- `src/disasm/capstone.rs` retains the LSL scale on ordinary ARM register
  operands, including `add pc, pc, r0, lsl #2`.
- `src/analysis/dispatch/arm_tables.rs` recognises only the exact A32 literal,
  PC-relative materialisation, byte load, and scaled terminal sequence.
- `src/analysis/cfg/dispatch_flow.rs` reads the literal through the bounded
  image view and invalidates the destination when it cannot be read.
- `src/analysis/jump_table.rs` decodes unsigned byte entries with checked
  arithmetic and refuses non-executable, overlapping, or overflowing targets.
- `src/analysis/cfg/dispatch_resolution.rs` adds the resulting ordered typed
  case edges to the CFG.
- `src/ir/lift_arm32.rs` represents the exact terminal as an indirect jump;
  `src/ir/lift_function.rs` snapshots a byte-table selector before `ldrb`
  overwrites its physical register.

This does not claim general ARM table recovery. Thumb `tbb`/`tbh`, A32 word
tables, compiler variants, and unguarded value-set analysis remain independent
contracts.

## Execution evidence

At hardened exact commit `5ef0bcb9`, after a clean-worktree
`uv run maturin develop --release`:

- `dense_dispatch` passes all 22 native ARMv7 execution cases in production
  v1 output.
- `dispatch_in_loop` first passed native ARMv7 execution through the
  independently selected `shadow_v2=True` output. The subsequent WP4 repair at
  `6f0ba701` makes production v1 pass as well: the local raw loop owns all six
  case-to-header backedges and retains the recovered switch. One explicit
  guard transfer remains as an `EdgeViaGoto` readability finding; there are no
  hard unowned-edge findings. See
  `wp4-a32-multi-latch-dispatch-loop.md` for the independently measured repair.

Focused command:

```text
TMPDIR=$HOME/.cache/glaurung/tmp uv run pytest -q \
  python/tests/test_decompiler_arch_roundtrip.py -k a32_o2 -rxX
```

At `5ef0bcb9`, the result was two passed and one strict expected failure. At
`56503e53`, after the WP4 repair and census refresh, all seven focused A32
architecture tests pass and the expected-failure marker has been removed.

## Safety and gate evidence

- Dispatch tracker suite: 45 passed.
- Jump-table decoder suite: 24 passed.
- Exact terminal recognition, Capstone scale, A32 lift, and overwritten-selector
  snapshot tests pass.
- `cargo test --features python-ext`: green, beginning with 4,110 passed library
  tests and ending with green integration and documentation tests.
- The first clean-tip matrix exposed a native stack overflow in production v1
  on `43_base64::base64_decode`: four valid 48-entry A32 byte switches made
  speculative shape recovery revisit the same graph recursively. Commit
  `5ef0bcb9` adds a graph-sized depth and work budget shared by every recursive
  shape recogniser. Exhaustion selects the complete labelled CFG; it never
  returns a partial speculative tree. The real function now completes in 0.17
  seconds at 67,332 KiB maximum RSS instead of exiting with SIGSEGV.
- Complete ARMv7 A32 O0/O2 parent/tip comparison: 410 compiler/optimization
  lanes and 1,604 function verdicts at both exact revisions. Nine functions
  improve from `fail` to `pass`, and no function becomes worse or disappears:
  three fixture-04 switch shapes, fixture-08 `dispatch_switch`, fixture-126
  `apply_opcode`, fixture-186 `fallthrough_no_default`, both measured
  fixture-204 functions, and fixture-206 `dense_dispatch`.
- Both revisions predate newer committed baselines, so their raw gate summaries
  contain the same 739 stale-baseline regressions. Attribution uses the exact
  parent `ab726bc3` versus hardened tip `5ef0bcb9` status maps rather than
  presenting those differently scoped baseline comparisons as this slice's
  regressions.

The full Python repository gate is not claimed here. The preceding stacked
i386 exact-checkout run remains broadly red at 4,597 passed, 125 failed, 891
expected failures, 78 skipped, and 125 deselected; comparison against its
AArch64 parent finds no tip-only failing node IDs.

## Next boundary

The production-v1 loop ownership defect exposed by this slice is closed at
`6f0ba701`. Commits `28b3bc5b` and `0e29ffc4` then remove the undefined-looking
precondition arm and the explicit outer-guard transfer under separate
fail-closed contracts; see `wp4-a32-guard-quality.md`.
