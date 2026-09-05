# WP4 raw-switch private linear prefixes — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

Commit `ca30c62f` extends the one-block raw-switch entry partition from
`13588284` through bounded private straight-line prefixes. This is the planned
next ownership increment: a handler may move more than one block into its case
only while every interior block has exactly one predecessor—the preceding
prefix block—and the preceding block has exactly that one successor.

Prefixes stop before another case/default entry, the dispatch, the folded
guard, a shared join, any branch, any cycle, a block outside canonical raw-loop
ownership, or the eight-block budget. Distinct prefixes are disjoint. A stopped
suffix remains labelled and emitted once, and the last inlined block retains an
explicit transfer to it.

## Independent verification

The region verifier now checks the presentation partition independently of its
producer. It rejects:

- missing or incomplete typed switch evidence;
- empty or over-budget prefixes;
- entries not owned exclusively by their typed case/default;
- a target shared by a case and default;
- blocks outside the raw ownership set;
- overlapping prefixes;
- an interior edge that is not one-to-one; and
- a prefix that crosses a shared join.

A forged case prefix `[case_entry, shared_join]`, where the default also enters
that join, produces `RawLoopPrefixInvalid`. The producer test independently
recovers a real two-block private path and proves it stops before the multiply
entered loop header.

## Evidence

- Both focused producer/lowerer tests pass, including grouped non-positional
  labels and a two-block private prefix.
- The forged shared-join verifier test passes.
- `cargo test --features python-ext`: 4,118 library tests passed, zero failed,
  five ignored; every integration and documentation target passed.
- Release extension rebuilt with
  `TMPDIR="$HOME/.cache/glaurung/tmp" uv run maturin develop --release`.
- Real ARMv7 A32 fixture-206 native round trip remains green; structure
  accounting remains silent.
- The real output is byte-identical to `13588284` because that function's
  useful handler prefixes were already one block: zero gotos, six continues,
  cases `0..6`, one default, and one shared latch.

The exact clean structural gate at `8c65a78a`, the immediately preceding
one-block partition increment, completed 26 of 27 tests green in 568.91 seconds.
Its final aggregate ratchet failure consists of pre-existing findings: exact
parent/tip output is byte-identical for both reported switch rows and for all
three reported memory-store rows in both `plain` and `c` styles. That gate does
not cover this commit's new multi-block-prefix behavior. Current-tip full
structural/def-use, cross-architecture and host matrices, GED, RSS, output-size,
and whole Python evidence therefore remain open. This increment advances the
general partition contract but does not complete WP4 promotion or WP5.
