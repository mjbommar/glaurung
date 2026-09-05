# WP4 raw-switch private branching regions — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

Commit `1ce1a80b` extends raw-switch arm ownership from the private linear
prefixes recorded in `wp4-raw-switch-private-prefixes.md` to bounded,
predecessor-closed private DAGs. A case or default may now own a conditional
branch and its private reconvergence instead of transferring to out-of-line
labels in the surrounding raw loop.

This is presentation ownership only. The canonical raw-loop block set remains
unchanged, and the producer stops before the dispatch, folded guard, another
typed arm entry, a block outside the raw loop, a previously claimed block, a
cycle, or any block with a predecessor outside the candidate arm. Regions are
disjoint, deterministically ordered, and capped at 16 blocks. Shared joins and
cross-arm suffixes therefore remain in outer raw-loop ownership and are emitted
once.

## Independent verification

The verifier does not trust the producer's partition. For each declared inline
region it checks complete typed switch evidence, the correct exclusive arm
entry, entry-first topological order, non-empty and at-most-16-block size,
unique and disjoint raw-owned blocks, and complete predecessor closure for
every block after the entry.

A forged region that crosses a case/default shared join is rejected as
`RawLoopInlineRegionInvalid`. A separate positive verifier test accepts a
private diamond. Producer and lowerer tests prove that the same diamond is
collected, rendered inside its case with its local branch intact, and stopped
before the shared loop latch.

## Real ARMv7 A32 evidence

`python/tests/fixtures/raw_switch_private_diamond.c` forces GCC to retain an
actual conditional branch inside case 0 of a byte-table-dispatched loop. The
parent and tip were run against the same ARMv7 A32 O2 shared object.

- Parent `33aed1ae` emits two transfers from case 0 to out-of-line labels
  `L_428` and `L_448`.
- Tip `1ce1a80b` emits `if (acc <= 6)` directly inside case 0, keeps both
  arithmetic bodies there, and emits no `goto`.
- Output contracts from 85 to 81 lines without deleting either behavior.
- The new native ARM differential passes, and the existing fixture-206 A32
  production round trip remains green.
- Structure accounting is silent; neither output contains a verifier
  diagnostic.

The generated test census changes only for the three new IR tests: declared
tests move from 4,633 to 4,636, the IR count moves from 2,113 to 2,116, and the
never-executed pool remains zero. The six-test census gate passes after the
generated baseline refresh in `b2ef5cb2`.

An exact clean checkout at `1ce1a80b` rebuilt the release extension and passed
the complete `cargo test --features python-ext` gate: the library target reports
4,119 passed, zero failed, and five ignored; every integration and documentation
target also passed. The two targeted A32 Python tests then passed together.

The complete exact-tip structural gate passes 25 of 27 tests in 654.91 seconds.
Its eight regression findings and six improvement findings are identical to
the preceding exact result recorded for the private-prefix increment; the new
region does not add a structural-ratchet row. The complete def-use census passes
four of six tests in 53.76 seconds. After normalising pytest indentation and
deduplicating repeated display lines, all 169 regression/improvement findings
are byte-identical to the preceding exact `5fc93b15` report. Neither baseline
is rewritten here: both remain stale in both directions and require their own
review.

The whole-Python, cross-architecture, GED, RSS, and output-size gates remain
separate evidence obligations. This increment proves one bounded acyclic arm
shape; it does not admit cyclic, cross-arm, or shared-join ownership and does
not complete WP4 promotion.
