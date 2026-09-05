# WP4 raw-switch exclusive entry partition — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

Commit `13588284` lands the first production presentation partition for raw
dispatch loops. It moves a case or default's first basic block into the switch
arm only when that block is inside the canonical raw-loop ownership set and
every CFG predecessor is the typed dispatch or, for a distinct default, its
folded guard. Shared successor blocks stay in the raw block list and are emitted
once.

This is CFG ownership, not lexical or textual inlining. Multiple source case
values selecting one entry use empty fallthrough labels followed by one copy of
the entry body. A target shared between a case and default declines. Missing or
incomplete switch evidence retains the prior labelled representation.

## Real output movement

For ARMv7 A32 O2
`206_aarch64_wide_dispatch::dispatch_in_loop`, all seven remaining handler/join
gotos disappear:

- cases 0, 1, 4, 5, and 6 contain their update, latch test, `continue`, and
  terminal return directly;
- case 2 contains `acc += 4` and breaks to the single shared latch;
- case 3 remains a direct return;
- default contains `acc = 0` and breaks to that same latch;
- the shared `var6 != var7` latch is emitted once after the switch.

The previous output had seven gotos, six `continue` statements, and eight
case/default labels. The new output has zero gotos, the same six `continue`
statements, and the same seven numbered cases plus one default. One harmless
unreferenced `L_51c` presentation label remains; removing it is separate label
hygiene, not evidence for widening the ownership proof.

## Proof and refusal boundary

- A case entry is eligible only when every predecessor is the exact dispatch.
- A distinct default entry is eligible only when every predecessor is the
  dispatch or the evidence's exact guard.
- An entry must be in the raw loop's canonical block set.
- Shared suffixes are not moved, cloned, or inferred. Their existing block
  ownership and transfer lowering remain authoritative.
- Invalid target indices decline during lowering rather than indexing outside
  the LLIR block table.
- Ordinary multi-latch raw loops carry an empty partition.

The reduced AST test uses grouped, non-positional values `10`, `12`, and `42`.
It verifies one body for the grouped target, direct `continue` transfers, no
separate labels for the exclusive entries, the typed default, and the folded
guard.

## Evidence and limits

- Release extension rebuilt with
  `TMPDIR="$HOME/.cache/glaurung/tmp" uv run maturin develop --release`.
- Real A32 v1 architecture test: 1 passed, 99 deselected; native differential
  execution remains green and output is required to contain no `goto`.
- `GLAURUNG_ACCOUNT_STRUCTURE=1` emits zero bytes for the real function.
- `cargo test --features python-ext`: 4,116 library tests passed, zero failed,
  five ignored; every integration and documentation target passed.
- The exact clean structural gate at `a1bcdaf0` reached 18 of 27 tests before a
  stale declared-name assertion (`fib(arg0)` versus the improved `fib(n)`).
  Commit `16947a6f` corrects both recursion signatures and its focused test is
  green. A complete current-tip rerun remains open.
- Full def-use, architecture/host matrices, GED, RSS, output-size comparison,
  and whole Python remain open. This is not WP4 promotion or WP5 completion.

The next partition increment may extend an entry through a multi-block private
prefix only with interior-predecessor closure, explicit stop-at-shared-join
proof, cycle refusal, and independent accounting that every block is emitted
exactly once.
