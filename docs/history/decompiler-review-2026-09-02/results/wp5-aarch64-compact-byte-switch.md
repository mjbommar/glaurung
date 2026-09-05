# WP5 AArch64 compact byte-switch evidence — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

## Outcome

Behavioral commit `310b949e` recovers GCC's compact AArch64 O2 switch form for
the real `206_aarch64_wide_dispatch::dense_dispatch` fixture. The dispatch is:

```text
cmp w0, #0xf; b.ls dispatch
adrp/add table; ldrb offset, [table, w0, uxtw]
adr target_base; add target, target_base, offset, sxtb #2; br target
```

Before this increment, the indirect `br` was unrecovered and the function
collapsed to its `return -1` path. It now renders a closed `switch` with cases
`0..15` and the out-of-range default. The emitted function recompiles and
matches the original for all 22 deterministic execution cases. The committed
architecture baseline changes only this cell from `fail` to `pass`.

The output is structurally correct but still exposes unnecessary integer casts
inside several case expressions. Those casts belong to WP6/WP7 readability and
type work; this WP5 increment does not hide that remaining defect.

## Production boundary

- `src/analysis/dispatch/registers.rs` gives the tracker an AArch64 W/X
  register identity (`w0` and `x0` are views of one value).
- `src/analysis/cfg/ctrl_flow.rs` and `src/analysis/cfg/walk.rs` carry the
  inclusive `b.ls` taken-edge bound to the dispatch path.
- `src/analysis/dispatch.rs` recognizes the exact `LDRB` plus encoded
  `ADD Xd, Xn, Wm, SXTB #2` sequence. Unsupported scales and unmodelled writes
  invalidate the candidate rather than retaining stale evidence.
- `src/analysis/jump_table.rs` decodes exactly the guard-proved number of signed
  byte offsets, uses checked signed address arithmetic, requires executable
  targets, and rejects a target inside the table itself.
- `src/analysis/cfg/dispatch_resolution.rs` converts the decoded targets to the
  ordinary typed switch edges; `src/ir/lift_function.rs` preserves the original
  selector identity for the ordered case labels.

This is deliberately one exact compiler encoding, not a general AArch64 value
set engine. Missing bounds, malformed extents, wrong scale, arithmetic overflow,
non-executable targets, and table overlap all decline safely.

Hardening commit `5dbc3fc4` closes one additional stale-evidence path found in
pre-merge review: an intervening AArch64 direct or indirect call now clears the
tracker because an arbitrary callee may overwrite the volatile registers and
flags that proved the candidate. A real-encoding unit sequence requires the
post-call `br` to remain unresolved. The target fixture, ten-lane switch slice,
412-lane architecture result, and full Rust gate are unchanged after hardening.

## Validation

All commands used `TMPDIR=$HOME/.cache/glaurung/tmp` in the isolated worktree
based on `7c0ba967`.

- `cargo test --features python-ext` at hardened tip `5dbc3fc4`: 4,100 library
  tests passed, zero failed,
  and five were ignored; every integration and documentation target passed.
- `uv run maturin develop --release`: fresh release extension built from the
  committed source.
- `uv run pytest python/tests/test_decompiler_arch_roundtrip.py -k
  'aarch64_o2_compact_signed_byte_switch' -q`: passed against a real cross-built
  fixture and host reference.
- `uv run pytest python/tests/test_dectest_selection.py -q`: 68 passed.
- `uv run python tools/dectest.py 04_switch_shapes 154_wide_switch
  204_adjacent_dispatch_tables 206_aarch64_wide_dispatch
  215_switch_on_wide_selector --arch aarch64`: ten scoped lanes, no regressions
  and no unrecorded improvements after accepting the one reviewed movement.
- `uv run python tools/dectest.py @o0 @o2 --arch aarch64`: 412 scoped lanes.
  The tip and an isolated fresh-release parent at `7c0ba967` report the exact
  same four baseline regressions and fourteen stale improvements. The four
  regressions are `164::tlv164_leaf_sum` at O0 and three `198` aggregate-return
  cells; exact parent reproduction proves none is attributable to this
  increment. The intended `206::dense_dispatch` movement is absent from the
  parent's improvement list because it still fails there and is accepted as
  `pass` only at the tip.
- `git diff --check`: passed before commit.
- `uv run pytest python/tests/test_docs_links.py -q`: four passed.
- `uv run pytest python/tests/test_docs_manifest.py -q`: two tests remain red
  because the parent already contains 14 undated and 19 unindexed historical
  records. This increment's record is dated and indexed and appears in neither
  offender list.

An isolated parent/tip fitness comparison against `7c0ba967` records the
increment's structural cost. Product mean LOC moves from 413.3712 to 414.0136,
LOC in files already above 1,000 lines moves from 52,010 to 52,215, and its
share of product LOC moves from 21.3253% to 21.3761%. No file crosses a 1,000-
or 2,000-line threshold and maximum file size is unchanged. The repository's
ratchet still reports seven broader stale-baseline differences; the isolated
comparison attributes only these three movements to this increment. This
accepted growth is concentrated in the existing dispatch analysis and should
be revisited when WP9 moves register/encoding facts behind target-owned queries.

The parent evidence commit `7c0ba967` also completed its whole Python suite:
4,610 passed, 118 failed, 70 skipped, 891 xfailed, and 125 deselected in
2,603.49 seconds. The extension and Python environment were worktree-local and
the worktree remained clean, but another run shared the allowed gitignored
fixture-build cache, so this is isolated-environment rather than
exclusive-machine/cache evidence. It remains a red parent snapshot and does
not substitute for the required post-`310b949e` whole Python gate.
The hardened tip at `5dbc3fc4` also completed its whole Python suite against a
fresh release extension: 4,595 passed, 126 failed, 78 skipped, 891 xfailed,
and 125 deselected in 2,711.36 seconds. An exact node-id comparison against the
parent found eight tip-only failures and no parent-only failures. Seven of the
eight (one `decompile_vas_sources` case and six declaration/CLI cases) all
passed together on an immediate clean-tip retry, classifying them as
full-suite order or shared-state contamination rather than deterministic WP5
regressions. The sole reproducible delta was the expected stale test census:
this increment adds six Rust test declarations. Commit `88bb8650` refreshes
that generated baseline from 4,611 to 4,617 declarations, leaves the
never-executed pool at zero, and the focused six-test census suite then passes.

The complete gate is therefore recorded and triaged, but remains red because
of the repository's broad existing Python failures. The focused retry does not
turn that red snapshot into a green release claim, and the whole suite was not
rerun solely for the generated census JSON change.

No DecBench run or upstream interaction was performed.
