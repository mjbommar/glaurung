# WP4 sibling-owned loop exits

> **Kind:** record · **Date:** 2026-09-08

## Result

Commits `300b7f66` and `99eae1f7` close one verified WP5-to-WP4 handoff exposed by
`212_loop_with_returning_arm-clang-O2.so::fsm_returns_from_arm`. Indirect-target
analysis already recovered the exact four-case dispatch, but tree recovery
declined the complete function. An earlier branch had legitimately taken
ownership of one return block; the multi-exit loop later treated that
sibling-owned exit continuation as fatal.

The first increment proved that a sibling-owned loop exit need not reject the
whole tree, but its empty continuation exposed an immediate semantic regression
in the adjacent `two_returning_arms` function: falling off the loop returned 4
instead of 1. The accepted follow-up never treats that continuation as empty.
It materializes a `DuplicatedReturn` only when the bounded tail planner recorded
the exact target and loop-exit predecessor; otherwise it preserves a verified
`SharedGoto` to the single-owned continuation. Candidate and tree verification
remain mandatory. The state-machine case independently covers all 14 blocks
and 20 CFG edges.

The production v1 default is deliberately unchanged. With explicit
`shadow_v2=True`, the normal typed render pipeline now emits a four-case switch
instead of declining to v1's unrecovered indirect jump. Some case-suffix gotos
remain, so this is a correctness and coverage closure rather than a claim that
the state machine has reached source-like readability.

## Focused evidence

```bash
cargo test --features python-ext ir::structure_v2:: --lib
```

Result: 41 passed, 0 failed in 0.99 seconds. This includes the adjacent
`two_returning_arms` clone-provenance regression.

```bash
uv run pytest -q \
  python/tests/test_decompiler_render_styles.py::test_shadow_loop_switches_with_shared_exits_round_trip
```

Result: 1 passed. The release-built shadow output contains the recovered FSM
switch, no unrecovered-indirect-jump marker, and both affected functions pass
their compiled execution differentials.

The same test runs the ordinary compiled execution differential with seed 1234
and 12 fuzz cases. The result is `pass` over 27 deterministic cases. A direct
A/B invocation recorded:

- production v1: `fail`, returning 1 instead of 0 for the `abc` input;
- verified shadow v2: `pass`, 27 cases.

The pinned `99eae1f7` fixture-212 family check requested four functions. Two
remain local shadow declines. Of the two rendered candidates,
`fsm_returns_from_arm` improves from fail to pass and `two_returning_arms`
remains pass over 22 cases. The result is one improvement, one stable pass,
zero regressions, and zero infrastructure findings. Structurally,
`two_returning_arms` improves from eight gotos to one; the FSM has three shadow
gotos versus production's two, so its correctness improvement is not presented
as a readability win.

Commit `b214a053` extends the same ownership rule to joins selected while a
natural loop is active. An inner conditional may use an immediate
post-dominator only when that join remains inside the active loop; a
function-level epilogue beyond the loop stays owned by the loop or its sibling
path. The loop's own continuation now uses the same exact planned-clone or
verified-shared-goto rule as its explicit exit regions.

The pinned follow-up again requested all four Clang O2 fixture functions. Three
now render through shadow v2 and `all_arms_break` still declines locally:

- `fsm_returns_from_arm`: production fails and shadow passes 27 cases;
- `two_returning_arms`: production and shadow both pass 22 cases, while gotos
  fall from 8 to 1;
- `nested_loop_returning_arm`: production and shadow both pass 22 cases, while
  gotos fall from 42 to 35;
- execution summary: 1 improved, 2 stable passes, 0 regressions, and 0
  infrastructure findings.

Clang fully unrolls the source inner loop in this O2 object, yielding one
natural outer loop around a 70-block returning comparison ladder. The new real
fixture test covers all 70 blocks and 116 edges and requires deterministic,
parseable structured output. Its shadow text grows from production's 9,319
bytes to 25,894 bytes, so this remains an explicit output-size and cleanup
debt despite the seven-goto reduction.

The focused Rust module after this increment reports 42 passed and 0 failed in
0.93 seconds. The expanded Python execution regression passes as one test over
the three rendered fixture functions.

## Broad-gate boundary

Repository policy requires a whole-Python attempt after a source commit:

```bash
uv run pytest python/tests/ --tb=short -q
```

The shared dirty checkout reached 17% and reported six failures in existing
cross-architecture round-trip cells: AArch64 optimized call flow, i386
GOT-relative switches, two ARM32 wide-selector lanes, and two i386 wide-selector
lanes. The run was stopped after those terminal failures were captured rather
than spending the rest of the day on unrelated tests. The new focused Python
regression and all 41 structure-v2 tests remain green; the whole-Python gate is
red and is not represented as passing.

After the semantic follow-up commit, the required bounded rerun used the same
suite with `-x`. It reached 17% and stopped at the first same broad failure,
`test_aarch64_optimized_call_flow_round_trips`: `call_chain_in_loop` returned 0
instead of 22176384 for `[0, 0]`. This is outside the structure-v2 fixture-212
slice, but the global gate remains honestly red. The required post-`b214a053`
attempt reproduced that same first failure at 17%; no new earlier failure was
observed.

## Roadmap effect

This expands WP4's locally degrading verified subset and closes one concrete
returning-switch-arm family in the explicit shadow production route. It does
not satisfy the remaining promotion criteria: clean-pinned block/edge
accounting, GED, structure-axis, and runtime/output-size evidence are still
required before v2 can become the default.
