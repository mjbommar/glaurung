# WP4 sibling-owned loop exits

> **Kind:** record · **Date:** 2026-09-08

## Result

Commit `300b7f66` closes one verified WP5-to-WP4 handoff exposed by
`212_loop_with_returning_arm-clang-O2.so::fsm_returns_from_arm`. Indirect-target
analysis already recovered the exact four-case dispatch, but tree recovery
declined the complete function. An earlier branch had legitimately taken
ownership of one return block; the multi-exit loop later treated that
sibling-owned exit continuation as fatal.

The loop builder now retains the typed `Break` edge and records an empty exit
continuation when another structured path already owns the target. It neither
rebuilds nor duplicates that target. Candidate and tree verification remain
mandatory and independently cover all 14 blocks and 20 CFG edges.

The production v1 default is deliberately unchanged. With explicit
`shadow_v2=True`, the normal typed render pipeline now emits a four-case switch
instead of declining to v1's unrecovered indirect jump. Some case-suffix gotos
remain, so this is a correctness and coverage closure rather than a claim that
the state machine has reached source-like readability.

## Focused evidence

```bash
cargo test --features python-ext ir::structure_v2:: --lib
```

Result: 40 passed, 0 failed in 0.95 seconds.

```bash
uv run pytest -q \
  python/tests/test_decompiler_render_styles.py::test_shadow_loop_switch_with_a_shared_exit_round_trips
```

Result: 1 passed. The release-built shadow output contains `switch`, cases 0
through 3, and no unrecovered-indirect-jump marker.

The same test runs the ordinary compiled execution differential with seed 1234
and 12 fuzz cases. The result is `pass` over 27 deterministic cases. A direct
A/B invocation recorded:

- production v1: `fail`, returning 1 instead of 0 for the `abc` input;
- verified shadow v2: `pass`, 27 cases.

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
regression and all 40 structure-v2 tests remain green; the whole-Python gate is
red and is not represented as passing.

## Roadmap effect

This expands WP4's locally degrading verified subset and closes one concrete
returning-switch-arm family in the explicit shadow production route. It does
not satisfy the remaining promotion criteria: clean-pinned block/edge
accounting, GED, structure-axis, and runtime/output-size evidence are still
required before v2 can become the default.
