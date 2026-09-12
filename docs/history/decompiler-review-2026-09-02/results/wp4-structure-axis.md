# WP4 source-relative structure axis

> **Kind:** record · **Date:** 2026-09-12

## Result

Commit `156b641e` extends `tools/structure_v2_compare.py` with the missing
source-relative structure measurement required by WP4. Production and shadow
are projected through the same native control-skeleton metric and compared to
the same checked-in C function. The report keeps `no_c_source`,
`production_missing`, `shadow_declined`, `production_unparsed`,
`shadow_unparsed`, and `abstained` outside the jointly scored denominator.
Coverage loss therefore cannot improve the distance total.

This is the repository's control-structure axis, not DecBench GED. It measures
loops, branches, switches, transfers, returns, and statement shape while
discarding expression interiors. No DecBench or Joern command was run.

Nine focused tool tests pass. They include a source-identical shadow
improvement, an explicit shadow decline, fixed-denominator aggregation, the
real mixed render/decline batch, and the existing reviewed-goto contracts.

## Exploratory fixture-212 slice

The post-commit command was:

```bash
uv run python tools/structure_v2_compare.py --jobs 1 \
  --fixture '212_loop_with_returning_arm-clang-O2.so' \
  --output "$HOME/.cache/glaurung/tmp/structure-v2-212-156b641e.json"
```

All four requested functions were jointly scored. Two improve and two regress:

| Function | Production distance | Shadow distance | Movement |
|---|---:|---:|---:|
| `fsm_returns_from_arm` | 22 | 27 | +5 |
| `two_returning_arms` | 40 | 37 | -3 |
| `nested_loop_returning_arm` | 250 | 285 | +35 |
| `all_arms_break` | 68 | 67 | -1 |
| **Total** | **380** | **416** | **+36** |

This changes the next decision materially: closing every shadow decline and
reducing gotos does not yet make this family source-structurally better. The
70-block compiler-unrolled `nested_loop_returning_arm` comparison ladder is the
dominant debt. Total output also grows from 15,432 to 34,753 bytes. The narrow
timing was 0.216 seconds for production and 0.222 seconds for shadow, with
89,024 KiB process RSS, but one tiny cached object is not a runtime budget.

## Provenance boundary

The JSON correctly names tool commit `156b641e`, but the release extension was
built in the shared checkout while another lane's uncommitted source-metrics
and syntax work was present. The CPython 3.12 extension hash was
`60e39209e3cbd2893ec40691adb8bed9ab702f6c6f51cbc5086f7c5074aa374e`; the
remaining native-source diff hash was
`6f0bc2e8519dc6203226e71961dc4c0752742dd650467a7837ea46ab4e4ad9b1`.
Consequently these four rows are exploratory evidence, not the clean pinned
715-row promotion result. Rebuild from a clean revision after the concurrent
lane lands, then run the full comparison once.

## Roadmap effect

The structure-axis measurement route is implemented and fail-closed. Its WP4
exit criterion remains open because the clean pinned full sample has not run
and this focused slice currently regresses in aggregate. The next quality task
is to reduce the verified shadow tree expansion in
`nested_loop_returning_arm`, then rerun this four-function slice before paying
for the full sample.

## Terminal-branch presentation cleanup

Commit `91d5713f` performs the first targeted reduction. Once structure-v2's
verified region has fixed block ownership and lowered to the AST, an `else`
after a branch that returns on every path carries no control information. The
shadow-only presentation pass rewrites `if (c) return; else body` as
`if (c) return; body`, including nested all-path returns, while preserving the
conditional's origin set. Partial-return arms, gotos, breaks, and continues do
not qualify.

An attempted tree-level implementation was rejected before commit because the
focused gate showed it could disturb lexical join ownership and duplicate paths
in `early_return` and `hybrid_switch`. The accepted AST-boundary implementation
passes all 46 structure-v2 tests, including those two controls, and the
release-built four-function execution differential remains green.

The same fixed four-function slice moves in the intended direction:

- aggregate shadow structure distance falls from 416 to 394, versus production
  at 380;
- shadow output falls from 34,753 to 26,894 bytes;
- `nested_loop_returning_arm` falls from distance 285 to 273 and from 25,894 to
  20,330 bytes;
- `all_arms_break` falls from distance 67 to 63 and from 4,555 to 3,340 bytes,
  now smaller than production's 3,567 bytes;
- gotos and all four execution verdicts are unchanged.

The result is substantial cleanup but not structure-axis closure: shadow still
trails production 394 to 380 on this slice. The post-commit bounded whole-Python
attempt reached 17% and stopped at the same existing AArch64
`call_chain_in_loop` mismatch (0 instead of 22176384 for `[0, 0]`), with no new
earlier failure.

The post-commit JSON names `91d5713f`. Because the shared release build still
included another lane's uncommitted native changes, it remains scoped
engineering evidence rather than the clean promotion run. Its CPython 3.12
extension hash is
`a98a8f60cd21e0de5308d7475a8b417981cb6af10bff48e49777b66be6ac5253`, and
the remaining native-source diff hash is
`8526d3054b53773d2ed4ad3a2272c626d124387867787a11e84f1030897ac396`.

## Terminal-transfer presentation cleanup

Commit `7d9335e6` generalises the same proved lexical rule from returns to every
unconditional transfer represented by the typed AST: `return`, `throw`, direct
or indirect `goto`, `break`, and `continue`. Once either transfer executes, the
following `else` is unreachable; moving that body after the guard changes no
condition, transfer, or statement order. A new attributed direct-goto test was
observed red before the implementation. All 47 focused structure-v2 tests pass,
and the release-built four-function execution differential remains green.

The post-commit focused command is the command above with output path
`$HOME/.cache/glaurung/tmp/structure-v2-212-7d9335e6.json`. All four functions
remain jointly scored, and the result crosses the focused structure threshold:

| Function | Production distance | Shadow distance | Movement |
|---|---:|---:|---:|
| `fsm_returns_from_arm` | 22 | 25 | +3 |
| `two_returning_arms` | 40 | 31 | -9 |
| `nested_loop_returning_arm` | 250 | 251 | +1 |
| `all_arms_break` | 68 | 65 | -3 |
| **Total** | **380** | **372** | **-8** |

Compared with the preceding return-only cleanup, shadow distance falls from
394 to 372 and output falls from 26,894 to 19,899 bytes. The dominant unrolled
function falls from distance 273 to 251 and from 20,330 to 13,534 bytes. Goto
counts remain 58 production versus 43 shadow, and all execution verdicts remain
green. The post-source fail-fast Python gate again reached 17% with no earlier
new failure and stopped at the existing AArch64 `call_chain_in_loop` mismatch
(0 instead of 22176384 for `[0, 0]`).

This proves favorable movement for the focused family, not WP4 promotion over
the pinned full comparison. The release extension still includes the same
concurrent native-source diff named above; its CPython 3.12 hash is
`70feb570d1842d5700e8a14c1124a8da5cf2a2372a8314e666e7d689430c9f38`.
The next WP4 measurement is the clean pinned full comparison after those shared
changes land. Until then, quality work should proceed on the remaining explicit
per-function regressions or on WP5 rather than repeatedly running the corpus.

## Loop-local partial switch joins

Commit `40f06b60` fixes the remaining three `fsm_returns_from_arm` suffix
gotos at their ownership source. A returning case means the latch cannot
post-dominate the whole switch. The tree builder now accepts a partial
loop-local join only when at least two in-loop arm entries either are one exact
candidate block or have that block as their sole successor. Out-of-loop arms
are typed exits and do not vote; the loop header, guard, dispatch, active, and
already-owned blocks are all excluded. Thus the rule derives one continuation
from CFG identities without matching labels or rendered text.

The real Clang O2 fixture test was observed red with three `goto L_113c`
transfers. It now renders ordinary `break` arms, owns the latch once after the
switch, and has zero gotos. All 47 structure-v2 tests and all four executable
fixture-212 differentials pass. The post-commit focused report at
`$HOME/.cache/glaurung/tmp/structure-v2-212-40f06b60.json` records:

- `fsm_returns_from_arm`: distance 25 to 23, gotos 3 to 0, and 1,642 to 1,619
  shadow bytes relative to the preceding commit;
- aggregate shadow distance 372 to 370, versus production at 380;
- aggregate shadow gotos 43 to 40, versus production at 58;
- aggregate shadow output 19,899 to 19,876 bytes, versus production at 15,432.

The required post-source Python fail-fast gate again reached 17% without an
earlier failure and stopped at the existing AArch64 `call_chain_in_loop`
mismatch. The report names `40f06b60`; the CPython 3.12 extension hash is
`2a087b14b4655b97b2de1e0f1394fdee52c8cf9d6a4cdb6c566f2d6a9a4289d4`.
The build still includes the concurrent native-source diff whose hash is
`8526d3054b53773d2ed4ad3a2272c626d124387867787a11e84f1030897ac396`,
so the clean pinned full comparison remains the promotion boundary.
