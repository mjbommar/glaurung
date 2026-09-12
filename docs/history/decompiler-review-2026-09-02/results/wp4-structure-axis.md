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
