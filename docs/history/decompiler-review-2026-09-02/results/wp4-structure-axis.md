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
