# WP4 corpus shadow-coverage evidence — 2026-09-04

> **Kind:** record · **Date:** 2026-09-04

## Outcome

`decompile_many(..., shadow_v2=True)` now declines one unsupported function
locally instead of aborting every requested function in the binary. The caller
can compare requested and returned VAs and count the refusal explicitly. Caller
contract errors, such as requesting shadow-v2 with a non-`decbench` style,
remain hard errors.

`tools/structure_v2_compare.py` uses that contract to compare production and
verified shadow output for every function in the current ground-truth
`structure` inventory. It batches each side per binary, runs a bounded number
of binaries concurrently, and emits deterministic JSON containing coverage,
goto counts, output sizes, timings, RSS, and per-function status.

## Complete exploratory census

The first complete run covered all 715 current structure rows across 436
fixture objects:

| status | functions |
|---|---:|
| improved | 180 |
| unchanged | 38 |
| regressed | 29 |
| shadow declined | 468 |
| production missing | 0 |

Thus shadow-v2 returned a comparable candidate for 247/715 rows (34.5%). Of
those candidates, 180 reduced goto count, 38 tied, and 29 increased it.
Comparable goto totals fell from 2,166 to 1,570, but this aggregate does not
override the 29 individual regressions. Comparable rendered size grew from
900,025 to 1,479,556 bytes (64.4%). Summed per-object time was 308.706 seconds
for production and 262.057 seconds for shadow; four workers completed the
comparison in 142.787 seconds with 892,176 KiB maximum RSS.

This is useful rejection evidence, **not promotion evidence**. The shadow
structurer remains opt-in because it has individual goto regressions, declines
65.5% of the target universe, and substantially increases output size. The
largest observed regressions include wide switches, Duff-style control flow,
flattened control flow, and dispatch nested in loops. Those families are the
next focused WP4 inputs.

## Nested-join repair

The first regression investigation found an ownership-order bug. When a
nested conditional's immediate post-dominator was exactly its enclosing stop
boundary, recovery discarded that boundary. The first visited arm then owned
the shared continuation and nested it under itself; siblings reached the
misplaced continuation with artificial gotos. Commit `1e0f41c7` retains the
join as the arms' stop while leaving its single emission to the enclosing
region.

On `07_packet_parser-gcc-O0.so::parse_packet`, the stack-canary/return epilogue
moved from a 20-space-deep branch to function scope and candidate size fell
from 3,572 to 3,492 bytes. Two avoidable transfers to that correctly placed
join remain and are pinned as explicit debt.

A second complete exploratory census measured the generic effect:

- among previously comparable candidates, 57 functions lost gotos, 173 tied,
  and 17 gained gotos;
- their aggregate goto count fell by 100 and output size fell by 122,459 bytes;
- 21 previously declined rows became renderable: 18 improved and 3 regressed;
- overall coverage rose from 247 to 268 candidates, with 217 improved, 10
  unchanged, 41 regressed, and 447 declined.

The apparent increase from 29 to 41 regressed rows is concentrated partly in
one Rust runtime `get_backtrace_style` body repeated across many fixtures, but
it remains a real blocker rather than being erased as duplication. The next
WP4 step is to eliminate or locally refuse those 17 worsened existing
candidates and the three newly renderable regressions, then rerun from a clean
native build.

## Provenance limitation

The report named committed revision
`54628f5af2d27fa91376e2a79ea22f06e623784f`, which contains the batch-local
decline and measurement tool. However, the native extension was built in the
shared worktree while unrelated, uncommitted CFG, Joern, and metrics changes
were present. Its dirty-source diff hashed to
`889ec323453d8683155e349959b0ba0a195c9efbf9ab48dd41bb1c75d09b0b89` when
recorded. The JSON remains in the local cache and is deliberately not committed
as a pinned benchmark result. Re-run from a clean native build after those
lanes land before accepting timing, output-size, or exact per-function counts
as promotion evidence.

The nested-join follow-up report likewise ran in the shared worktree before
the fix was committed, so its JSON revision field is `9a741786` rather than
`1e0f41c7`. Its before/after deltas are exploratory engineering evidence, not
a replacement for the required clean pinned run.

## Validation

```text
focused local-decline, invalid-style, and comparison-tool tests
3 passed

ruff check + format check over the three touched Python files
pass

complete comparison command
uv run python tools/structure_v2_compare.py --jobs 4 \
  --output "$HOME/.cache/glaurung/tmp/structure-v2-54628f5a.json"
exit 0
```

The required broad Rust gate was also attempted. It recorded a failure in the
concurrently added `metrics::byte_match` tests and one property test continued
growing past 17 GiB RSS, so the already-failed run was stopped. That result is
neither attributed to WP4 nor reported as a green gate. A clean full Rust gate,
the full Python suite, execution differential, block/edge accounting, and GED
remain required.

No DecBench run or upstream interaction was performed.
