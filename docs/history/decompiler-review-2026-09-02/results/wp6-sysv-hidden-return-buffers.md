# WP6 SysV hidden return-buffer evidence — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

## Outcome

Commit `ede20fb0` repairs a call-recovery gap for SysV AMD64 functions that
return memory-class aggregates through a hidden result pointer. Call argument
reconstruction previously kept the adjacent `%rdi = %rsp` setup but discarded
an unchanged explicit argument already live in `%rsi`. The rendered call then
lacked the source argument and the stack destination was not promoted as one
aggregate object.

The implementation now combines adjacent setup expressions with missing
caller live-ins only when parameter-slot, reaching-value, and clobber evidence
all agree. The declared aggregate byte width is carried through the recovered
hidden-pointer contract as a C pointer-to-array, translated back to entry-stack
coordinates, and supplied as one object hint to stack promotion.

## Fixture evidence

Using a freshly rebuilt release extension, these execution-differential lanes
changed from fail to pass:

- `195_by_value_aggregates:clang:O2:bv195_big_roundtrip`
- `195_by_value_aggregates:gcc:O2:bv195_big_roundtrip`
- `198_aggregate_return_edges:gcc:O2:agr198_five_roundtrip`

The complete scoped host run covered 12 lanes with zero regressions and three
improvements:

```text
uv run python tools/dectest.py \
  '195_by_value_aggregates:*:*' \
  '197_homogeneous_float_aggregates:*:*' \
  '198_aggregate_return_edges:*:*' \
  --jobs 8 --full
```

Fixture `198` is now entirely pass/structural across those host lanes. The
remaining failures are the four `bv195_make_mixed` cells in fixture `195` and
several O2 helper/wrapper cells in fixture `197`; split integer/SSE and
homogeneous-float aggregate recovery therefore remain roadmap work.

## Validation

Focused Rust validation passed 90 call-argument tests and five indirect-result
tests, including new coverage for a hidden result setup combined with a live-in
argument and for one aggregate stack-object hint.

The required full Rust command passed at the exact source commit:

```text
cargo test --features python-ext
```

The library target reported 4,060 passed, 0 failed, and 5 ignored; all
integration and documentation targets also passed.

The whole Python suite completed, but remains red:

```text
uv run pytest python/tests/
116 failed, 4613 passed, 68 skipped, 125 deselected, 896 xfailed
2 subtests passed in 2493.96s
```

The run includes expected generated-census and improvement-ratchet failures as
well as the repository's broad existing failure set. The census is refreshed
for the two new declared Rust tests. Behavioral baselines are not refreshed by
this increment because an improvement ratchet is evidence to review, not
permission to accept every concurrent baseline change.

## Scope and limits

This evidence is limited to the supported SysV AMD64 hidden-first-argument
contract. Existing AArch64 handling is separate, and this increment makes no
claim for Win64, 32-bit targets, arbitrary architectures, or non-C aggregate
ABIs. It does not complete WP6's general constraint solver.

No DecBench run, publication, issue, comment, or pull request was performed.
