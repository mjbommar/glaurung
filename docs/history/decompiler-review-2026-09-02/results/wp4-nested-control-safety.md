# WP4 nested-control safety and switch-exit repair

> **Kind:** record · **Date:** 2026-09-04

## Result

Commit `c3bbe2a6bdd100589126561ce2292974eeb06494` removes every execution
regression exposed by the structure-v2 corpus comparator at this checkpoint.
The production structurer remains authoritative; this is shadow-mode evidence,
not a promotion.

Two independent semantic defects were repaired:

1. post-tested fact collection no longer flattens a nested `If` by concatenating
   both arms, which had made conditional work unconditional; and
2. a typed loop exit nested in a C `switch` now uses a deterministic exit
   trampoline, because a bare `break` there exits the switch rather than the
   enclosing loop.

The first repair is deliberately fail-closed. The verified typed tree remains
available, but rendering declines when the current AST cannot preserve an
internal post-tested branch. This raises declines rather than publishing C that
passes syntax checks but changes behavior.

## Revisions and build

- Before: `0da8744d`, based on the execution route introduced at `6175d67d`.
- After: `c3bbe2a6bdd100589126561ce2292974eeb06494`.
- Build: CPython 3.14, PyO3, `uv run maturin develop --release`.

The repository advanced through concurrent parser commits while this increment
was tested. Only `src/ir/ast/lower_region.rs`,
`src/ir/structure_v2/render.rs`, and `src/ir/structure_v2/mod.rs` were staged in
the code commit.

## Focused RED/GREEN evidence

The pinned execution sequence was 21 regressions at `6175d67d`, six at
`0da8744d`, and zero at `c3bbe2a6`. The final two failures were
`145_control_flow_flattening:clang:{O2,O2strip}:flattened_accumulate`; both now
pass the ordinary execution differential in shadow mode.

Focused Rust coverage:

```bash
cargo test --features python-ext multi_exit_transfer_tests --lib
cargo test --features python-ext post_tested_fact_collection_refuses_to_flatten_an_internal_branch --lib
cargo test --features python-ext real_dowhile_fixture_declines_to_flatten_its_internal_early_exit --lib
cargo test --features python-ext real_wide_effect_switches_keep_typed_cases_when_rendering_declines --lib
cargo test --features python-ext real_flattened_switch_does_not_claim_its_enclosing_loop_exit_as_a_join --lib
```

## Pinned corpus evidence

Commands:

```bash
uv run maturin develop --release
uv run python tools/structure_v2_compare.py --jobs 4 \
  --output "$HOME/.cache/glaurung/tmp/structure-v2-c3bbe2a6.json"
uv run python tools/structure_v2_execution.py \
  "$HOME/.cache/glaurung/tmp/structure-v2-c3bbe2a6.json" --jobs 4 \
  --output "$HOME/.cache/glaurung/tmp/structure-v2-execution-c3bbe2a6.json"
```

Both reports identify revision
`c3bbe2a6bdd100589126561ce2292974eeb06494`.

Structural comparison over 715 requested functions in 436 built objects:

- 204 improved and 33 unchanged;
- 13 raw regressions: 4 exact accepted honest-goto rows and 9 unexplained;
- 465 shadow declines and 0 production-missing rows;
- comparable gotos: production 1,790, shadow 584;
- comparable bytes: production 693,393, shadow 1,223,475;
- summed time: production 51.30s, shadow 42.04s;
- wall time 23.43s; peak RSS 900,864 KiB.

Execution comparison over 250 candidates in 166 executable objects:

- 12 improved, 177 stable pass, and 22 stable non-pass;
- **0 regressed** and 0 infrastructure findings;
- 39 explicitly not executable by this harness;
- summed time: production 113.21s, shadow 82.51s;
- wall time: 49.44s.

The 39 non-executable candidates are not passes and are not evidence of
behavioral equivalence. They remain a separate coverage obligation.

## Gates and remaining work

`cargo test --features python-ext` passed from the exact staged working-tree
contents immediately before `c3bbe2a6`: the library reported 3,978 passed, 4
ignored, and no failures, followed by all integration and doc-test binaries
passing. The slow identity-retrieval tail completed normally.

The post-commit `uv run pytest python/tests/` gate completed in 2,454.38 seconds:
4,542 passed, 116 failed, 69 skipped, 125 deselected, 897 expected failures,
11 warnings, and 2 subtests passed. The global Python gate is therefore **red**.
Failures span ARM32 and i386 semantics, dialect parser expectations, fixture and
structural baselines, generated census/facet/stub/reference files, source-tree
fitness, documentation indexing, and other global health checks. This report's
missing history-index entry accounts for two of those failures and is repaired
in the accompanying documentation commit; the suite result is not rewritten as
green. The zero-regression statement above is limited to the pinned
structure-v2 execution comparator.

WP4 remains incomplete. Next work is to explain or repair nine structural
regressions, safely express nested post-tested branches, reduce or classify 465
declines, complete GED and structure-axis evidence, accept runtime/output-size
budgets, and extend the 39 non-executable candidates where a real comparison
contract is possible.
