# WP3 versioned SSA invalidation: first consumer migration

> **Kind:** record · **Date:** 2026-09-06

## Outcome

Behavioral commit `925dc002` introduces the first bounded implementation of
WP3's pipeline-owned SSA lifecycle. `SsaInfo` carries a revision, and
`VersionedSsa` prevents a stale artifact from being consumed after a declared
SSA-relevant mutation. `Invalidate` distinguishes CFG, definition, use, type,
presentation, and conservative-all changes; its default is deliberately
`All`.

The production `normalize_definedness_and_compute_ssa` transaction is the
first migrated consumer. When `erase_unobserved_masked_inputs` changes operand
uses, the transaction declares `Invalidate::Uses`, rebuilds the exceptional
CFG view, and reconstructs SSA before returning it. Type-only and
presentation-only changes do not trigger a value-identity rebuild.

This is not WP3 completion. The versioned owner currently spans one LLIR
normalization transaction, not the entire lift-to-AST pipeline. Stable opaque
identity through AST lowering, instruction origins, copy-propagation
migration, per-pass change sets, and the legacy-`All` ratchet remain open.

## Changes

- `src/ir/ssa.rs`: `SsaInfo::revision`, `Invalidate`, and `VersionedSsa`.
- `src/python_bindings/ir/pipeline.rs`: the definedness-normalization mutation
  declares its use change and ensures current SSA before consumption.
- `tests/test_census_baseline.json`: census commit `4bfee20c` records the three
  new unit contracts.

The exact parent for the behavioral comparison is `d0cfdfce`; the exact
measured tip is `4bfee20c`.

## Verification

The focused SSA module reports 15 passed tests. The focused Python entry-point
equivalence, determinism, and pipeline-profile set reports 19 passed tests.

The required exact-tip Rust command was:

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"
cargo test --features python-ext
```

It completed with 4,212 passed, zero failed, and five ignored library tests;
all integration and documentation targets passed. The isolated verification
checkout used the complete generated fixture corpus after an initial run
correctly failed because its disposable build directory contained only the
stripped comparison lanes.

The identity-only output gate decompiled the same 419 stripped fixture lanes
at parent and tip. Both normalized result maps have SHA-256:

```text
d86d3399127f93a292e895acc84375d2622065b9acf17d38228bb20973ca0c21
```

They are byte-for-byte identical. Both revisions report the same 116 lane
divergences and zero infrastructure failures. Relative to the older committed
ratchet, both also report the same 29 unrecorded divergences and eight healed
entries; that independent ratchet drift is not caused by this increment.

The complete exact-tip Python command was:

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"
uv run pytest python/tests/ -q
```

It completed red after roughly 50 minutes: 87 failed node IDs, 881 xfails, 59
skips, and zero xpasses. Failures span already-red fixture matrices, generated
documentation, fitness/baseline ratchets, dialect expectations, variable
addresses, and other repository debt. One focused return-definedness
expectation is also stale because current output names the value `value`
instead of `arg0`. A full parent Python run was not performed, so this result
does not claim the entire Python failure set is independently A/B-proven.
The byte-identical 419-lane comparison, focused consumer tests, and green full
Rust gate are the bounded causality evidence for this identity-only slice.

No DecBench run or upstream interaction was performed.
