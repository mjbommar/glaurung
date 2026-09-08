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

The exact parent for the first behavioral comparison is `d0cfdfce`; its exact
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

## Follow-on: retain the owner across return materialization

Commit `09522773` removes the remaining throw-away SSA construction inside
`prepare_llir_for_lowering_with_shadow`. One `VersionedSsa` now spans initial
definedness normalization, prototype recovery, and explicit return-value
materialization. Materializing a recovered return declares `Invalidate::Uses`;
the same owner reconstructs before indirect-target recovery, structuring, and
value numbering. Its revision therefore records both repairs rather than
resetting to zero at the second boundary.

Focused verification at `09522773`:

- 15 SSA tests passed, including two sequential invalidations on one owner;
- the direct return-materialization SSA test passed;
- 19 entry-point-equivalence, determinism, and pipeline-profile tests passed
  against a release-built extension;
- `cargo test --features python-ext` passed completely: 4,212 library tests,
  zero failed, five ignored, plus every integration and documentation target;
  the 44-test CFR target reported 44 passed and ten ignored in 523.24 seconds;
- the 419-lane stripped identity map is byte-for-byte identical to the prior
  `4bfee20c` map, with the same SHA-256 shown above. The command still exits 1
  for the identical pre-existing ratchet drift.

The mandatory whole Python suite completed with 87 failed node IDs, 881
xfails, and 57 skips. The focused WP3 tests are not among the failures. This is
still a red repository-wide gate and therefore not release evidence; the
captured log is
`$HOME/.cache/glaurung/tmp/wp3-return-ssa-python.log`. The shell command used
`tee`, whose zero exit status masked pytest's nonzero status, so the result is
classified from pytest's failure report rather than the pipeline status.

No DecBench run or upstream interaction was performed.

## Follow-up: classify mutations at their call sites

Commit `bac6cef8` adds `VersionedSsa::apply_mutation`, whose API requires an
explicit `Invalidate` class and a changed/no-op result. Both current LLIR
mutations after SSA construction now use it: dead masked-input erasure and
prototype-driven return materialization each declare `Invalidate::Uses` at the
mutation call. A no-op retains the current artifact; an actual use mutation
makes consumption fail until `ensure` reconstructs SSA.

The new contract test was observed red before the API existed. It and the three
adjacent default-invalidation, rebuild, and non-semantic-change tests pass
individually with 4,416 unrelated tests filtered out. No broad suite or external
benchmark ran. This closes migration of the currently active pipeline mutation
sites, but compile-time enforcement for future mutating passes and a durable
legacy-`All` count ratchet remain open.

Commit `e8bec18c` adds that first durable ratchet. Raw
`VersionedSsa::invalidate` is now private, and the focused source contract pins
the production pipeline to two classified `apply_mutation` sites, zero direct
invalidation calls, and zero `Invalidate::All` sites. Adding or removing a
registered post-SSA mutation therefore requires an explicit test update. The
ratchet and the adjacent changed/no-op mutation contract pass individually with
4,417 unrelated tests filtered out. Detecting a wholly unregistered raw LLIR
mutation remains the open enforcement edge.

Commit `2fe827df` closes that edge for the production post-SSA transaction.
`SsaTrackedLlir` takes the only mutable borrow of the LLIR once SSA is created,
exposes immutable function access to consumers, and exposes mutation only
through the classified gateway. A new mutation in this transaction must
therefore supply an `Invalidate` class, while the ratchet continues to pin two
registered sites and zero legacy `All` sites.

The focused ratchet, changed/no-op mutation contract, and adjacent pipeline
compile contract pass individually with 4,417 unrelated tests filtered out. No
broad suite or external benchmark ran. This establishes the requested
registration rule for the authoritative LLIR-to-AST pipeline; AST-native
identity lifecycle and the remaining WP3 consumer/origin criteria remain open.
