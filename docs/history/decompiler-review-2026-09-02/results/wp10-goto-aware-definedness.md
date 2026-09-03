# WP10 goto-aware definition verification

## Revisions and build

- Before: `2419372380e229d938bc54da0e3e656289b262c2`
- After: `96afcb2e` (`ir: verify definitions across goto control flow`)
- Release extension SHA-256:
  `e2701cb13bcf9e203c35a1b5ce49957a3892949aefcc8e62af5013b2ae0d2c1c`
- Toolchain: `rustc 1.97.0-nightly (f53b654a8 2026-04-30)`,
  `cargo 1.97.0-nightly (eb9b60f1f 2026-04-24)`, CPython 3.14
- Build command:
  `TMPDIR=/home/mjbommar/.cache/glaurung/tmp uv run maturin develop --release`

The checkout contained concurrent decompiler work outside this increment.
Results below therefore establish compatibility with that exact worktree; they
do not attribute its unrelated output changes to this increment.

## Change

`src/ir/verify_defs.rs` no longer skips the flow-sensitive
`UsedBeforeDefinition` rule whenever a rendered function contains labels or
gotos. It builds a statement-level CFG over the final emitted AST, resolves
labels and gotos, models structured branches, loops, switches, breaks, and
exception arms, and computes maybe-reaching definitions to a fixed point.
Missing and duplicate labels decline this stronger claim while preserving the
always-safe `NeverDefined` result. The whole-function read inventory now also
covers `Throw`, `IndirectGoto`, and `TryCatch` bodies.

The CFG and verifier consume only normalized AST nodes and virtual-register
identities. They do not inspect image format, instruction encoding, operating
system, or target architecture. This makes the analysis layer portable across
every backend that reaches this AST, without claiming that every Glaurung
backend can currently lift or decompile every input.

## RED and GREEN evidence

The first RED test constructed `goto L; var2 = 1; L: var1 = var2` and showed
that the former implementation returned no finding. The completed suite adds
forward and backward gotos, nested gotos, loop exits, malformed label graphs,
and a malformed-label plus indirect-target case. The latter failed RED because
the always-safe read inventory omitted indirect targets, then passed after the
inventory was completed.

```text
cargo test --features python-ext ir::verify_defs::tests -q
38 passed; 0 failed
```

The full Rust/bindings gate also passed:

```text
cargo test --features python-ext
3100 library tests passed; 3 ignored
all ordinary integration targets passed
1 doctest passed; 1 ignored
```

## Fixture and output evidence

The goto-heavy behavioral slice selected 20 of 838 fixture lanes:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp uv run python tools/dectest.py \
  102_duffs_device 103_computed_goto 105_goto_ladder \
  145_control_flow_flattening 211_irreducible_loops --full
SCOPED: 20 lanes of 838 (2%) - no regressions in scope
```

This verifier changes diagnostics, not the emitted executable C statements.
Accordingly the scoped behavior verdicts, C/Rust source counts, structural
goto/switch/break counts, execution differentials, GED, type, byte, and Union
scores have no change attributable to this increment. The release rebuild took
about 33 seconds; the focused Rust suite took about 37 seconds including
compilation; the already-built goto fixture slice took about 8 seconds. Peak
RSS was not captured, so no RSS claim is made.

The full structural test file completed with 7 failures. One is the intended
newly visible `cpp_exception` definition finding. The remaining failures are
concurrent output/baseline drift outside this increment: direct-return versus
assignment spelling for `tail_dispatch`, recovered parameter names replacing
`argN` expectations, lost `memory_store` expectations, and unrecorded x87
definition improvements. This is recorded as a red shared-worktree gate, not
as verifier evidence or a reason to refresh the baseline.

## Census result and accepted interpretation

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp uv run pytest \
  python/tests/test_decompiler_defuse_census.py -q
3 passed; 3 failed
```

This is not a silent output regression. The new analysis exposed real reads
that the old verifier skipped, including uninitialised `ret` paths in
`cpp_template_int16` and `match_order`, an uninitialised `local_8c` path in
`rust_overflow_matrix`, and previously unscanned exception-body reads. At the
same time, concurrent pipeline work reduced aggregate undefined-read totals in
every compiler lane. The committed baseline was deliberately not refreshed:
doing so here would mix those unrelated improvements with this verifier change
and would convert newly visible decompiler defects into unexplained accepted
regressions. The new findings remain explicit repair targets.

## Trade-offs

The analysis remains deliberately may-defined at joins and loop backedges to
avoid false positives. It can therefore miss a read undefined on only one of
several paths. A malformed label graph declines `UsedBeforeDefinition` rather
than inventing edges, but still reports `NeverDefined`. This preserves
best-effort output and strengthens its health metadata without pretending the
render is semantically verified.
