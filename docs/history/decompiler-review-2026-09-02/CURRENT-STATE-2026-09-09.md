# Decompiler roadmap current state — 2026-09-09

> **Kind:** record · **Date:** 2026-09-09

**Branch:** `master`

**Implementation revision summarized:** `3bc525f5`

**Operational authority:** [`PLAN.md`](PLAN.md)

**Boundary:** internal Glaurung work only; no DecBench issue, comment, pull
request, or other autonomous upstream interaction.

This is the concise resume document. The result files remain the evidence for
individual increments, and `PLAN.md` remains authoritative when this summary
and the live checklist differ. In particular, the older review attachment says
WP2 was incomplete; the live plan records that the shared pipeline and explicit
pass ordering have since landed, so WP3 is now the active architecture lane.

## Roadmap state

| Package | State | What is true now | What remains |
|---|---|---|---|
| WP0 | Complete | Inventory, batching, language split, and fail-closed gate contracts are established. | Maintain the ratchets as fixtures and tests change. |
| WP1 | Essentially complete | The MIR production trial failed its cost criterion; AST/label-CFG remains the production direction. | Delete dormant substrate responsibility by responsibility under WP10 where independent uses do not justify it. |
| WP2 | Complete in the live plan | Entry points share pipeline ownership, budgets, pass order, and checked profiles. | Preserve ordering and budget contracts while later packages change the pipeline. |
| WP3 | Active, substantially implemented | Pipeline-owned SSA, classified invalidation, stable `ValueId`, identity-keyed type and bit-demand facts, render-only role naming, statement/expression origins, structured mappings, and many identity-aware consumers have landed. | Finish the residual semantic-name-reader and origin audits, prove deterministic mapping closure, and remove `tag_phys` only after its final typed dependency is gone. |
| WP4 | Substantially underway | Shadow structuring locally degrades, recovers important loops/continues, and has bounded execution evidence. | Complete unexplained block/edge accounting, corpus GED/structure evidence, and promotion budgets before replacing v1. |
| WP5 | Substantially underway | Typed case/default/provenance evidence is shared by CFG and structurers; dense switches and several real host/A32/i386 cases now recover. | Close Thumb, remaining AArch64/wide-selector cells, residual declines, and the complete promotion matrix. |
| WP6 | Partial | Several return-width, signedness, aggregate, HFA, pair-return, hidden-result, and compiler-helper ABI defects are fixed. | Build the general stable-value constraint solver across equality, pointer/pointee, aggregate, call, and confidence facts. |
| WP7A | Complete | Width-safe immediate expression cleanup and its equivalence controls landed. | Maintain the proof boundary. |
| WP7B | Partial | Important comparison, range, loop-condition, literal, and cast cleanup rules landed; `classify` now renders `while (n > 100)` cleanly. | Implement the planned SSA idiom framework instead of accumulating renderer-specific rules. |
| WP8 | Nearly complete | Declaration authority, conflict provenance, analyst annotations, and deterministic scored output are implemented. | Prove the broad “never worse than trusted declaration” corpus exit criterion. |
| WP9 | Partial | Target model, instruction census, ARM register views, and several ABI/architecture facts are explicit. | Continue shared fact migration, ARM32 coverage, silent-writer closure, and required architecture-profile wiring. |
| WP10 | Partial | LLIR/definedness invariants, goto-aware checks, and fail-closed performance preflight exist. | Add structured health closure, finish O2/full-gate triage, and delete only superseded code with responsibility evidence. |

The full objective is not complete. M3 remains partial because WP3 is open;
M4 through M6 remain open.

## Recent decompiler-quality progress

The recent WP3 sequence removed several cases where coalesced SSA versions of
one physical storage location lost valid type or lowering evidence:

- integer declarations retain proved width and signedness;
- prepared and final declaration planning retain same-storage scalar and
  pointer facts while mixed storage still declines;
- high-variable pointer and unsigned-literal refinement accepts same-storage
  coalescing without treating ambiguity as proof;
- packed dword concatenation preserves the required 64-bit widening before a
  high-half shift;
- live-in parameter discovery now recognizes phi plumbing from exact SSA
  identity rather than parsing `reg#version` presentation text.

The last item fixed a real correctness defect. An opaque phi copy retained only
by conservative call may-uses previously invented argument slot 3. The new
test was red with `{3}` and is green after `a957c94c`. The explicit no-sidecar
API retains spelling compatibility; production with an identity snapshot does
not use it.

`ed8128a7` also adds a fast byte-neutrality contract: one real fixture function
must emit identical C when decompiled inside the whole exported-function batch
or as a one-function scoped batch. This does not replace the 419-pair
before/after identity sweep, but it catches batch-population leaks during the
ordinary narrow loop.

The latest WP3 slice fixes exceptional control-flow entry rather than another
display-name consumer. LSDA-proven landing markers now survive a preceding
normal return, and an unwinder-supplied exception object becomes an explicit
external unknown only when stable identity proves the ABI register. GCC O0
Hello C++ `main` moves from two undefined reads to zero without inventing a
local definition; all four directly owning GCC/Clang O0/O2 exception cells
remain green.

Detailed evidence:

- [`results/wp3-coalesced-integer-declaration-types.md`](results/wp3-coalesced-integer-declaration-types.md)
- [`results/wp3-abi-width-identities.md`](results/wp3-abi-width-identities.md)
- [`results/wp3-declaration-identities.md`](results/wp3-declaration-identities.md)
- [`results/wp3-pointer-refinement-identities.md`](results/wp3-pointer-refinement-identities.md)
- [`results/wp3-unsigned-literal-identities.md`](results/wp3-unsigned-literal-identities.md)
- [`results/wp3-coalesced-packed-lane-lowering.md`](results/wp3-coalesced-packed-lane-lowering.md)
- [`results/wp3-scoped-byte-neutrality.md`](results/wp3-scoped-byte-neutrality.md)
- [`results/wp3-phi-plumbing-identities.md`](results/wp3-phi-plumbing-identities.md)
- [`results/wp3-exception-landing-inputs.md`](results/wp3-exception-landing-inputs.md)

## Latest validation boundary

The isolated exact-source release overlay for `b0319768` produced native
SHA-256:

```text
de6e45554988f2cc8497f6db9ea285d0bd85357aeff520be4f29615463436a20
```

Latest focused evidence:

- identity-proven and ambiguous landing-input contracts: 2/2 passed;
- exception-recovery module: 13/13 passed;
- label-pruning module: 22/22 passed;
- real GCC O0 Hello C++ definedness regression: passed with zero verifier
  findings;
- directly owning `cpp_exception` cells: 4/4 passed across GCC/Clang O0/O2;
- broader fixture 136 exception slice: unchanged at its 12 failed baselines.

The required post-source-commit Python suite reached an unrelated CFR corpus-
size assertion after 569 passes, 15 skips, three xfails, and two subtests. Only
eight eligible retrieval queries were available where that test requires 20.
The exception-recovery module is 13/13 green after replacing one stale nested-
cast assertion with the semantic four-byte `int` throw contract. These results
support the bounded change only and are not a release-green claim. No complete
fixture matrix, 419-pair identity sweep, DecBench, Joern, GED, performance, or
corpus-wide measurement was run.

The release measurement used the isolated verifier rather than the stale main-
checkout extension. The result record names the exact overlays, native hash,
commands, and limitations; it is the authority for this increment.

## Ordered resume point

1. Continue WP3 before starting a new dependent WP6/WP7B architecture layer.
2. Audit remaining production `ssa_base`, `split_once('#')`, `argN`,
   `local_`, and `stack_` readers. Classify each as:
   - semantic identity requiring `ValueIdentities`/`ValueId` migration;
   - exact version/lifetime logic that must remain exact; or
   - explicit pre-sidecar/no-sidecar compatibility code.
3. For each genuine semantic reader, add an opaque-name positive and a
   misleading-name refusal before changing production code.
4. Validate only the owning Rust module and one causally relevant fixture while
   iterating. Rebuild an exact release commit before fixture measurement.
5. Run the six-cell Hello checkpoint periodically after coherent
   output-affecting batches, not after every metadata-only edit.
6. Pay the 419-pair byte-identity sweep and broader repository gates once per
   coherent WP3 migration batch before claiming the corresponding exit
   criterion.
7. Remove `tag_phys` only after the audit proves no remaining typed consumer
   depends on its spelling. Do not replace it with another display-name parser.

The next promising audit surfaces are the remaining identity-optional call,
frame, float-bank, memory-object, and variable-address helpers. Several already
use identity-aware production branches and spelling-only compatibility
branches; do not rewrite those merely to reduce a grep count. The next change
must demonstrate a production semantic decision that still ignores available
identity evidence.

## Workspace handoff

At this handoff, `master` and `origin/master` both point to `3bc525f5`. The main
checkout contains concurrent uncommitted work under `src/csource/`,
`src/syntax/`, `src/python_bindings/source_metrics.rs`, `src/lib.rs`, and
`src/ir/stack_locals/indexed_objects.rs`. Those paths were neither staged nor
modified by this lane. Re-check ownership and status before the next commit.
