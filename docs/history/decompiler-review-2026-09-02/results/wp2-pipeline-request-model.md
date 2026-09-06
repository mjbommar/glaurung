# WP2 pipeline-owned request model

Date: 2026-09-06

Behavioral commits: `d6a65779`, `5a2d6c86`, `e19bd73b`, `41bd90a6`,
`73a79d61`, `5ea45dca`, `15d044eb`, `e0588083`, `21f8b29a`, `2ef9c4eb`,
`d900cf1b`

## Boundary moved

The module-level and reusable-session `decompile_at` adapters previously
passed eleven positional orchestration arguments into a function still owned
by `ir.rs`. They now construct one pipeline-owned `DecompileRequest` carrying:

- the normalized function-address request;
- an `AnalysisBudget` with function, block, instruction, per-function time,
  and whole-analysis time limits; and
- `RenderOptions` for style, typing, debug data, and analyst overlays.

`AnalysisBudget::discovery` is the single conversion to CFG discovery limits.
This prevents these two adapters from silently dropping a limit while the
remaining entry points migrate.

## Deliberate boundary

This is an incremental WP2 production series, not completion. All four adapters
now construct typed requests/results, share callee preparation and LLIR-to-AST
lowering, and consume one image-wide render-context builder. Discovery/debug
assembly, declaration-local merging, and final rendering remain adapter-owned.
Checked pass stages, the bounded fixpoint driver, the remaining explicit budget
classes, and a structured public Python projection also remain open. No new
public Python API or output format is claimed.

## Exact-range convergence

The first full-text four-entry-point differential exposed a real semantic
split. For the exact 38-byte `08_indirect_dispatch::tail_dispatch` range,
address, many, and all emitted the same structured switch and preserved two
indirect-call arguments. Range synthesized one basic block, discarded the CFG,
used empty direct-callee facts, and emitted a zero-argument indirect call.

`5a2d6c86` makes a range request reuse ordinary discovered CFG and callee facts
only when every discovered block fits inside the caller's exact range. An
undiscovered or out-of-range function retains the old explicit-window fallback;
the API does not silently expand beyond the caller's bound. All four public
paths now emit the same 759-byte pseudocode for the pinned case.

The same commit routes range/all/many discovery through the pipeline-owned
`AnalysisBudget` conversion. It does not yet make those three adapters construct
`DecompileRequest`, and their remaining per-function orchestration is still
duplicated.

## Shared callee preparation

`e19bd73b` removes another independently repeated orchestration sequence from
all four entry points. `callee_contracts.rs::prepare_direct_callee_facts` now
owns this exact order:

1. expand compiler soft helpers while argument registers are architectural;
2. attach ABI and known-call effects before SSA;
3. recover bounded direct-callee layouts and prototypes; and
4. apply those recovered effects to the caller before its own recovery.

Address, exact range, all, and many call this boundary instead of importing and
sequencing its component passes themselves. This completes the plan's shared
callee-preparation item. It does not complete the common per-function
orchestrator: discovery/context assembly, declaration selection, and rendering
are still repeated in `ir.rs` at this point in the history.

## One LLIR-to-AST stage

`41bd90a6` adds pipeline-owned `PreparedAst` and
`lower_and_run_ast_passes`. Every public adapter now hands its `PreparedLlir`
to that one function, which owns:

- direct-callee pass-through parameter refinement;
- region lowering and function profiling;
- landing-pad annotation and lower-stage health tracing; and
- the complete shared AST pass invocation and its returned stack/role facts.

This removes four independently sequenced copies from `ir.rs`. It also closes
a real range-path drift: range did not previously refine pass-through parameter
hints, while address, all, and many did. The pinned four-entry-point fixture
remains byte-identical after making the refinement universal.

The boundary deliberately returns the numbered LLIR, prototype, width map,
stack facts, and profiler beside the AST so a renderer cannot accidentally use
facts from another function. Context/discovery assembly, declaration-local
merging, and rendering still live in the adapters; therefore the planned
pipeline-owned `decompile_function(session, request)` and all-entry-point result
migration are not yet complete.

## Structured result and fingerprint

`5ea45dca` adds the result half of the typed boundary for module-level and
reusable-session single-function decompilation. Their legacy Python methods
still project a string, but internally receive one `DecompileResult` carrying:

- pseudocode;
- final, renderer-independent `AstHealth`;
- explicit completeness plus the exact discovery-budget names that fired;
- the declaration/analyst provenance that influenced the result; and
- `PipelineFingerprint`, including schema, explicit pass-set version, every
  `AnalysisBudget` field, style/type/debug selectors, and analyst-overlay
  presence.

Unit tests prove that a budget change changes fingerprint identity and that
completeness reports the exact fired limit. A structured Python projection
remains open, so this is not yet the complete public WP2 result surface.

`15d044eb` completes the internal adapter migration: exact range, all, and many
now construct the same `DecompileRequest`, including the shadow-v2 selector,
and create `DecompileResult` from the final rendered AST before projecting their
existing string/tuple APIs. Thus every path computes health, exact completeness,
provenance, and the same versioned fingerprint. This does not yet centralize the
context assembly or renderer itself; those remain the boundary required to turn
the adapters into thin shells over one `decompile_function`.

## Program render context

`e0588083` removes four copies of the immutable image-wide render setup.
`pipeline.rs::prepare_program_render_context` is now the sole constructor for:

- data-symbol/string-pool reconciliation;
- relocation-aware read-only data;
- function-pointer tables; and
- ELF GOT target facts.

Every adapter consumes the resulting `ProgramRenderContext`. All/many prepare
it once outside their per-function loops, preserving the batch performance
contract. This is deliberately narrower than the final `decompile_function`
boundary: discovery and address-name construction, per-function declaration
facts, and final rendering still remain to migrate.

`21f8b29a` then removes the other four image-wide setup copies.
`prepare_program_debug_context` now owns optional DWARF/PDB declaration loading,
PDB-source identity, and the combined DWARF/PDB type records. Its disabled path
returns explicit empty facts without parsing debug data. The borrowed
`DwarfTypeEnv` remains a caller-local view over the context's owned records,
avoiding a self-referential context while keeping the preparation policy in one
place. Each adapter retains its exact prior enablement condition, including the
declaration-only DecBench batch mode.

`2ef9c4eb` centralizes the remaining binary-truth name/data preparation.
`prepare_program_name_context` now owns the combined object parse and the
ordered enrichment with discovered names, FLIRT-referenced names, and ordinary
referenced-function names. It returns the address-name map and data symbols as
one `ProgramNameContext`; analyst overlays remain intentionally later because
semantic callee/environment queries must use binary truth. The four adapters no
longer hold raw image-byte locals or independently sequence these name sources.
The profile ceiling remains 20 parses across the tested language/toolchain
samples.

`d900cf1b` centralizes discovery itself. `discover_program` performs the sole
`AnalysisBudget` conversion, releases the GIL around the session query, and
returns `ProgramDiscovery { budgets, functions }` so downstream context cannot
silently use different limits from those that produced the function set. All
four adapters use this boundary with their existing seed sets. Adding the
injected `Python` token to exact-range is not a public argument change; it makes
that previously blocking discovery path interruptible and consistent with
address/all/many.

The expanded profile test initially exposed 21 constant object parses against
the ceiling of 20. An exact parent/current A/B proved the result model added
none. Call-site instrumentation then located the duplicate: the combined
symbol/data collector held an `object::File` but reparsed the bytes to recover
GOT names. `73a79d61` adds parsed-object GOT extraction and reuses that object,
restoring 20 parses across GCC C, Clang C, Go, Rust, and both discovery limits
without changing the ceiling.

Commit `1e1ac0a8` moves the final semantic preparation of `PreparedAst` behind
one pipeline-owned `finalize_prepared_ast` boundary. Address, exact-range, all,
and many now apply analyst frame facts, DWARF register-local facts, DecBench
exception recovery, machine-frame cleanup, and PDB field annotations in the
same ordered implementation. The adapters retain only their distinct public
return shapes and rendering policies; centralizing those render policies is the
next WP2 boundary.

Commit `2f7a6149` closes that next boundary. One pipeline-owned
`render_prepared_ast` now selects analyst/debug declaration authority, projects
DecBench and plain type maps, records declaration conflicts, selects all output
styles, carries provenance, and prefixes per-function incompleteness. All four
adapters call it and retain only their public Python container/variable
projection. The entry-point differential now covers DecBench, C, and untyped
styles rather than one render mode.

Commit `2ee8fa15` closes the outer orchestration boundary. One pipeline-owned
`decompile_function` now owns the entire per-function transaction: lift,
direct-callee facts, analyst-name overlay, typed and shadow LLIR preparation,
shadow selection, stack hints, lowering and AST passes, finalization, and
rendering. Address, exact-range, all, and many are adapters over that same
transaction and no longer independently perform per-function discovery,
naming, callee analysis, lowering, finalization, or rendering. This completes
the shared production path, not WP2: the additional explicit budget classes,
checked pass preconditions/order, bounded fixpoint reporting, and exact budget
closure tests remain.

Commit `74853fcc` begins the checked-order half without changing the pass list
or rendered output. `PipelineStageTracker` now requires and records the coarse
production transitions from start through lift, callee facts, LLIR
preparation, AST preparation, finalization, and rendering. A focused negative
test attempts to render from the Lifted stage and proves the transition fails
with its expected and actual stages while preserving the current state. This
is not the completed pass manager: the individual operations inside
`run_ast_passes` still need declared preconditions, and repeated passes still
need the bounded fixpoint driver and firing/termination report.

## Validation

- Pipeline budget field-preservation unit: passed.
- `python/tests/test_decompiler_session.py`: three passed, including exact
  equality between module-level and reusable-session output.
- Release extension rebuild: passed.
- `cargo test --features python-ext`: 4,201 library tests passed, zero failed,
  five ignored; all integration and documentation targets passed. The long
  identity-retrieval target reports 44 passed and ten ignored.
- `python/tests/test_decompiler_entrypoint_equivalence.py`: one full-text
  four-entry-point differential passed.
- Declaration authority, PDB type recovery, session reuse, entry-point
  equivalence, and the stripped forwarded-parameter regression focused set:
  23 passed after a fresh release extension build at `e19bd73b`.
- Full `cargo test --features python-ext` at `e19bd73b`: 4,201 library tests
  passed, zero failed, five ignored; every integration and documentation target
  passed. The long identity-retrieval target reports 44 passed and ten ignored
  in 522.46 seconds.
- Fresh release extension plus the same 23-test focused set at `41bd90a6`:
  passed, including byte-identical output across address, range, all, and many.
- Full `cargo test --features python-ext` at `41bd90a6`: 4,201 library tests
  passed, zero failed, five ignored; every integration and documentation target
  passed. The identity-retrieval target reports 44 passed and ten ignored in
  524.96 seconds.
- Fresh release extension plus pipeline profile, entry-point equivalence,
  declaration, PDB, session, and determinism tests at `5ea45dca`: 36 passed.
  The whole-program parse count is 20 for all four language/toolchain samples
  and for both tested discovery limits.
- Full `cargo test --features python-ext` at `5ea45dca`: 4,203 library tests
  passed, zero failed, five ignored; every integration and documentation target
  passed. The identity-retrieval target reports 44 passed and ten ignored in
  524.99 seconds.
- Fresh release extension plus entry-point equivalence, declaration, PDB,
  session, determinism, pipeline-profile, and stripped-callee tests at
  `15d044eb`: 37 passed.
- Full `cargo test --features python-ext` at `15d044eb`: every enabled test
  passed. The shared checkout contained 4,208 library tests at execution time,
  including five concurrent-lane declarations outside this commit; five were
  ignored. Identity retrieval reports 44 passed and ten ignored in 523.30
  seconds, and every integration/documentation target passed.
- Fresh release extension plus the same entry-point, declaration, PDB, session,
  determinism, pipeline-profile, and stripped-callee set at `e0588083`: 37
  passed.
- Full `cargo test --features python-ext` at `e0588083`: 4,203 library tests
  passed, zero failed, and five ignored; every integration and documentation
  target passed. Identity retrieval reports 44 passed and ten ignored in
  524.91 seconds.
- Fresh release extension plus the same 37 focused checks at `21f8b29a`:
  passed.
- Full `cargo test --features python-ext` at `21f8b29a`: 4,203 library tests
  passed, zero failed, and five ignored; every integration and documentation
  target passed. Identity retrieval reports 44 passed and ten ignored in
  526.66 seconds.
- Fresh release extension plus the same 37 focused checks at `2ef9c4eb`:
  passed, including full-text entry-point equivalence and the object-parse
  ceiling.
- Full `cargo test --features python-ext` at `2ef9c4eb`: 4,203 library tests
  passed, zero failed, and five ignored; every integration and documentation
  target passed. Identity retrieval reports 44 passed and ten ignored in
  528.62 seconds.
- Fresh release extension plus the same 37 focused checks at `d900cf1b`:
  passed.
- Full `cargo test --features python-ext` at `d900cf1b`: 4,203 library tests
  passed, zero failed, and five ignored; every integration and documentation
  target passed. Identity retrieval reports 44 passed and ten ignored in
  526.49 seconds.
- Fresh release extension plus the same 37 focused checks at `1e1ac0a8`:
  passed, including full-text four-entry-point equivalence.
- Full `cargo test --features python-ext` from a clean detached worktree at
  exact commit `1e1ac0a8`: 4,203 library tests passed, zero failed, and five
  ignored; every integration and documentation target passed. Identity
  retrieval reports 44 passed and ten ignored.
- Fresh release extension plus the expanded 39 focused checks at `2f7a6149`:
  passed. The entry-point differential passes three render styles across all
  four public paths, and the test-census guard also passes.
- Full `cargo test --features python-ext` from a clean detached worktree at
  exact commit `2f7a6149`: 4,203 library tests passed, zero failed, and five
  ignored; every integration and documentation target passed. Identity
  retrieval reports 44 passed and ten ignored.
- Fresh release extension plus 55 focused pipeline, entry-point, declaration,
  PDB, session, determinism, profile, render-style, and stripped-parameter
  checks at `2ee8fa15`: all passed.
- Full `cargo test --features python-ext` from a clean detached worktree at
  exact commit `2ee8fa15`: exit zero; 4,203 library tests passed, zero failed,
  and five ignored; every integration and documentation target passed.
  Identity retrieval reports 44 passed and ten ignored; doc tests report two
  passed and one ignored.
- Fresh release extension plus 36 entry-point-equivalence, session,
  determinism, pipeline-profile, and render-style checks at `74853fcc`: all
  passed.
- Full `cargo test --features python-ext` from a clean detached worktree at
  exact commit `74853fcc`: exit zero; 4,204 library tests passed, zero failed,
  and five ignored; every integration and documentation target passed.
  Identity retrieval reports 44 passed and ten ignored; doc tests report two
  passed and one ignored.
