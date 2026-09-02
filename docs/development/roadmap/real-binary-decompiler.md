# Real-binary decompiler roadmap

> **Kind:** plan · **Status:** proposed

This plan joins three previously separate bodies of evidence:

* the generated [test inventory](../../test-inventory/README.md) and
  [test-estate plan](../test-estate/README.md);
* the [three-way parity backlog](../decompiler-parity-backlog.md); and
* the pinned [full-run failure taxonomy](../../history/design/campaigns/decbench-full-failure-taxonomy-2026-08-31.md).

It gives them one product-facing order: make Glaurung's strong deterministic
optimized-code result survive the ugly tail of production and hostile
binaries.

The navigable R0–R7/M1–M7 evidence and plan map is the
[roadmap planning package](README.md).

## Progress

F1a, the F1b product-side distinction (`0d6b30d1`) and F2a (`0031c3ee`)
landed; the readability census reached 3,580 GCC/Clang O0/O2 rows
(`1329382d`); the performance gate now fails closed and is scheduled
(`4f4f88e3`); determinism canaries, nightly fuzzing, and several thin-module
ratchets landed. R4 gained four hermetic lanes — PE entry/TLS/import
(`99113bc8`), clang-cl PE32/PE32+ identity (`8c0a89f6`), PDB type/layout
(`c7200d2d`), Mach-O x86-64/ARM64 thin (`ba2fe5c2`) — each of which found a
real defect in the code it was pointed at. Go fixture lanes are wired but
**opt-in** behind `GLAURUNG_FIXTURE_GO` (`6660f1f7`); their manifest entries
and four baseline refreshes are still outstanding.

These are substrate advances, not milestone exits: F1c/F1d, large-function
telemetry, lane-keyed structural semantics, the rest of the format matrix,
hostile semantic oracles, and a provenance-complete release report remain
open.

## Evidence boundary

The full run proves excellent DecBench-relative results on optimized and
inlined functions. It does not prove malware superiority, robustness against
packing or obfuscation, or parity across PE and Mach-O. DecBench identifies
classes and measures releases; it is never a source of committed fixtures.

## North-star contract

For a supported, unpacked native binary, Glaurung should deterministically:

1. account for every requested function by immutable address;
2. return a body or a structured, phase-specific refusal;
3. preserve control and data dependencies important to an analyst;
4. produce recompilable C where the target ABI permits it;
5. remain bounded on large and adversarial functions; and
6. reproduce the result without a network or model call.

Pretty output is subordinate to semantic fidelity, but structural quality is
measured rather than waived.

## Workstreams and order

### R0 — Measurement integrity and inventory authority

Why first: an unreachable test or stale generated table cannot guard later
work.

Deliverables:

* regenerate `index.json`, `index.yaml`, `unreachable.json`, `coverage.md`, and
  summary counts atomically;
* add `tools/build_test_inventory.py --check` and a CI stale-artifact test;
* extend inventory entries with oracle, format, architecture, compiler,
  optimization, stripped/packed/obfuscated flags, language, size class,
  real-world/construct class, provenance hash, license, last runner, runtime
  class, and ground-truth strength;
* finish the reachability plan to zero unexplained unreachable items.

Acceptance: the inventory alone answers “how many reachable, source-grounded
PE O2 functions run automatically?”

The missing canonical inputs, schema-v2 migration, atomic renderer, `--check`
contract, structured reachability, and roadmap queries are specified in the
[inventory-authority plan](test-inventory-authority.md).

### R1 — Missing-body identity and recovery

Why now: the full run found 217 missing bodies, but 186 are pre-decompiler
identity failures and 31 are ARM body-recovery failures.

The implementation order, with current status, is:

1. **landed:** i386 stdcall decoration fixture and collision-safe normalization
   (proven cause of 33 F1 rows);
2. ARM32 Cortex-M `MRS`/`MSR` fixture and lift semantics for `BASEPRI`,
   `BASEPRI_MAX`, `IPSR`, and `PSP` (proven cause of all 31 F2 rows);
3. **core landed; scoring contract open:** explicit external/import
   disposition for 63 F1b rows;
4. dataset consistency disposition for 88 manifest-only F1c rows;
5. source/build provenance trace for the two gzip F1d rows;
6. broader PE entry/TLS/import fixture;
7. ARM veneer and ELF alias fixtures;
8. missing-body ratchet.

Full acceptance is specified in the
[failure taxonomy](../../history/design/campaigns/decbench-full-failure-taxonomy-2026-08-31.md).
The TDD sequence, schemas, focused commands, and stop conditions are in the
[failure remediation plan](decbench-failure-remediation.md).
Do not call this lane complete because the aggregate remains 99.77%; completion
is zero unexplained rows.

### R2 — Large-function boundedness and quality

Why second: DecBench `large` absolute perfection is near zero even where the
relative rank is favorable. This is the largest demonstrated quality hole.

Add a new `@large` corpus with three tiers:

* generated source compiled by real toolchains: 250/1,000-case switches,
  nested loops, cleanup ladders, computed state machines, and large expression
  DAGs;
* permissively licensed production functions: parsers, dispatchers, protocol
  state machines, and command interpreters, pinned to source commits;
* adversarial but valid functions: irreducible regions, dense indirect
  branches, alias-heavy memory, and unusually high phi pressure.

Record input bytes, blocks, edges, cyclomatic complexity, indirect branches,
phase timings, peak RSS, MIR/SSA high-water marks, output bytes, recovered
blocks/edges, undefined reads, structural predicates, compile/execution
verdicts, and terminal phase/refusal.

Ratchets:

* no panic or unbounded allocation;
* timeout is explicit and phase-attributed;
* no silent block loss;
* no >25% instruction or >50% RSS regression without an accepted reason;
* no compile, execution, or structural regression.

The measured size curve, telemetry schema, 18-function generated ladder,
production-shape requirements, and phase taxonomy are specified in the
[large-function plan](large-functions.md).

### R3 — O2/inlined structural quality

Why third: optimized semantics are a strength, while perfect GED remains only
about one third. Preserve correctness while making output source-like.

Execute test-estate Phase 7.5 for GCC and Clang O2, then add loop-kind and
goto-free predicates for inlined shapes; condition complexity, duplicate
condition, cast, temporary, and expression-depth metrics; a structured diff
against source CFG; and the page-align/symbol-snapping guard.

Then implement parity work in this order:

1. inlined-body register threading;
2. variadic/call-site argument arity;
3. real pointer/array C rendering;
4. cross-call type propagation and aggregate field recovery.

Each transform lands behind an execution-differential fixture first. The
comparison-fusion regression proved that readability transforms are semantic.

The current structural-baseline audit, four-lane schema, optimized-shape
corpus, readability metrics, fix order, large-function bridge, and acceptance
ratchets are specified in the
[optimized structural-quality plan](optimized-structural-quality.md).

### R4 — PE/PDB and Mach-O parity

Why fourth: 171/217 missing bodies are PE identity rows, while the fixture
estate lacks hermetic parity with ELF.

Promote test-estate Phase 4 ahead of Go and asset deduplication:

1. clang-cl/lld-link PE32 and PE32+ lanes at O0/O2 with PDB/linker-map oracles;
2. real MSVC fixture fetch/cache only for producer-specific behavior;
3. PE TLS, SEH, imports, exports, delay imports, forwarded exports, overlays,
   and worker-thread entry procedures;
4. Zig Mach-O x86-64/ARM64 lanes, stubs/chained fixups, and universal binaries.

PE cells must distinguish imports, thunks, aliases, and real bodies. A body for
an import name is not automatically success.

The live asset/toolchain audit, shared oracle stack, minimal PE identity lane,
hermetic PDB types, fetched-MSVC rescope, thin/fat Mach-O matrix, and completion
ratchets are specified in the
[PE/PDB and Mach-O parity plan](pe-pdb-macho-parity.md).

### R5 — Controlled real-world and malware-shaped assets

Build matched families, not an uncurated malware zoo:

* debug, release, stripped O0, stripped O2, O3, and one LTO build;
* glibc and musl; GCC, Clang, clang-cl/MSVC; x86-64 and ARM64;
* original, packed, and unpacked pairs;
* benign reference and source-modified suspicious behavior;
* controlled flattening, opaque predicates, import hashing, indirect dispatch,
  anti-debug calls, TLS callbacks, self-address/page masks, encrypted embedded
  payloads, and malformed-but-loadable sections.

Every asset needs source revision, build-container digest, command line,
SHA-256, license/redistribution status, and oracle. Preserve page masks,
syscall requests, suspicious constants, and data dependencies as explicit
predicates. Source-available demonstrations are preferable to opaque malware
because they provide truth and safe redistribution.

The current asset audit, safe corpus boundary, eight-layer oracle contract,
canonical provenance schema, and phased ELF/PE/ARM implementation are in the
[real-world asset plan](real-world-malware-assets.md). Its first
decision is to deepen `tests/realistic_corpus/`, not replace it.

### R6 — Performance ratchet

The pinned full decompile took 213.1 seconds for 803 binaries, so performance
is a strength. Protect it rather than making speculative core optimizations.

An instruction-count tool is now invoked by the local gate, but it has no
committed baseline and currently exits successfully when the baseline or a
comparable measurement is missing. Complete test-estate Phase 6 fail-closed,
then extend its reference ladder with an ordinary executable, large binary,
pathological `@large` function, dense state machine, and PE import/TLS fixture.
Use proven release builds. Gate instructions, wall time, max RSS, output size,
body/refusal completeness, and deterministic digests together. Keep upstream
DecBench site-generation time outside the product gate.

The current-tool audit, typed measurement states, provenance schema, reference
ladder, determinism matrix, TDD sequence, and completion evidence are in the
[performance/determinism plan](performance-determinism-ratchet.md).

### R7 — Matrix breadth and thin native modules

After R0–R6 are guarded:

* wire the existing Go fixtures;
* add stripped O0, LTO, and musl one lane at a time;
* build corpus-driven demangle, similarity, FLIRT, and target suites;
* run committed fuzz seeds through disassembly, lifting, CFG, structuring, PE,
  and Mach-O parsers nightly.

These remain valuable, but should not displace demonstrated missing-body,
large-function, PE, or O2 structural work.

## Milestones

| milestone | exit evidence |
|---|---|
| M1 — trustworthy estate | Atomic inventory current; zero unexplained unreachable entries; CI runs intended gates. |
| M2 — complete accounting | Every requested function returns a body or structured reason; all 217 pinned rows have proven dispositions and independent fixtures. |
| M3 — bounded large functions | `@large` has phase/resource/quality ratchets and no unexplained body loss. |
| M4 — optimized readability | GCC/Clang O2 structural ratchets run; priority parity defects fixed without execution regressions. |
| M5 — format parity | Hermetic PE/PDB and Mach-O lanes cover identity, body recovery, types, and structure. |
| M6 — real-world confidence | Matched production and malware-shaped families run with provenance and signal-preservation predicates. |
| M7 — release gate | Performance, determinism, failure taxonomy, fixture matrices, and held-out evaluation produce one pinned internal report. |

## Carried from the 2026-08-13 roadmap

The roadmap that preceded this plan set is archived as
[`history/design/decompiler-roadmap-2026-08-13.md`](../../history/design/decompiler-roadmap-2026-08-13.md).
Its structure was sound and its contents fell about four hundred commits
behind; its meta-guidance is now in [`README.md`](README.md) and its file-size
program in [`development/testing-gates.md`](../testing-gates.md). What follows
is every item of it that was still genuinely open when it was archived,
re-checked against the tree on 2026-09-02. Each line names the check that
proves it and links the original statement.

* **The physical decomposition it planned never happened.** `src/ir/hir/`,
  `src/lift/`, `src/ir/lifted/` and `src/render/` do not exist (`ls` each). Any
  future ownership map has to be written against `src/ir/` as it is.
  ([foundations](../../history/design/decompiler-roadmap-2026-08-13.md#foundations-still-incomplete))
* **`FunctionFacts` / `CallFactStore` is unbuilt.**
  `rg 'FunctionFacts|CallFactStore' src/` returns nothing. It was the most
  duplicated open item in the old plan and it has one design, kept live at
  [`design/function-facts-and-call-facts.md`](../../design/function-facts-and-call-facts.md),
  whose §6 records the measurement that rules out founding it on the existing
  `CallGraph`.
  ([EPIC 1](../../history/design/decompiler-roadmap-2026-08-13.md#epic-1--program-level-symbol-and-type-environment))
* **Verified MIR is built but has no consumer.** The old blocker — "MIR is not
  built on a production decompile" — is gone: `PreparedLlir::mir()` lives at
  `src/python_bindings/ir/pipeline.rs:402` and is reachable for every
  decompilation. The item that remains is the one behind it: its only caller
  is a `#[cfg(test)]` assertion, `DefinitionOracle` appears only under
  `src/ir/mir/`, and none of the seven named definition-sensitive consumers has
  migrated. Four AST-level substitutes (`copy_prop`, `expr_reconstruct`,
  `stack_locals`, `structured_reaching`) still carry the load and say so in
  their own doc comments.
  ([foundations](../../history/design/decompiler-roadmap-2026-08-13.md#foundations-still-incomplete))
* **The aggregate/object model still runs on the AST-era adapter.**
  `src/ir/memory_objects/ast.rs::infer_from_ast` is the only object-model
  producer with a production caller (`src/ir/high_variables.rs:36`);
  `shape.rs` and `partition.rs` exist on the MIR side with nothing in the
  render path reading them.
  ([EPIC 3](../../history/design/decompiler-roadmap-2026-08-13.md#epic-3--aggregate-and-memory-object-recovery))
* **The canonical type store is still write-only.**
  `ProgramEnvironment::types()` (`src/program/environment.rs:59`) has no
  production reader, PDB facts go to a Python SQLite table and to AST string
  hints in `src/ir/pdb_fields.rs`, and inferred types live in
  `types_recover.rs`'s own lattice. The first step is a reader path, not
  another writer.
  ([foundations](../../history/design/decompiler-roadmap-2026-08-13.md#foundations-still-incomplete))
* **Rendering is not a pure projection.**
  `render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types`
  (`src/ir/ast/decbench_render.rs:130`) is the production entry, ten `DEC_*`
  thread-local cells remain in `src/ir/ast.rs`, and `remap_type_map`
  (`src/python_bindings/ir/type_maps.rs:56`) is still live. Two of the analyses
  it calls run *after* the verification boundary, so the thing verified is not
  the thing rendered.
  ([HIR and rendering](../../history/design/decompiler-roadmap-2026-08-13.md#semantic-hir-and-pure-rendering))
* **Typed completeness does not travel through every stage.** The sharp end is
  that the batch entry points drop `LiftError` rather than recording it, so a
  function that failed to lift is indistinguishable from one that does not
  exist. R1's missing-body accounting is the same defect measured from the
  outside.
  ([foundations](../../history/design/decompiler-roadmap-2026-08-13.md#foundations-still-incomplete))
* **`ProgramSession` is not yet the sole owner of every parse.** Object parses
  per session were bounded to a constant (19 for `decompile_at`, 20 for
  `decompile_all`) rather than reduced to one; reaching one needs a
  relocation/symbol index on `ProgramImage`.
  ([foundations](../../history/design/decompiler-roadmap-2026-08-13.md#foundations-still-incomplete))
* **The ARM32 machine model is still incomplete**, though less so than when
  the list was written: RRX and register-shifted-register are handled
  (`src/ir/lift_arm32/shifts.rs`) and Cortex-M system registers landed with
  F2a. NEON has no ARM32 lifting at all (`rg -li neon src/ir/lift_arm32*`
  finds nothing), and VFP s/d/q register overlap, `d0`–`d7` argument slots and
  64-bit integer argument pairing remain unmodelled. ARM32 is a conformance
  architecture here, not an optional afterthought.
  ([EPIC 4](../../history/design/decompiler-roadmap-2026-08-13.md#epic-4--architecture-parametric-machine-model))
* **The fourteen non-negotiable design rules stand**, and are the part of the
  old document most worth re-reading before a structural change — in
  particular rule 8 (a failed proof keeps an honest goto, it does not guess),
  rule 12 (serial and parallel analysis must produce identical facts), and
  rule 14 (a split counts only if it creates a narrower API and one reason to
  change).
  ([design rules](../../history/design/decompiler-roadmap-2026-08-13.md#non-negotiable-design-rules))

Three further open items from the old plan live elsewhere now rather than
here: its file-size and ownership targets are the measured program in
[`development/testing-gates.md`](../testing-gates.md); its DecBench and
evaluation appendix is [`README.md`'s on-demand section](README.md#decbench-evaluation-on-demand-only);
and the unimplemented ideas it pointed at — goto sinking, the two dormant loop
passes, and the stack-bias affine index — are in
[`design/open-questions.md`](../../design/open-questions.md).

## Explicit non-goals

* Do not add LLM inference to improve a deterministic benchmark column.
* Do not copy DecBench bodies into committed fixtures.
* Do not optimize exact byte match at the expense of semantic fidelity.
* Do not call favorable rank on a weak absolute metric evidence of solved
  quality.
* Do not treat packed/self-modifying code as ordinary native code; identify and
  refuse it precisely until an unpacking layer exists.

## Immediate increments

Landed since the original list: the collision-safe i386 stdcall fixture and
resolver, the import-versus-absent product distinction, the Cortex-M decode
and `MRS`/`MSR` lift with its body-recovery fixture, the four-lane readability
census, four hermetic PE/PDB/Mach-O lanes, and a perf gate that fails closed.
Next:

1. Complete the scoring/dataset external/import contract for the 63 F1b rows.
2. Add a manifest/source-CFG/binary-identity consistency validator for the 88
   F1c rows.
3. Trace gzip `__printf__` source/build provenance for the two F1d rows.
4. Specify and land the smallest `@large` generated tier with phase telemetry.
5. Make inventory generation atomic and add `--check`.
6. Promote `tests/realistic_corpus/` from discovery-only evidence to classified
   body accounting plus a small compile/execution and signal-preservation set.
7. Replace the initial perf baseline with a provenance-complete release
   baseline joined to completeness, RSS, output, and determinism evidence.
8. Add the Mach-O universal (fat) slice lane; the thin lanes are the template.

Each increment updates the diary, the relevant checkbox, and the inventory
entry naming its actual runner.
