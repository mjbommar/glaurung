# Real-binary decompiler roadmap — evidence update 2026-08-31

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

## Progress update — 2026-09-01

F1a and the F1b product-side distinction landed; the readability census
reached 3,580 GCC/Clang O0/O2 rows; and an initial performance baseline,
determinism canaries, nightly fuzzing, and several thin-module ratchets landed.
PE symbol/PDB/RSDS front-door defects were also repaired. These are substrate
advances, not milestone exits: F1c/F1d/F2a, large-function telemetry,
lane-keyed structural semantics, format matrices, hostile semantic oracles,
and a fail-closed provenance-complete release report remain open.

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
resolver, the import-versus-absent product distinction, the four-lane
readability census, and the initial instruction baseline. Next:

1. Add the Cortex-M MRS/MSR fixture before changing ARM32 lifting; the pinned
   data predicts all 31 F2 rows move or gain explicit refusal.
2. Complete the scoring/dataset external/import contract for the 63 F1b rows.
3. Add a manifest/source-CFG/binary-identity consistency validator for the 88
   F1c rows.
4. Trace gzip `__printf__` source/build provenance for the two F1d rows.
5. Specify and land the smallest `@large` generated tier with phase telemetry.
6. Make inventory generation atomic and add `--check`.
7. Promote `tests/realistic_corpus/` from discovery-only evidence to classified
   body accounting plus a small compile/execution and signal-preservation set.
8. Make `tools/perf_gate.py` fail closed, then replace the initial baseline with
   a provenance-complete release baseline joined to completeness, RSS, output,
   and determinism evidence.

Each increment updates the diary, the relevant checkbox, and the inventory
entry naming its actual runner.
