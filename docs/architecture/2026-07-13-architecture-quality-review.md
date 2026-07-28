# Glaurung architecture, quality, and efficiency review

- **Date:** 2026-07-13
- **Repository snapshot:** `cf97906`
- **Status:** Findings and recommendations, including the latest Android, Linux
  IOCTL, SELinux, and IOCTLance work; no production code changed by this review
- **Scope:** Rust core, PyO3 boundary, Python package, CLI, LLM/tool platform,
  persistent project database, test/type/lint gates, and representative end-to-end
  workflows

## Executive summary

Glaurung has unusually broad capability for a pre-alpha reverse-engineering
framework: a substantial safe-Rust analysis core, real binary fixtures, persistent
analyst state, decompilation, Windows and Java workflows, an execution engine, and
an extensive agent tool surface. The most important architectural problem is not a
missing feature. It is that these capabilities do not yet share one explicit,
long-lived runtime model.

Today, analysis is predominantly exposed as independent path/bytes functions,
project persistence is assembled by domain modules that each own schema fragments,
and the CLI and main agent construct most capabilities eagerly. The consequences are
repeated whole-binary work, expensive cold startup, scattered lifecycle policy,
weak invalidation semantics, difficult-to-test orchestration, and a widening gap
between runtime APIs and their static descriptions.

The recommended destination is:

1. a content-identified `AnalysisSession` owning bytes, parsed format state,
   analysis caches, budgets, and a project handle;
2. an explicit analysis-pass manager with typed inputs, outputs, dependencies,
   provenance, and invalidation;
3. one versioned repository layer for the `.glaurung` database;
4. lazy command and agent capability registries built from focused toolsets; and
5. architectural fitness gates covering imports, type contracts, schema migrations,
   budgets, and workflow performance.

These are mutually reinforcing changes. They should be delivered incrementally,
not as a rewrite.

## Priority model

Rankings combine five factors:

- **User impact:** latency, memory, correctness, recoverability, and analyst trust.
- **Architectural leverage:** how many later changes become simpler.
- **Evidence strength:** measured behavior outranks inference from file size.
- **Risk growth:** how quickly the problem worsens as formats, tools, and analyses
  are added.
- **Delivery shape:** preference for changes that can land behind compatibility
  facades with fixture-backed tests.

Priority labels mean:

- **P0:** start before expanding the affected subsystem further.
- **P1:** begin after the P0 foundations, or in parallel when it does not conflict.
- **P2:** important hardening and maintainability work.

## Review method

The review used three additional iterations after the initial top-down survey.

### Iteration 1: static architecture and ownership

The first pass mapped source size, import relationships, extension boundaries,
schema ownership, feature gates, exception handling, type/lint state, and documented
architecture promises.

Key observations:

- Python: 384 modules and approximately 154,469 lines.
- Rust: 216 modules and approximately 88,540 lines.
- Tests: 350 Python test files and 37 Rust integration-test files, in addition to
  Rust unit tests embedded in modules.
- One Python import-cycle component contains `glaurung.cli`, `cli.main`,
  `commands.explain`, and `commands._layer0_prepass`.
- `glaurung.llm.tools.windows_risk_report` imports a CLI implementation module,
  reversing the intended presentation-to-domain dependency direction.
- 31 files under `src/core/` still contain PyO3 `pyclass` or `pymethods`
  definitions. The no-default-feature Rust build nevertheless succeeds, so this is
  a source-boundary/testability concern rather than an immediate build failure.
- `memory_agent.py` has 202 direct tool-module import statements.
- SQLite DDL is distributed across 12 KB modules. `xref_db.py` alone invokes its
  idempotent `_ensure_schema()` from 42 call sites in addition to the function
  definition.
- The Python package currently has 384 broad `except Exception` or
  `except BaseException` handlers and 118 standalone `pass` statements. Many are
  deliberate best-effort boundaries, but they are not governed by one partial-result
  policy.
- Ruff reported 51 findings, including seven undefined-name findings and one bare
  exception. `ty` reported 279 diagnostics in the final pass: 165 unresolved
  attributes, 48 invalid argument types, 14 unknown arguments, 11 invalid
  assignments, and smaller categories. Native-extension visibility accounts for
  many unresolved attributes, but the invalid/unknown argument findings also expose
  API drift that should not be dismissed as stub noise.

### Iteration 2: measured runtime and storage behavior

Measurements used the checked-in extension, Python 3.14.3, pydantic-ai 2.9.0,
real checked-in binaries, `/usr/bin/time`, `importtime`, and SQLite inspection.
They are local engineering baselines, not universal performance claims.

| Operation | Wall time | Peak RSS | Notes |
|---|---:|---:|---|
| `import glaurung` | 0.10 s | 38 MB | Native/public base import |
| `import glaurung.cli.main` | 1.80 s | 249 MB | No command executed |
| import `memory_agent` | 1.70 s | 239 MB | No agent run |
| `glaurung --help` | 1.80 s | 249 MB | Parser construction only |
| real ELF `kickoff` (18 KB fixture) | 2.09 s | 255 MB | CLI report says analysis work completed in 392 ms |

Import inspection after `glaurung.cli.main` showed:

- 320 loaded Glaurung modules;
- 214 loaded `glaurung.llm.tools.*` modules;
- 18 loaded agent modules; and
- 2,042 total Python modules.

`importtime` attributed the chain primarily to `cli.commands.ask` ->
`llm.agents.factory` -> `llm.agents.memory_agent` -> pydantic-ai and its MCP/tool
dependencies. The gap between the 392 ms reported real ELF analysis and the 2.09 s
process time is a useful illustration: on small inputs, orchestration/import cost is
larger than analysis cost.

Repeated function discovery on the checked-in 3.9 MB Rust release fixture took a
median 76.0 ms through the path API and 75.3 ms through a bytes API that reused a
single Python-side read. Each repeated call took essentially the same time. This
does not prove that every analysis is expensive, but it demonstrates the absence of
cross-call result reuse. The existing `g.ir.decompile_many` source comment already
identifies the more severe form: calling `decompile_at` for N functions performs N
whole analyses, and the batch API was introduced to amortize that cost.

A real 1.4 MB checked-in Windows DLL kickoff did not complete within a 60-second
external limit. Before termination it had produced a 17 MB database containing
4,955 function names, 18,401 xrefs, 1,329 stack-frame variables, and 20,836 function
prototype rows. This is not a correctness failure by itself, and the fixture is a
substantive workload. It demonstrates why the composite workflow needs a shared
deadline, progress, checkpointing, and a clear partial-result contract.

The generated project also exposed database lifecycle costs:

- `PersistentKnowledgeBase.open()` is fast for this project because the generic
  node/edge tables are empty; most real data lives in specialized tables.
- The base object eagerly hydrates all generic nodes and edges via `fetchall()` when
  they are present, while specialized data is queried separately.
- `xref_db._ensure_schema()` executes DDL, two `PRAGMA table_info` scans, possible
  column migrations, and a commit from nearly every public xref/name operation.
- On the real project, 10,000 `get_function_name()` calls took approximately
  680 ms through the public API versus 23 ms for the equivalent prepared SQL lookup
  on the same connection: roughly a 29x difference in this microbenchmark. The
  absolute public cost is about 68 microseconds per call, but this is avoidable
  lifecycle work in a hot primitive.
- `PersistentKnowledgeBase.save()` says it writes the new diff but iterates every
  in-memory node and edge, issuing updates for already-persisted rows. Its cost is
  therefore proportional to the full generic working set, not only dirty records.

### Iteration 3: external architecture research

The recommendations were checked against current authoritative documentation:

- LLVM's [new pass manager](https://llvm.org/docs/NewPassManager.html) separates
  analysis managers by IR scope, computes analyses lazily, caches results, and
  requires transformations to declare preserved/invalidated analyses. Its warning
  about accidentally creating quadratic behavior by recomputing outer analyses from
  inner passes maps directly to repeated binary-wide discovery from function tools.
- MLIR's [pass infrastructure](https://mlir.llvm.org/docs/PassManagement/) similarly
  treats analyses as cached, non-mutating values with explicit dependency-aware
  invalidation. Glaurung does not need LLVM's complexity, but should adopt those
  lifecycle properties.
- PyPA documents [metadata entry points](https://packaging.python.org/en/latest/guides/creating-and-discovering-plugins/)
  as a standard plugin discovery mechanism. An internal registry should come first;
  entry points can later expose the same contract to third parties.
- Python documents `importlib.util.LazyLoader`, but explicitly warns that it can
  postpone errors out of context. Glaurung should therefore use explicit descriptor
  registries and local imports, not global transparent lazy importing. See the
  [importlib documentation](https://docs.python.org/3/library/importlib.html#importlib.util.LazyLoader).
- Current Pydantic AI [toolsets](https://pydantic.dev/docs/ai/tools-toolsets/toolsets/)
  are reusable, composable, dynamically constructed, and filterable. Its API also
  supports deferred loading. Glaurung's hand-built filtering should converge on
  focused toolsets while keeping its deterministic intent router.
- SQLite provides an application-owned
  [`user_version`](https://www.sqlite.org/pragma.html#pragma_user_version), explicit
  transaction semantics, and one-writer behavior. The application is responsible
  for ordered migrations and transaction scope; schema checks are not query-layer
  work. See SQLite's [transaction documentation](https://www.sqlite.org/lang_transaction.html).
- Cargo's [feature guidance](https://doc.rust-lang.org/cargo/reference/features.html)
  emphasizes additive features and explicit optional dependencies. Glaurung's
  existing Rust feature gates are a good foundation for capability profiles.
- `ty` requires `.pyi` descriptions for compiled extension APIs; this confirms that
  native-surface diagnostics should be addressed by generated/validated stubs, not
  blanket suppression. See the [ty typing FAQ](https://docs.astral.sh/ty/reference/typing-faq/).

### Latest-work integration review: `c9a56ee..cf97906`

The latest six commits add Android DEX/APK/AXML parsing, Android packed-relocation
and PAC/BTI analysis, dispatch-aware IOCTLance parity, Linux kernel-module IOCTL
surface recovery, symbolic-example feature gating, and the first SELinux policydb
parsing stage. The work is generally cohesive, fixture-backed, and careful about
bounds and incomplete semantic coverage. It should shape the architecture program,
not sit beside it as a separate pipeline.

| Area | Review | Integration into the plan |
|---|---|---|
| Android formats | Cohesive format modules, real fixtures, and reproducible fixture provenance | Use them to define a capability-graduation contract from parser to user-facing workflow |
| AArch64 PAC/BTI | Specific fixture-backed discovery support; also adds more architecture-specific policy to `analysis/cfg.rs` | Extract architecture discovery strategies when the pass/session substrate lands |
| Linux IOCTL surface | Useful typed Rust domain, but heuristics and empty-on-error behavior lose confidence and failure state | Produce a provenance-bearing `KernelIoctlSurface` artifact with coverage, diagnostics, and confidence |
| SELinux policydb | Correctly staged at the header rather than overstating an incomplete policy oracle | Finish and validate symbol, class/permission, type-attribute, avtab, conditional, and MLS semantics before reachability affects severity |
| IOCTLance parity | Valuable real-corpus regression harness with dispatch-aware comparison | Replace human-output regex/`eval` parsing with a versioned JSON result artifact before making it a gate |
| Cargo gating | `required-features = ["symbolic"]` correctly gates the symbolic examples | Include examples and format modules in the supported feature/profile matrix |
| Integration gates | Focused new tests and builds pass; repository-wide formatting and two existing Rust tests do not | Add a stabilization phase before extending this vertical |

The strongest architectural opportunity is a concrete cross-artifact pilot:

```text
AndroidPackageFacts
        |
        +--> NativeLibraryFacts
                  |
                  +--> UserlandIoctlUse ------------------------+
                                                               |
KernelModuleFacts --> KernelIoctlSurface --> SymbolicSinkFinding+--> CorrelatedExposureFinding
                                                               |
SELinuxPolicyFacts --> SePolicyReachability --------------------+
```

Every artifact should carry source identity, producer/version, option fingerprint,
coverage, status, diagnostics, resource use, and evidence references. This pilot
exercises format parsing, architecture-aware discovery, policy semantics, symbolic
analysis, correlation, partial outcomes, and persistence without inventing a
synthetic architecture example.

## Architectural strengths to preserve

The findings should not obscure the sound foundations already present.

1. **The Rust core can build without default features.** `cargo check
   --no-default-features` succeeded. PyO3 is optional and execution/symbolic/solver
   capabilities already have feature gates.
2. **The base import is lean.** `import glaurung` was only 0.10 seconds and 38 MB;
   the cold-start problem is localized to CLI/agent composition rather than the
   native package itself.
3. **Budgets already exist at important low levels.** Triage I/O and function
   discovery accept byte, function, block, instruction, and timeout caps. The missing
   part is propagation through composite workflows.
4. **Batching has started.** `decompile_many` is a direct response to repeated
   analysis. It is evidence for the session design, not throwaway work.
5. **The persistent project uses WAL and enables foreign keys on application
   connections.** The issue is centralized ownership and migration semantics, not a
   need to replace SQLite.
6. **The repository includes real corpora and integration tests.** This makes it
   practical to test each architectural migration against representative ELF, PE,
   Mach-O, Java, packed, adversarial, and Windows-driver inputs.
7. **The execution engine has a particularly coherent design record.** Its explicit
   phases, feature boundaries, differential oracle, and benchmarks are a useful
   model for other subsystems.

## Ranked findings and recommendations

### Rank 1 — P0: introduce an `AnalysisSession` and analysis-result manager

**Finding.** File identity, bytes, format parsing, function discovery, name maps,
string pools, disassembly, LLIR, CFG, and decompiler intermediates are owned by
individual operations. Batch APIs solve specific repeated-work cases but do not
provide a general lifecycle or invalidation model.

**Why this ranks first.** It addresses the largest cross-cutting performance issue
and creates the context needed by pass scheduling, tool routing, budgets,
observability, and persistent caching.

**Recommendation.** Add a Rust-owned `AnalysisSession` (with a thin Python wrapper)
that contains:

- immutable binary identity: canonical path when available, size, mtime, and a
  content hash;
- one bounded read or memory mapping and parsed container/architecture state;
- typed analysis-result keys such as `(artifact_hash, analysis_kind, options_hash,
  engine_version)`;
- lazy in-memory caches for function discovery, symbols, strings, xrefs, LLIR, CFG,
  and decompilation prerequisites;
- a shared deadline/cancellation token and resource counters;
- optional attachment to a project repository; and
- explicit invalidation when bytes, analysis settings, types, names, or patches
  change.

Do not begin with durable caching of every intermediate. First prove correct
in-process reuse. Durable cache entries should follow only for expensive,
deterministic artifacts with stable serialization.

**First vertical slice.** Convert `analyze_functions_*`, `decompile_at`,
`decompile_many`, and one xref tool to use the session while preserving existing
functions as compatibility wrappers.

**Acceptance evidence.** Fixture-backed equality against current outputs; one read
and one function-discovery pass for a multi-function decompile; cache hit/miss and
invalidation tests; measured warm-call speedup; bounded memory.

### Rank 2 — P0: centralize `.glaurung` schema, migrations, and repositories

**Finding.** The persistent-project design promises ordered migrations, but the
implementation rejects any version mismatch and no migrations directory exists.
Schema creation and opportunistic `ALTER TABLE` logic live in domain modules and
are executed from query operations. Generic nodes/edges and specialized relational
tables also have different load/persistence models without a documented repository
boundary.

**Recommendation.** Keep SQLite, but establish one `ProjectRepository` lifecycle:

- one manifest declaring the current integer schema version and every table/index;
- ordered, transactional, forward-only migrations with backup/failure tests;
- schema initialization and migration exactly once per opened connection;
- repositories for functions, xrefs, types, evidence, frames, journal, and generic
  graph records;
- cursor/paged query APIs for large collections;
- an explicit unit-of-work/dirty set so save cost is proportional to mutations;
- project integrity checks and an atomic checkpoint command; and
- a documented concurrency policy for readers, the single writer, timeouts, and
  cancellation.

The generic graph can remain useful for agent memory, while first-class high-volume
facts remain normalized. The architecture needs to state which is authoritative for
each entity and how cross-model references are maintained.

**First vertical slice.** Move all existing DDL into schema version 2, implement a
v1-to-v2 no-data-loss migration, remove `_ensure_schema()` from hot reads, and add a
repository for function names/xrefs behind the current functions.

**Acceptance evidence.** Fresh create, v1 migration, interrupted-migration rollback,
forward-version rejection, `PRAGMA foreign_key_check`, real project reopen, and a
hot-lookup benchmark showing schema work occurs once.

### Rank 3 — P0: make CLI commands and agent capabilities lazy by construction

**Finding.** `glaurung --help` imports nearly the whole application and agent tool
surface. This creates a measured 1.8-second/249-MB floor and couples unrelated
commands to optional agent dependencies and import failures.

**Recommendation.** Introduce two lightweight registries:

- `CommandDescriptor`: name, help, argument-registration callable path, formatter
  path, capability/extras requirements, and implementation loader.
- `ToolsetDescriptor`: stable ID, domain, supported formats, cost/risk tags,
  dependency requirements, tool metadata loader, and implementation loader.

Parser construction should load only small descriptors. Command execution should
load one implementation. Agent construction should select route/toolset descriptors
before importing tool implementations. Build focused Pydantic AI
`FunctionToolset`s/`CombinedToolset`s and use filtered or deferred loading where
appropriate.

Avoid transparent global lazy imports because they obscure initialization errors.
Load explicitly at a boundary that can produce a clear capability error.

**First vertical slice.** Make `triage`, `strings`, and `--help` independent of the
LLM stack; then convert Windows and Java agent tools into domain toolsets.

**Acceptance evidence.** `--help` under 250 ms and 75 MB on the same environment;
no `glaurung.llm.agents` or tool implementation modules loaded; command-level smoke
tests; deterministic tool names and route output unchanged.

### Rank 4 — P0: define a typed analysis-pass graph and extension contract

**Finding.** Kickoff and other composite workflows directly orchestrate many
functions. Dependencies, prerequisites, produced artifacts, invalidations, and
partial outcomes are implicit. The planned plugin architecture therefore has no
stable substrate.

**Recommendation.** Define an in-process pass contract before dynamic third-party
plugins:

```text
PassId
scope: binary | function | region | project
requires: typed ArtifactKey set
produces: typed ArtifactKey set
mutates: declared project domains
cost: expected class and default budget
run(session, inputs, context) -> PassOutcome
```

`PassOutcome` should include status, produced artifacts, provenance, diagnostics,
resource usage, and preserved/invalidated results. Scheduling should be
deterministic, cycle-checked, and observable. Function-scoped passes should reuse
immutable binary-scoped analyses rather than trigger them.

Once internal passes are stable, expose the same contract through Python entry
points. Do not start with arbitrary native dynamic libraries or a stable Rust ABI.

**First vertical slice.** Use the new Android-driver work as the first typed vertical:
produce `AndroidPackageFacts`, `NativeLibraryFacts`, `UserlandIoctlUse`,
`KernelModuleFacts`, `KernelIoctlSurface`, `SELinuxPolicyFacts`,
`SePolicyReachability`, `SymbolicSinkFinding`, and `CorrelatedExposureFinding`
artifacts behind existing APIs. Preserve the current behavior while making missing
policy semantics, heuristic coverage, and analysis failures explicit. Convert
kickoff to the same pass contract once this smaller artifact chain proves it.

**Acceptance evidence.** pass-order snapshot tests, cycle rejection, missing
capability errors, cache reuse, invalidation tests, and identical kickoff output.

### Rank 5 — P0: propagate budgets, cancellation, progress, and partial status end to end

**Finding.** Low-level budget controls do not form a composite deadline. The real
Windows kickoff exceeded 60 seconds without producing user-visible checkpointed
output. The new symbolic IOCTLance example has a useful local timeout, but its
format parsing, kernel-surface recovery, policy work, symbolic analysis, correlation,
and persistence still lack one shared deadline. Broad best-effort handling can also
erase the distinction between “not applicable,” “no findings,” “budget exhausted,”
and “analysis failed”; `map_linux_ioctl_surface` currently collapses parse/analysis
failure to an empty result.

**Recommendation.** Add one `ExecutionContext` shared by sessions, passes, database
operations, CLI commands, and agent tools:

- monotonic deadline and cancellation token;
- byte, function, block, instruction, output-row, and recursion budgets;
- progress events with phase, completed/total when known, and latest checkpoint;
- structured `complete`, `partial`, `skipped`, `cancelled`, and `failed` status;
- causal typed diagnostics; and
- transaction/checkpoint policy for partial durable results.

Timeouts must not imply safety if lower-level native work cannot observe them.
Cancellation checks belong in bounded loops and between passes, with documented
granularity.

**First vertical slice.** Add a shared deadline to kickoff and ensure function
discovery, frame analysis, type propagation, and project writes all observe it.

**Acceptance evidence.** deterministic forced-timeout tests on real fixtures;
database integrity after cancellation; resumable/pass-idempotent behavior; clear
CLI status and nonzero exit semantics.

### Rank 6 — P1: make the Rust/Python API contract generated and type-checkable

**Finding.** Runtime-native modules work, but static tooling cannot see large parts
of `g.analysis`, `g.ir`, `g.debug`, and related surfaces. Some handwritten stub
signatures have drifted from callers. The 279 `ty` diagnostics therefore mix tool
configuration/stub gaps with genuine type/API problems.

**Recommendation.** Treat the Python API as a versioned product:

- generate or mechanically validate `.pyi` files from registered PyO3 signatures;
- keep wrapper return values typed rather than constructing unstructured Python
  dictionaries where stable models exist;
- add a public API manifest/snapshot and compatibility test;
- configure `ty` with the actual Python environment and extension stubs;
- separate native-surface diagnostics from pure-Python diagnostics; and
- ratchet each category to zero rather than adding blanket ignores.

Also define a capability-graduation ladder for new Rust work:

```text
core parser -> triage fact -> typed pass artifact -> Python binding
            -> project persistence -> CLI/tool surface -> benchmark/docs
```

The new Android, Linux IOCTL, and SELinux modules are strong core capabilities, but
most are not yet represented consistently in Python bindings, persistent projects,
or the CLI. A capability should declare its current rung rather than appearing
simultaneously “shipped” in one layer and absent in another.

The six invalid method overrides in CLI commands also indicate that the command
base abstraction should be generic in its formatter or should accept the base type
and narrow internally.

**First vertical slice.** Correct stubs for `analysis`, `ir`, `disasm`, `debug`, and
`symbols`; then fix unknown-argument and invalid-argument diagnostics in one command
family.

**Acceptance evidence.** stub/runtime parity tests across supported Python versions;
zero unknown-argument diagnostics; a committed `ty` baseline that can only improve.

### Rank 7 — P1: split high-change modules at domain boundaries, not arbitrary line counts

**Finding.** Several modules have accumulated multiple reasons to change:

- `windows_function_pretty_lift.py`: 6,046 lines and 224 top-level functions/classes;
- `cli/commands/windows.py`: 4,027 lines;
- `llm/kb/xref_db.py`: 3,420 lines and 87 top-level functions/classes;
- `analysis/cfg.rs`: 3,699 lines;
- `ir/lift_x86.rs`: 2,820 lines; and
- `ir/ast.rs`: 2,259 lines.

Large source files are not inherently wrong in Rust tables/lifters. The issue is
mixed ownership. `xref_db.py`, for example, owns schema migration, undo/redo,
function names, xrefs, prototypes, type propagation, rendering, evidence,
verification, symbol borrowing, stack variables, bookmarks, and journal entries.

**Recommendation.** Decompose by stable concepts with narrow facades:

- repositories and schema outside domain algorithms;
- pure analysis outside persistence;
- renderers outside mutation services;
- CLI parsing/formatting outside reusable Windows domain services;
- architecture-specific lifters split by instruction family only when profiling and
  ownership justify it.

Preserve compatibility imports during migration and enforce dependency direction.
The new `formats::{apk, axml, dex, sepolicy}` modules are positive examples of
cohesive boundaries. By contrast, new AArch64 discovery policy in `cfg.rs` should
eventually become an architecture-specific seed/control-flow strategy, preferably
as part of the pass refactor rather than a standalone file split.

**First vertical slice.** Split xref/name/prototype/frame/journal repositories from
`xref_db.py`; this aligns with rank 2 and avoids a low-value standalone reshuffle.

### Rank 8 — P1: replace broad exception suppression with a subsystem error policy

**Finding.** Broad catches are widespread because Glaurung intentionally performs
best-effort analysis. The design intent is valid; the representation is too weak.
Silent catches during standard-library import, evidence extraction, or optional
passes make absence indistinguishable from failure.

**Recommendation.** Define shared error categories such as input, unsupported,
corrupt, budget, dependency, provider, persistence, internal invariant, and
cancelled. At best-effort boundaries:

- catch only the expected category;
- emit a structured diagnostic and partial-status transition;
- preserve exception chaining internally;
- redact sensitive paths/content from logs; and
- reserve silent suppression for cleanup where failure truly cannot affect output.

Begin with the 20 broad catches in `windows_risk.py`, 19 in `xref_db.py`, 18 in
`evidence.py`, and the standard-library auto-load catches in `persistent.py`.

**Acceptance evidence.** fault-injection tests for missing bundles, corrupt DB rows,
unsupported formats, provider failures, and cancellation; no false “complete” result.

### Rank 9 — P1: separate installation and runtime capability profiles

**Finding.** The base project directly depends on both `pydantic-ai-slim` with three
providers and full `pydantic-ai`. Full pydantic-ai enables a wider set including CLI,
evals, Logfire, MCP, retries, and web support, so the direct slim declaration does
not make the installed environment slim. The local environment resolves 114
packages and occupies about 135 MB. This is not excessive for the full product, but
it is unnecessary for native triage/disassembly use and amplifies eager imports.

**Recommendation.** Define supported profiles rather than ad hoc optionality:

- base: native analysis, persistence, and CLI fundamentals;
- `llm`: Pydantic AI plus the default OpenAI provider;
- provider extras: Anthropic and Google;
- `agent-platform`: MCP/Logfire/web integrations when actually used;
- development/test groups; and
- Rust feature matrix aligned with Python package capabilities.

Because Glaurung is AI-native, the default end-user install may still include
`llm`. The architectural requirement is that non-agent commands do not import or
require it, and that minimal builds are tested.

The latest work partially advances this recommendation: symbolic examples now use
Cargo `required-features` correctly. However, Android APK parsing and its compression
support are currently part of the unconditional Rust surface. The feature matrix
should explicitly decide which format parsers belong to the base product rather
than letting dependency history make that choice implicitly.

**Acceptance evidence.** install/import smoke tests for each supported profile,
clear missing-capability messages, wheel-size and dependency-count baselines.

### Rank 10 — P1: add workflow-level performance and memory gates

**Finding.** Criterion benchmarks and the binary scorecard cover valuable kernels
and output quality, but they do not protect startup, project lifecycle, repeated
analysis, tool registration, or composite command memory.

**Recommendation.** Add a stable engineering scorecard using real fixtures:

- cold `import glaurung`, `--help`, and one non-LLM command;
- session open and first/warm analysis;
- one versus N decompiles;
- project create, migrate, reopen, lookup, page, and dirty save;
- focused agent/toolset construction by route;
- kickoff wall time, phase time, peak RSS, output/database size; and
- cancellation latency.

Track distributions and regression budgets; do not fail CI on noisy single-run
microseconds. Keep large/nightly fixtures separate from fast presubmit gates.

Adopt the dispatch-aware IOCTLance parity corpus as an early workflow scorecard, but
first make the scanner and comparator exchange a versioned JSON schema. Save inputs,
configuration, coverage, per-stage timing, diagnostics, and mismatches as artifacts;
parsing human output with regular expressions and `eval` is too brittle for a
long-lived regression gate even when the input is trusted local output.

### Rank 11 — P2: complete source-level Rust core/PyO3 separation incrementally

**Finding.** Optional compilation works, but 31 core files still combine domain
types with Python methods. This increases review surface, permits Python-specific
return/error choices to leak inward, and makes the intended `python_bindings/`
boundary incomplete.

**Recommendation.** Move Python constructors, getters, serialization adapters, and
special methods into binding modules while retaining pure Rust domain types and
errors. Do this by cohesive type families after ranks 1 and 6 define the desired API;
otherwise the project risks moving an unstable surface twice.

**Acceptance evidence.** no PyO3 imports/attributes under selected core modules,
unchanged Python API snapshots, Rust-only tests, and Python wrapper tests.

### Rank 12 — P2: enforce dependency direction and remove the current import cycle

**Finding.** The CLI package participates in a four-module cycle, and one LLM tool
imports `cli.commands.windows_risk`. Presentation code is therefore being used as a
domain library.

**Recommendation.** Extract reusable services and request/result models from command
modules. Establish and test a dependency direction such as:

```text
core/native -> domain services -> repositories/pass platform -> CLI and agents
```

CLI and agent adapters may both depend on domain services; neither should depend on
the other. Add a small AST-based dependency fitness test with explicit, reviewed
exceptions.

### Rank 13 — P2: align documentation with executable architecture decisions

**Finding.** Some documents are excellent, but others mix proposals, historical
plans, and current contracts. The persistent-project document promises migrations
that do not exist; the PyO3 separation document is dated December 2024 and its
checklist no longer fully describes build reality. The Android parser checklist in
`docs/parsers/android/README.md` still marks DEX, APK, AXML, and multidex work as
unimplemented while `docs/formats/android.md` and the current code describe them as
shipped.

**Recommendation.** Add concise architecture decision records for:

- session identity and invalidation;
- pass/artifact model;
- project schema ownership and migrations;
- command/tool discovery;
- supported capability profiles; and
- public Python API/stub generation.

Living status documents should link to executable tests or manifests. Historical
proposals should be clearly labeled and should not function as current contracts.

### Rank 14 — P2: establish a lint/type debt ratchet

**Finding.** The mandatory completion commands are not currently green: Ruff reports
51 issues and `ty` reports 279 diagnostics. At `cf97906`, `cargo test --all-targets`
passes 802 tests and fails the same two WinAPI prototype tests already documented by
earlier work; focused Android, Linux IOCTL, and SELinux tests pass. `cargo build
--all-targets` and the symbolic IOCTLance example build pass, but `cargo fmt --check`
reports formatting diffs that include newly added Android files. With a codebase this
broad, an all-at-once cleanup is likely to conflict with feature work, but leaving
the gates aspirational allows further drift.

**Recommendation.** First classify diagnostics into configuration/stub debt and
real code defects. Store a machine-readable baseline by code and path, require no
new findings, and burn it down by subsystem. Undefined names, bare exceptions,
unknown arguments, and invalid overrides should be addressed before style-only
issues.

This is a quality program, not permission to weaken the project instructions or
hide diagnostics globally.

## Recommended delivery sequence

### Top 10 starting backlog

This is the review order for the first implementation work. Each item should be a
separately mergeable TDD slice; the phase sections below preserve the longer-term
dependency structure.

1. **Restore the latest-work gates.** Apply Rust formatting, keep the focused
   Android, Linux IOCTL, and SELinux tests green, and either fix or record an
   explicit baseline for the two known WinAPI prototype failures in the all-target
   suite.
2. **Harden APK and DEX input boundaries.** Add real adversarial fixtures for ZIP
   structure validation, CRC and declared-size checks, decompression budgets,
   table-size limits, and explicit partial/error outcomes instead of silent skips.
3. **Make manifest reachability Android-version-aware.** Resolve relative component
   names and model `targetSdkVersion`, component-kind defaults, provider behavior,
   and Android 12's explicit-exported requirement before treating a component as
   externally reachable.
4. **Publish the capability-graduation matrix.** Record, for DEX, APK, AXML, packed
   relocations, PAC/BTI, Linux IOCTL, SELinux, and IOCTLance, the current parser,
   triage, pass, binding, persistence, CLI/tool, documentation, benchmark, and
   feature-profile rung.
5. **Replace IOCTLance text scraping with a versioned JSON artifact.** Remove the
   regular-expression/`eval` exchange and preserve input identity, options, tool
   versions, coverage, timing, diagnostics, findings, and mismatches.
6. **Turn Linux IOCTL recovery into a provenance-bearing outcome.** Distinguish not
   applicable, no handlers, partial coverage, budget exhaustion, and failure;
   validate `file_operations` slots, invalidate stale register facts, and attach
   evidence and confidence to every recovered handler and command.
7. **Complete the SELinux semantic oracle.** Parse and differentially validate
   symbols, classes/permissions, type attributes, avtab, conditionals, and MLS on
   real policies before policy reachability can change finding severity.
8. **Make CLI commands and toolsets lazy.** Commit cold-start/import/RSS baselines,
   add lightweight descriptors, and make `--help`, `triage`, and `strings` avoid
   importing the agent/tool graph.
9. **Land the minimal session/pass substrate.** Introduce artifact identity,
   `AnalysisSession`, `ExecutionContext`, typed `PassOutcome`, cache/invalidation
   tests, and end-to-end deadline, cancellation, progress, and partial-result
   propagation behind existing APIs.
10. **Build the Android-driver correlation pilot.** Produce independently
    inspectable and resumable package, native-library, userland-IOCTL, kernel-IOCTL,
    SELinux-reachability, symbolic-sink, and correlated-exposure artifacts through
    the typed pass graph, then graduate the proven outputs through persistence,
    Python, CLI/tools, and the IOCTLance scorecard.

### Phase 0: stabilize and graduate the latest work (immediate)

1. Format the latest Rust additions and make `cargo fmt --check` pass without
   unrelated rewrites.
2. Resolve or explicitly baseline the two existing WinAPI prototype test failures;
   keep the focused Android, Linux IOCTL, and SELinux tests green.
3. Add a capability matrix showing the graduation rung, feature requirements,
   bindings, persistence, CLI/tool exposure, documentation, and benchmark coverage
   for each new capability.
4. Define versioned JSON result schemas for Linux IOCTL surface recovery and
   IOCTLance parity, including evidence, coverage, confidence, and diagnostics.
5. Continue SELinux parsing through symbols, classes/permissions, type attributes,
   avtab, conditionals, and MLS with real-policy differential tests. Do not use an
   incomplete oracle to strengthen a reachability or severity claim.
6. Keep the emerging Android-driver workflow behind the session/pass interfaces
   described in Phase B instead of adding another ad hoc composite orchestrator.

### Phase A: measure and isolate startup (small, immediate)

1. Commit cold-start/import/RSS benchmarks.
2. Add lightweight command descriptors.
3. Make `--help`, `triage`, and `strings` avoid all agent imports.
4. Create domain toolset descriptors and preserve deterministic routing.

This phase should provide a visible improvement quickly and reduce friction during
later work.

### Phase B: establish the session and pass substrate (foundational)

1. Define artifact identity, option fingerprints, and `AnalysisSession` ownership.
2. Wrap current function discovery and decompilation APIs.
3. Add cache/invalidation tests.
4. Define `PassOutcome` and convert kickoff without behavior changes.
5. Thread the execution context/deadline through the converted passes.
6. Implement the Android package -> native library -> kernel IOCTL -> SELinux
   reachability -> symbolic sink correlation as the first multi-artifact pass graph.

### Phase C: migrate the project database (foundational)

1. Freeze and test schema v1 as the migration source.
2. Introduce centralized schema v2 and repositories.
3. Move xref/name schema checks out of hot paths.
4. Implement dirty tracking, paging, integrity checks, and cancellation-safe
   transactions.
5. Convert one high-volume real project and compare output/counts.

### Phase D: contract and modularity hardening

1. Generate/validate native stubs and establish the `ty` ratchet.
2. Extract Windows domain services from CLI modules.
3. Decompose `xref_db.py` behind repositories.
4. Move cohesive PyO3 families out of core source.
5. Add dependency-direction and architecture fitness tests.

## Proposed architecture sketch

```text
CLI / REPL / LLM agents
        |
        v
lazy command + capability registries
        |
        v
domain services and typed pass requests
        |
        v
AnalysisSession ---- ExecutionContext
        |                    |
        |                    +-- deadline / cancellation / progress / budgets
        |
        +-- immutable binary image + parsed format
        +-- AnalysisManager (lazy typed results + invalidation)
        +-- PassManager (deterministic scheduling + outcomes)
        +-- ProjectRepository
                    |
                    +-- centralized schema + migrations
                    +-- function/xref/type/evidence/frame repositories
                    +-- transaction + dirty unit of work
```

The session is not a global singleton. Multiple binaries/projects must remain
independent, and immutable session analyses should be safe to share across
function-scoped work. Persistent analyst mutations should invalidate only dependent
rendered/derived artifacts, not force an unconditional full reanalysis.

## Decisions to make before implementation

1. **Session language boundary:** Prefer Rust ownership for bytes and native analysis
   caches, with Python holding a PyO3 session handle. Confirm that Python-only
   analyses can attach typed results without forcing all artifacts into Rust.
2. **Cache identity:** Decide which settings affect function discovery, lifting,
   types, and rendering. An underspecified cache key is a correctness bug.
3. **Database authority:** Decide whether generic KB nodes mirror first-class rows or
   represent only unstructured agent memory. Avoid dual writable truth.
4. **Migration guarantees:** Decide whether downgrade is unsupported, whether every
   migration creates a backup, and what recovery UX is promised after interruption.
5. **Plugin trust:** Initially support trusted in-process Python plugins only.
   Sandboxing, resource isolation, and stable third-party Rust ABIs are separate
   projects.
6. **Partial result semantics:** Decide which pass outputs are independently durable
   and resumable, and which must be committed atomically as a group.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Session becomes a new god object | Keep typed result stores and narrow service interfaces; session owns lifecycle, not every algorithm. |
| Cache returns stale analyst-facing output | Explicit option/version keys and dependency invalidation; default to recompute when uncertain. |
| Pass abstraction adds ceremony | Start with existing kickoff steps and only model dependencies/results that tests require. |
| Database migration damages projects | Backups, transactionally tested migrations, fixture snapshots, integrity checks, and forward-version refusal. |
| Lazy imports hide failures | Explicit descriptor loaders with command/capability-specific error messages. |
| Tool refactor changes model behavior | Snapshot tool names/schemas/routes and replay representative agent tests. |
| Type cleanup is dominated by extension false positives | Fix/generate native stubs first, then ratchet pure-Python errors separately. |
| Architectural work stalls feature delivery | Land vertical slices behind compatibility facades with measured user-facing wins. |

## Completion criteria for the architecture program

The program should not be considered complete merely because new classes exist.
Evidence should show:

- one binary read/parse/discovery lifecycle across a representative multi-tool run;
- correct cache invalidation after patching bytes, changing types/names, and changing
  analysis options;
- deterministic pass scheduling and provenance-bearing partial outcomes;
- one end-to-end Android-driver correlation run whose package, native, kernel,
  policy, and symbolic artifacts can be inspected and resumed independently;
- no policy-based exposure or severity claim unless the supporting SELinux policy
  structures were parsed and validated, with incomplete coverage reported explicitly;
- `--help` and non-LLM commands no longer import agent/tool implementations;
- versioned migration from every supported project schema and integrity-preserving
  cancellation;
- project saves proportional to dirty records and paged high-volume reads;
- workflow budgets enforced across native, Python, and persistence phases;
- public native stubs matching runtime signatures;
- no dependency cycles or CLI-to-agent/agent-to-CLI inversion;
- green or explicitly ratcheted Ruff and `ty` gates;
- machine-readable IOCTLance parity artifacts with stable schema, evidence, and
  reproducible mismatch accounting; and
- benchmark evidence that cold startup, warm repeated analysis, project operations,
  and peak memory meet agreed thresholds.

## Immediate recommendation

Start by restoring the latest-work integration gates: make formatting green,
baseline or fix the two known WinAPI tests, publish the capability-graduation
matrix, and replace IOCTLance's human-output exchange with a JSON artifact.

Then proceed with two coordinated but separately mergeable slices:

1. **Lazy CLI/tool registration**, because it is low-risk, directly measured, and
   directly targets the measured roughly 1.7-second and 200-MB gap between the base
   package import and simple CLI commands on this machine.
2. **`AnalysisSession` and typed-pass slice**, using the Android package -> kernel
   IOCTL -> SELinux -> symbolic correlation as the concrete pilot. It establishes
   reusable cache, provenance, coverage, and partial-result semantics while directly
   integrating the latest capability work.

Design the centralized database migration in parallel, but do not mutate existing
project files until v1 fixtures, backup behavior, and migration failure tests are in
place.

## Reproduction notes

Representative commands used for the local evidence included:

```bash
# Source and boundary inventory
find python/glaurung -type f -name '*.py' -print0 | xargs -0 wc -l
find src -type f -name '*.rs' -print0 | xargs -0 wc -l
rg -l '#\[(pyclass|pymethods)' src/core
rg -n '^from \.\.tools\.' python/glaurung/llm/agents/memory_agent.py
rg -n 'sqlite3\.connect|CREATE TABLE|ALTER TABLE' python/glaurung/llm/kb

# Current quality gates, run without fixes
uvx ruff check python/glaurung --statistics
uvx ty check python/glaurung
cargo check --no-default-features

# Latest-work integration gates
cargo fmt --check
cargo test --all-targets
cargo test --test android_dex_triage --test android_pac_bti_cfg \
  --test android_pac_stripped_discovery --test android_packed_relocations
cargo test linux_ioctl
cargo test sepolicy
cargo build --all-targets
cargo build --example ioctlance --features symbolic
uvx ruff check scripts/ioctlance_parity.py
uvx ty check scripts/ioctlance_parity.py
uv run python scripts/ioctlance_parity.py --help

# Cold process/import baselines
/usr/bin/time -f 'elapsed=%e rss_kb=%M' uv run python -c 'import glaurung'
/usr/bin/time -f 'elapsed=%e rss_kb=%M' \
  uv run python -c 'import glaurung.cli.main'
/usr/bin/time -f 'elapsed=%e rss_kb=%M' uv run glaurung --help
uv run python -X importtime -c 'import glaurung.cli.main'

# Real fixture workflows
uv run glaurung kickoff \
  samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2 \
  --db /tmp/glaurung-arch-review.glaurung --max-functions 500 --no-pdb

timeout 60s uv run glaurung kickoff \
  samples/binaries/platforms/windows/vendor/realworld/win11-webservices.dll \
  --db /tmp/glaurung-arch-review-driver.glaurung \
  --max-functions 500 --no-pdb --no-fetch-pdb
```

The import and timing commands were run more than once while investigating, but the
table intentionally reports a representative observed run rather than claiming a
statistically stable benchmark. The proposed scorecard should add warmups,
distributions, environment capture, and noise thresholds before these values become
regression gates.

The latest-work integration review covered commits `c9a56ee..cf97906`. This report
did not edit production or test code. At final verification the report itself was
the only review-owned worktree change.
