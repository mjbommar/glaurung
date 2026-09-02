# Module boundaries

> **Kind:** architecture · **Status:** maintained

Seven boundaries this codebase is meant to hold, each with the evidence that
would prove it held and where it stands today. This is not a migration plan.
A 2026-08 planning exercise wrote the boundaries down as a seven-project
portfolio and no commit ever cited one; that portfolio is archived at
[`../history/refactoring-portfolio-2026-08/`](../history/refactoring-portfolio-2026-08/)
with a scoreboard in its
[`OUTCOMES.md`](../history/refactoring-portfolio-2026-08/OUTCOMES.md). What
survives, and belongs here, is the statement of *what a correct boundary looks
like* — which is durable even when the plan to reach it was not.

The mechanism that actually moves the tree is measurement, not a plan: see
[Where the pressure comes from](#where-the-pressure-comes-from) at the end.

Status words below mean: **held** — the boundary is enforced by code or a gate;
**partial** — it exists in the tree but has a named violation; **open** — the
tree does not have it.

---

## 1. One program-semantic authority

**The boundary.** Program-wide facts — images, symbols, types, relocations,
completeness diagnostics — have exactly one owner, and per-function analysis
receives borrowed read-only views plus an explicit result sink. Function
analysis must not assemble a competing address, name, or type map. Conflicting
evidence is retained and ranked rather than merged; manual evidence stays
highest.

**Exit evidence.** One documented precedence table covering manual, debug,
signature, relocation, propagated and heuristic evidence. No production
consumer building a competing program-wide symbol or type authority. Repeated
analysis in one session parses each image and debug source once. Same-named
incompatible layouts stay distinct and diagnosable.

**Where it stands — partial.** `src/program/` is the owner:
`ProgramSession`, `ProgramImage`, `ProgramEnvironment`, `symbols/`, `types/`,
`references.rs`, `call_graph.rs`, `spans.rs` — 23 files, 8,951 lines.
`src/program/diagnostics.rs` does not exist. The precedence-table requirement
was satisfied, but on the Python side and outside this boundary:
`python/glaurung/llm/kb/provenance.py`, documented at
[`../reference/provenance.md`](../reference/provenance.md). So there is one
ranked authority for persisted analyst-facing facts and no single ranked
authority for native program facts.

---

## 2. Lifter → LLIR → SSA → verified typed MIR → recovery → HIR → renderer

**The boundary.** The decompiler is a one-way pipeline:

```text
machine instructions
  -> architecture lifter -> LLIR
  -> CFG-aware SSA + memory/object identities
  -> verified typed MIR
  -> semantic recovery services
  -> graph-complete HIR
  -> pure AST renderer
```

Every transition returns diagnostics and completeness. **Rendered C is a view,
never an input to semantic recovery.** That sentence is the load-bearing one:
it is what forbids reading the pretty output back to decide a type, a name, or
an edge.

**Exit evidence.** One public pipeline entry point and one pass ordering.
Lifters cannot import HIR, AST rendering, naming, or the Python bindings.
Render modules cannot mutate semantic facts. Every MIR-consuming pass declares
the invariants it needs and fails closed when they are absent.

**Where it stands — partial.** LLIR, SSA, recovery and rendering are all real;
`src/ir/mir/` (9 files, 4,550 lines) is a genuine verified typed MIR and is
built on demand by `PreparedLlir::mir`, but it carries `#[allow(dead_code)]`
and **has no production consumer**, so the "verified typed MIR" rung of the
pipeline is present and unwired. There is no `src/ir/hir/`. The one public
pipeline entry point exists in the wrong crate layer — see boundary 4.

**Stop conditions.** Reject a split that adds a cyclic dependency, duplicates
an IR type, changes pass order implicitly, or improves pseudocode by discarding
unknown effects or unresolved edges.

For what is built and what is not, in detail, read
[`decompiler-pipeline.md`](decompiler-pipeline.md).

---

## 3. Graph model, discovery, and algorithms are separate

**The boundary.** A graph algorithm does not decide whether missing bytes or an
unresolved indirect branch means analysis is complete. Discovery is a service
producing provenance-bearing candidates; it does not silently mutate graph
truth. Algorithms operate on immutable views and state their requirements.
Every terminator has an explicit representation, including unknown and indirect
transfers, and completeness distinguishes exhausted discovery from a resource
limit, unsupported semantics, unreadable bytes, and an unresolved target.

**Exit evidence.** No graph algorithm reads binary bytes or format parsers. No
renderer or binding mutates a graph. Exact-edge fixture gates report zero
invented or missing edges on their supported corpus, and incomplete cases stay
explicitly incomplete. Budget changes participate in session cache identity.

**Where it stands — held, under different names than the plan proposed.**
`src/analysis/cfg.rs` went 7,125 → 1,992 lines with 19 sibling modules —
`packed`, `image_view`, `budgets`, `scan`, `entry_shape`, `pe_tables`, `plt`,
`seeds`, `worklist`, `body_index`, `walk`, `ctrl_flow`, `extents`,
`function_build`, `repair`, `must_dataflow`, `dispatch_flow`,
`dispatch_resolution`, `stats` — and the discovery order is documented as a
table in `cfg.rs` itself. `src/analysis/completeness.rs` is the module that
turns "a budget fired" into a note the reader can see.

**Stop conditions.** Stop if an unknown edge becomes a fallthrough, an indirect
branch disappears, function candidates are accepted without provenance, or
graph validity is inferred only from a successful render.

---

## 4. The PyO3 seam is a translation layer

**The boundary.**

```text
Rust domain model -> Rust application services -> transport DTOs -> PyO3
                                                       |
                                                Python typed facade
```

Domain and application modules never import PyO3. A binding module validates
Python inputs, calls **one** application service, and converts a result or
error into a stable DTO carrying provenance, completeness and diagnostics.
Python convenience code composes public services; it does not repair or
reinterpret native facts.

**Exit evidence.** `rg 'pyo3' src --glob '*.rs'` finds PyO3 only in the crate
root and the binding modules. Rust services are testable without `python-ext`.
**Binding functions contain no pass sequencing, file parsing, or semantic
recovery policy.** Native errors map to stable, specific Python exceptions or
typed incomplete results.

**Where it stands — open, and this is the known violation.** The AST pass
ordering lives in `src/python_bindings/ir/pipeline.rs` (532 lines) and the
entry points in `src/python_bindings/ir.rs` (2,496). That is pass sequencing
inside the binding layer, which this boundary forbids in as many words. The
consequence is concrete and shows up elsewhere in this repository's rules: most
decompiler passes are reachable **only** through the bindings, so a plain
`cargo test` neither runs nor compiles them, and `--features python-ext` is
mandatory for any change that touches the pipeline.

```bash
rg -l 'pyo3' src --glob '*.rs' | grep -v python_bindings | wc -l   # 46
```

PyO3 also appears in 46 files outside `src/python_bindings/` — the per-type
`#[pyclass]` / `#[pymethods]` blocks in `core/`, `triage/`, `strings/` and
`symbols/`. Those are gated on `python-ext` and are the mechanism by which the
data model is exposed at all, but they are the same boundary, unheld.

Neither `src/decompile/service.rs`, `src/analysis/service.rs`,
`src/python_bindings/analysis/`, nor `python/glaurung/api/` exists. What did
land is the subdivision: `src/python_bindings/ir/` (`pipeline`, `lift`,
`session`, `type_maps`, `callee_contracts`, `dwarf_contracts`,
`decbench_render`), which took `ir.rs` from 3,875 to 2,496.

**Stop conditions.** Reject a migration that converts errors to empty
collections, exposes internal mutable models as API-stability promises, or adds
a second Python-only analysis pipeline.

---

## 5. The deterministic fact packet is the contract

**The boundary.** For the Windows surface, a deterministic fact packet is the
single contract shared by the CLI and the LLM tools. Command modules register,
validate and dispatch; they contain no domain algorithms. Tool adapters contain
no duplicate fact extraction. **Generated prose or pretty pseudocode cannot
feed back as a trusted fact without an explicit verified promotion step.**

**Exit evidence.** Schemas never lose fields or provenance; JSON output does
not change unintentionally; validation is not text-only; extraction never
depends on a renderer or an agent response.

**Where it stands — open as a code boundary, held as a discipline.** There is
no `windows/{domain,extract,services,render,validate}/` package, no
`cli/commands/windows/` package, and no `llm/tools/windows/` package;
`python/glaurung/cli/commands/windows.py` is 4,025 lines and
`python/glaurung/llm/tools/windows_function_pretty_lift.py` is 6,046. What is
held is the *rule*: the Windows analysis path is deterministic end to end —
`windows.py` imports no `pydantic_ai` and calls no model — so no generated
prose can enter it in the first place. See [`windows-port.md`](windows-port.md).

---

## 6. Storage, repositories, and domain records are separate

**The boundary.** SQL appears only in migration, storage and repository
modules. Repositories return typed records or typed absence, never partially
interpreted SQL rows handed on to a CLI, a renderer, or an agent. Manual
annotations always outrank automated evidence and are never deleted by a
refresh. Provenance survives round trips and migrations. Unknown future schema
versions fail with a clear error and are never opened as if current.

**Where it stands — partial, and split cleanly between the two halves.**

*Held:* the fail-closed rule (`persistent.py:210-215`, with the literal message
"migrations are not yet implemented"), and the manual-wins rule, which is now a
full ranked ladder enforced inside every setter
([`../reference/provenance.md`](../reference/provenance.md)), pinned by
`python/tests/test_kb_manual_precedence.py` and
`python/tests/test_kb_provenance_rank.py`.

*Open:* `python/glaurung/llm/kb/` is 27 flat modules with no `schema/`,
`storage/`, `repositories/`, `domain/` or `services/` split, and `xref_db.py`
is 3,557 lines holding schema, queries and domain conversion together. The
migration requirement cannot be met as written — migrations are unimplemented
and there has only ever been schema version `1` — which makes it a real,
unaddressed gap rather than a satisfied one.

**Stop conditions.** Stop if migration testing uses only a freshly created
database, if a rewrite loses provenance, or if repository extraction changes
transaction boundaries without an atomicity test.

---

## 7. One instruction semantics, many domains

**The boundary.** Instruction effects have **one** implementation,
parameterized by a domain; the concrete emulator and the symbolic engine call
the same owner. Execution state, memory, path constraints, exploration
scheduling and solver selection have separate types and owners. Vulnerability-
specific analyses consume trace and evidence APIs rather than embedding
semantics or steering the solver.

**Exit evidence.** Concrete and symbolic execution call the same
instruction-effect owner. Exploration strategies do not inspect solver
implementation details. Solver `unknown`, timeout, unsupported theory and
invalid model stay **distinct and fail closed**. Feature combinations (`exec`,
`symbolic`, each solver backend, the Python extension) compile and run their
declared tests independently.

**Where it stands — partial, with the hardest half held.** One interpreter is
shared: `src/exec/interp.rs` is parameterized over `src/exec/domain.rs`'s
`Domain` trait and the symbolic backend supplies its own domain, so there is no
duplicate instruction semantics. `src/symbolic/explore/` and
`src/symbolic/solver/` exist and `explore.rs` went 3,617 → 1,768 lines. The
feature-combination criterion is now enforced by
`scripts/feature-build-gate.sh`'s twelve lanes — delivered outside the plan
that asked for it. Not done: `src/exec/` is ten flat files with no `machine/`
or `semantics/` split, and `ioctl.rs`, `ordered_replay.rs`, `ordered_trace.rs`
and `native_trace.rs` sit flat in `src/symbolic/`.

**Stop conditions.** Stop if a refactor broadens supported semantics without
oracle or fixture evidence, **maps `unknown` to satisfiable or unsatisfiable**,
weakens resource limits, or makes a security-specific policy part of the
generic interpreter.

See [`execution-engine.md`](execution-engine.md) and
[`solver-backends.md`](solver-backends.md).

---

## Where the pressure comes from

No plan is driving these boundaries. Three measurements are, and they run in
the ordinary test suite rather than in a document:

- **`tools/fitness_report.py`** measures physical product lines over `src/*.rs`
  — excluding test files and modules, and stripping inline `#[cfg(test)]` —
  and `--check-ratchet` fails if any measure got worse.
  `tools/fitness_baseline.json` is the ratchet's stored state.
- **`python/tests/test_large_module_review.py`** requires every product file
  over 1,000 lines to carry an entry in `REVIEWED_LARGE_MODULES` saying why it
  has one reason to change — and deletes are enforced too: an entry for a file
  that has dropped back under the threshold fails the test.
- **`python/tests/test_src_dependency_boundaries.py`** pins which modules may
  read which environment variables, keyed by file path.

All three are the kind of gate an optimisation or fixture loop never runs,
because they ask whether the codebase is healthy rather than whether the
decompiler is correct. The numbers, the thresholds and where each gate runs are
in [`../development/testing-gates.md`](../development/testing-gates.md).

The rule those gates encode, and the one to apply before invoking any boundary
above: *a file split counts only if it creates a narrower API and one reason to
change; arbitrary fragmentation is not architecture.*
