# Hybrid analysis objective ladder

> **Kind:** design · **Status:** proposed

This is the ordered chain of outcomes by which Glaurung should close the gap
between decompilation and live binary analysis. It is deliberately stricter
than a feature roadmap. Each objective is an externally testable capability,
and every higher objective depends on the evidence contract below it.

The [runtime roadmap](../../development/roadmap/runtime-analysis.md) remains the
work order. This document defines what success means and prevents partial
integration from being mistaken for the result.

## North-star outcome

Given an exact binary and evidence from a core, stopped process, or bounded
trace, Glaurung should be able to say:

> This operation in this recovered function acted on this concrete runtime
> object during this execution, under these process and OS conditions. These
> bytes and events were observed; these program facts were inferred statically;
> this explanation was replayed; these alternatives were proved feasible or
> infeasible within these bounds; and these questions remain unknown.

The result must be navigable in both directions:

```text
runtime event or fault
  → process / thread / time
  → mapping and exact module instance
  → machine instruction occurrence
  → semantic operation and values
  → recovered expression, variable, type, and function
  → memory object and OS context
  → finding, alternatives, and evidence packet
```

And:

```text
decompiled expression or variable
  → semantic values and operations
  → static possibilities
  → observed occurrences across executions
  → concrete values, objects, and effects
  → coverage, contradictions, and unknowns
```

No address-only hyperlink, shared screen, debugger annotation, or unqualified
trace overlay counts as this outcome.

## Rules for climbing the ladder

1. **No rung is complete by demonstration alone.** It needs committed fixtures,
   negative controls, deterministic automation, and a shipping API or CLI.
2. **Every claim retains its epistemic kind.** Static, observed, replayed,
   symbolic, inferred, and unknown are never silently substituted.
3. **Identity precedes analysis.** A result that cannot prove which build,
   process, mapping, thread, occurrence, and bytes it concerns is not evidence.
4. **Absence is scoped.** Not observed is not unreachable; not captured is not
   zero; one observed target is not an exhaustive target set.
5. **The decompiler and runtime models remain distinct.** They meet through
   typed relations described in [reuse boundaries](reuse-boundaries.md).
6. **Good controls are first-class.** Precision is measured with normal cases,
   wrong-build cases, missing evidence, and benign executions—not only with
   known failures.
7. **Higher rungs cannot repair lower-rung uncertainty by guessing.** Symbolic
   execution cannot manufacture an absent page; an LLM cannot establish module
   identity; a renderer cannot turn ambiguity into a fact.
8. **A second source of evidence is required before generality is claimed.** A
   model proven only on one acquisition path, architecture, compiler, or
   fixture family remains provider-shaped.

## Objective 0 — Authoritative truth set

**Outcome:** The 60-program corpus becomes a reproducible measurement
instrument rather than a collection of examples.

Required capability:

- versioned semantic oracles separate from analyzer inputs;
- good and bad expectations for all 120 scenarios;
- independent oracles for crashes, changed bytes, dangerous operations, and
  normal behaviour;
- deterministic matrix ledger bound to source, compiler, flags, binary, input,
  and harness identities; and
- explicit skipped/not-evidence results when a requested artifact is absent.

**Exit evidence:** Every scenario has machine-readable positive and negative
expectations. Mutating an expected signal, byte interval, object, or event makes
the gate fail. The analyzer cannot read the oracle while producing its result.

**Does not count:** Matching process exit codes alone; treating sanitizer output
as analyzer input; silently dropping compiler or link lanes.

## Objective 1 — One trustworthy runtime artifact

**Outcome:** Live capture and postmortem import produce the same versioned
`ProcessCapsule` model with explicit completeness.

Required capability:

- process, thread, module, mapping, register, sparse-page, terminal-state, and
  provenance records;
- public metadata separated from sensitive payloads;
- requested-versus-obtained completeness and bounded collection;
- deterministic serialization and round-trip import; and
- hostile, oversized, truncated, path-substitution, and hash-disagreement
  rejection.

**Exit evidence:** A fresh process imports and re-exports representative live
and core artifacts deterministically. Semantically stable facts agree across
providers, while provider-specific omissions remain explicit.

**Does not count:** A directory of `/proc` files; a wrapper around one core
parser; replacing absent bytes with zero; claiming a core exists when host
policy suppressed it.

## Objective 2 — Exact static/runtime identity

**Outcome:** Every relevant runtime address can be resolved—or explicitly not
resolved—to an exact static image, module instance, mapping, and file range.

Required capability:

- durable execution, process, module-instance, mapping, and snapshot IDs;
- build ID plus content identity rather than path or basename;
- PIE/non-PIE and split-mapping normalization;
- separate raw VA, module-relative address, static VA, and file offset;
- distinctions among unchanged file-backed, modified file-backed, anonymous,
  aliased, deleted, and unknown pages; and
- byte-origin records for every decoded instruction.

**Exit evidence:** All captured main-module PCs in the default compiler,
optimization, and PIE matrix resolve to the correct exact build. Wrong-build,
same-basename, changed-page, duplicate-load, and missing-page controls fail
closed.

**Does not count:** Subtracting a presumed ASLR base; joining on path; decoding
file bytes when captured executable bytes differ.

**Current exit evidence:** The default eight-cell instruction-trace matrix
records every analyzed-image PC and resolves the complete population exactly;
an independent crash matrix rejects different builds. Same-basename,
changed/invalid code-byte, overlapping alias, disjoint duplicate-load, missing
page, and explicit-omission controls preserve typed identity/absence and
withhold contradicted static semantics. Objective 2's stated exit is closed.

## Objective 3 — Precise crash localization

**Outcome:** From a core or stopped child, Glaurung identifies the faulting
process, thread, signal, PC, instruction, access direction, target address, and
memory-permission context when the evidence permits.

Required capability:

- architecture-correct register import;
- faulting-thread selection without assuming note order;
- bounded stack and nearby-memory views;
- read/write/execute and deliberate-signal classification; and
- evidence-linked module, function, block, and instruction resolution.

**Exit evidence:** All 15 bad crash scenarios receive their correct supported
class, all 15 good controls receive no crash finding, and missing fault address,
register, page, or signal evidence weakens the result rather than being guessed.

**Does not count:** Printing the signal and PC; symbolizing against an unproved
binary; labeling every `SIGSEGV` a null dereference.

## Objective 4 — Fault-to-decompiler semantic explanation

**Outcome:** A faulting instruction occurrence resolves into the authoritative
function semantic graph and a recovered high-level expression without storing
runtime state in the AST.

Required capability:

- the central `FunctionIR` proposed by the
  [Ghidra comparison](ghidra-comparison.md);
- architecture-defined storage identities and register projections;
- stable operation, value, block, variable, type, and origin IDs;
- token-to-expression-to-operation navigation; and
- an `OperationOccurrence` joining runtime inputs, outputs, and effects to one
  static operation under process, thread, and occurrence scope.

**Exit evidence:** For supported crash cases, an analyst can navigate from the
fault to the recovered expression and back to the observed registers, address,
bytes, and machine instruction. Two loop iterations or threads can attach
different concrete values to the same static operation without collision.

**Does not count:** An address comment in pseudocode; assigning one concrete
value directly to an SSA value; post-hoc string matching against rendered C.

**Current progress:** Exact LLIR operations now carry a canonical static
function → block → operation identity hierarchy derived from immutable image
and lift-generation identity. Occurrence construction validates the complete
hierarchy and keeps capture/thread/event identity separate; the real
direct-store trace preserves it through project persistence. Objective 4
also assigns and validates distinct root IDs for recovered LLIR memory-address
and stored-value expressions plus deterministic IDs, parentage, paths, and
kinds for every nested node. Store address and data operands now have distinct
static value IDs linked to those roots without storing concrete occurrence
values; condition and ordinary defined values now follow the same identity
contract. Direct and indirect call targets and each recovered ABI input
position now use that contract too. A direct target has a semantic value but no
invented expression; a sliced indirect target has both, while concrete
pre-call values remain occurrence-scoped. Objective 4 remains open: the first
DWARF-backed pointer-variable relations now carry IR-owned immutable variable,
type, and semantic-value-binding records. Their image-scoped identities derive
from canonical `.debug_info` DIE offsets rather than names or runtime addresses.
Decompiler-recovered ABI parameters and uniquely located frame locals now also
receive IR-owned variable nodes. Their identities derive from the canonical
function plus ABI position or proven frame base/displacement and a recovery
profile, so changing a rendered name does not change identity. Missing or
ambiguous storage produces no variable identity rather than a name-based
fallback. Parameters with structured recovery evidence now reference immutable
recovered type nodes for integer signedness/width, float width, data-pointer
pointee width, Boolean-like values, or code pointers. Type identity includes
the exact image, semantic shape, target pointer width where relevant, and
recovery profile; rendered C spelling remains an attribute. Stack-local type
text does not mint a type node. The central graph still needs complete live-
range-aware high-variable and recovered-type coverage, bindings from those
variables to all relevant semantic values, AST-origin identities, token
navigation, and the end-to-end crash explanation.

## Objective 5 — Live/postmortem semantic equivalence

**Outcome:** Equivalent evidence captured live and in a core produces the same
stable crash explanation through the same analyzer path.

Required capability:

- a provider-neutral capsule and sparse-memory interface;
- explicit provider extensions rather than provider-specific analyzer branches;
- deterministic static correlation and `FunctionIR` resolution; and
- a defined equivalence projection that excludes volatile/provider-only fields.

**Exit evidence:** Representative null, permission, invalid-control, deliberate-
signal, and stack-exhaustion cases produce equal stable semantic reports from
live and core inputs. Deliberate omissions produce corresponding, explainable
differences.

**Does not count:** Two separately implemented reports that look similar; a
shared renderer over incompatible internal models.

## Objective 6 — Non-crashing memory corruption

**Outcome:** Glaurung identifies a changed dynamic object and byte interval even
when the process exits successfully, and attributes the responsible operation
when evidence exists.

Required capability:

- before/after snapshots or bounded write events;
- runtime object identity and lifetime for stack, global, heap, mapping, and
  unknown objects;
- allocation evidence without assuming portable allocator internals;
- byte diffing by object, not only by virtual address; and
- relations from dynamic objects and writes to `FunctionIR` storage, variables,
  fields, and operations.

**Exit evidence:** The 15 bad memory cases identify the expected changed object
and interval or a precise unsupported boundary; good controls produce no
corruption finding. At least one case proves exact write attribution and one
proves useful partial reporting without attribution.

**Does not count:** Rerunning under ASan and parsing its report; detecting only
process failure; calling every changed adjacent byte an overflow without object
or bounds evidence.

## Objective 7 — OS-contextualized behaviour

**Outcome:** The system explains security-relevant operations in their process,
resource, input, and mapping context while keeping normal behaviour clean.

Required capability:

- normalized syscall and semantic events for files, descriptors, sockets,
  processes, mappings, dynamic loading, and selected IOCTLs;
- stable resource identity across descriptor duplication and process creation;
- redacted input provenance;
- ordered mapping and protection transitions; and
- links from OS events to resolved static call sites and operation occurrences.

**Exit evidence:** The normal and dangerous populations receive their expected
facts and findings across the default matrix. Normal file, mapping, socket, and
process activity does not produce dangerous findings solely because the same
syscall appears in a bad fixture.

**Does not count:** A syscall log; matching dangerous function names; deciding
risk from a pathname or final mapping permissions without history.

## Objective 8 — Temporal semantic trace

**Outcome:** Bounded traces become sequences of semantic operation occurrences,
memory effects, control transfers, and OS events rather than disconnected
instruction addresses.

Required capability:

- per-thread sequence, provider ordering guarantees, and loss accounting;
- repeated operation occurrences distinguished across loops and recursion;
- explicit synchronization evidence rather than invented total order;
- observed-edge and observed-target relations that never become exhaustive by
  implication; and
- queryable slices from input event through memory/control effects to sink or
  fault.

**Exit evidence:** A bounded trace for representative corruption and dangerous-
sink cases reconstructs the relevant semantic chain deterministically. Dropped
events or provider blind spots break the chain visibly rather than being
bridged by assumption.

**Does not count:** Basic-block coverage; a timestamp-sorted multi-thread trace;
deleting static CFG edges that were not observed.

## Objective 9 — Deterministic replay from observation

**Outcome:** Captured state and events seed the existing concrete engine to
reproduce a bounded relevant slice and distinguish observed state from replayed
state.

Required capability:

- one LLIR semantic definition shared by lift, decompile, and execution;
- import of captured registers and selected pages into replay state;
- explicit models or stop boundaries for syscalls, libraries, and unavailable
  devices;
- comparison of replayed effects with observed effects; and
- divergence reports tied to unsupported semantics or missing environment.

**Exit evidence:** At least one crash and one non-crashing corruption slice
replay to the expected operation and memory effect. Mutated initial state or an
unsupported external effect yields a declared divergence, not a fabricated
match.

**Does not count:** Starting emulation at the binary entry point with synthetic
state; agreement between two Glaurung components that share the same semantic
bug without an independent runtime observation.

## Objective 10 — Bounded counterfactual reasoning

**Outcome:** From an observed execution, Glaurung can ask a narrow alternative
question, solve it, produce a concrete witness, and validate that witness on the
real fixture binary.

Examples include avoiding a crash, reaching the same dangerous sink with a
different input, changing a corrupted interval, or proving an alternative
infeasible within a stated bound.

Required capability:

- selective symbolic replacement of captured inputs or values;
- explicit path, memory, environment, and solver bounds;
- observed, replayed, and symbolic state kept distinguishable;
- model-to-real input materialization; and
- automatic real-binary witness validation.

**Exit evidence:** At least one crash case and one dangerous/corruption case
produce independently validated alternate inputs. Unsat and unknown results
state their exact bounded propositions.

**Does not count:** Solver satisfiability without a real witness; calling a
bounded unsat result globally unreachable; symbolic execution disconnected from
the captured state.

**Implementation evidence (2026-09-17):** The bounded x86-64 instruction-trace
lane meets this exit gate on the representative corpus. A production-owned
validator materializes the proposed byte patch, creates a distinct capture of
the exact binary, and joins the observed edge or crash class back to the
proposal without rewriting either execution. `memory_index_write` and
`danger_command_argument` validate consequence-bearing neighboring inputs;
`crash_null_write` validates a neighboring input as a real null-write core at
the predicted LLIR store. A two-branch command fixture also proves bounded
unsatisfiability while retaining the exact observed-prefix and negated-target
operation identities. SAT, UNSAT, and solver-returned unknown queries state
event, instruction-count, symbolic-byte, memory-snapshot, captured-byte, and
solver-time bounds. Pre-query unknowns explicitly state `not_constructed`
rather than implying that a bounded proposition was solved.

Axeyum is the authoritative solver for every SAT/SMT proposition in this
programme. Other solvers may appear only in explicitly labelled comparison
lanes and never supply the accepted witness or verdict.

## Objective 11 — Multi-process and concurrent causality

**Outcome:** Evidence can cross process and thread boundaries without collapsing
identity or inventing order.

Required capability:

- parent/child and execution-image transitions;
- descriptor, mapping, and input lineage across supported inheritance;
- per-thread occurrences and synchronization relations;
- race-aware memory evidence; and
- findings that cite the causal chain and its gaps.

**Exit evidence:** `normal_fork_wait` and `danger_fork_tree`, plus at least one
purpose-built threaded fixture, preserve resource and event identity across the
process tree. A deliberately unordered race remains a set of possible orders
unless the provider proves one.

**Does not count:** Grouping by PID; sorting all events by wall clock; attributing
a child event directly to the parent's static call site.

## Objective 12 — Model portability

**Outcome:** A second architecture and a second acquisition provider reuse the
same semantic, capsule, correlation, finding, and query models without parallel
implementations.

Required capability:

- target-defined storage projections rather than x86 register-name logic;
- provider-neutral sparse memory, registers, mappings, events, and completeness;
- format/provider extensions behind stable required fields; and
- unchanged analyst-facing queries and evidence packets.

**Exit evidence:** Linux AArch64 and one independent provider—such as a trace
backend or a platform dump format—pass a declared subset of the same objective
gates. Differences appear as capabilities and completeness, not forked models.

**Does not count:** Serializing provider-native records inside an opaque field;
copying the x86/Linux model and renaming types; a second report generator over a
separate analyzer.

## Objective 13 — Real-world investigative closure

**Outcome:** The system resolves previously unseen, non-fixture investigations
with reproducible evidence and materially less manual stitching than existing
decompiler-plus-debugger workflows.

Required capability:

- stripped and optimized binaries;
- shared libraries and multiple module instances;
- partial, hostile, and privacy-sensitive artifacts;
- analyst corrections that preserve provenance and deterministically update
  dependent results;
- stable JSON and navigable human reports; and
- performance and resource budgets suitable for routine use.

**Exit evidence:** A blinded corpus of real crashes, corruption defects, and
dangerous behaviours is adjudicated against independent ground truth. Results
report precision, supported coverage, incompleteness, time, and resource cost
over one fixed population. At least one investigation demonstrates a semantic
runtime-to-decompiler connection that Ghidra/IDA-style address correlation
alone does not provide.

**Does not count:** Curated demonstrations chosen after seeing the result;
fixture-only success; counting unsupported cases as correct abstentions without
reporting supported coverage; subjective claims that the pseudocode “helped.”

## Programme scorecard

Every objective reports the same dimensions:

| dimension | question |
|---|---|
| correctness | Did the result match an independent semantic oracle? |
| specificity | Did good and wrong-evidence controls remain clean? |
| identity | Are build, process, thread, mapping, occurrence, and byte origins proved? |
| completeness | Are absent, lost, denied, raced, unsupported, and bounded evidence explicit? |
| reproducibility | Can a fresh process import the artifacts and reproduce stable output? |
| provenance | Can every assertion be traced through its derivation to source evidence? |
| portability | Does the capability depend on one provider, target, compiler, or fixture convention? |
| cost | Are capture pause, artifact size, analysis time, query latency, and peak memory measured? |

A headline success rate is insufficient. The scorecard always includes the
fixed denominator, supported subset, abstentions, false positives, and evidence
loss.

## Ordering and stopping discipline

The objectives are intentionally ordered:

```text
truth
  → artifact
  → identity
  → crash localization
  → decompiler semantics
  → provider equivalence
  → dynamic objects
  → OS context
  → temporal semantics
  → replay
  → counterfactuals
  → concurrency
  → portability
  → real-world closure
```

Work may prototype a higher rung to test an interface, but the programme does
not claim that rung until every dependency has passed. If a higher-rung
prototype requires weakening an earlier identity, provenance, or completeness
contract, stop and repair the model rather than adding an exception.

This is the central lesson from prior systems: putting a debugger beside a
decompiler is achievable; preserving semantic identity and epistemic honesty
across static possibility, one concrete execution, temporal history, replay,
and bounded alternatives is the hard problem. The ladder exists to make sure
Glaurung solves that problem rather than merely reproducing the interface.
