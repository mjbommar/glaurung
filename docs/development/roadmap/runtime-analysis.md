# Runtime and hybrid analysis roadmap

> **Kind:** plan · **Status:** proposed

This is the implementation roadmap for turning Glaurung's static binary,
concrete-execution, symbolic-execution, and persistent-project foundations into
a runtime-aware analysis product. Its executable baseline is the 60-program C
corpus in [`tests/runtime_samples`](../../../tests/runtime_samples/README.md),
landed at `bffa6dd2` on 2026-09-15.

The [hybrid analysis objective ladder](../../design/hybrid-analysis-data-model/objective-ladder.md)
defines the successively harder outcomes this work must prove. This roadmap is
the work order; the ladder is the capability and evidence contract.

The corpus is a test instrument, not the feature. Today Glaurung can compile,
run, stop, and capture process metadata for the samples, and can obtain a core
file when the host permits it. It does **not** yet import those artifacts into
`ProgramSession`, read live memory, normalize runtime addresses, reconstruct a
fault, track input bytes, or emit a runtime-backed security finding. A roadmap
item is complete only when a shipping Glaurung surface consumes the evidence.

This plan does not authorize tracing an unrelated process, collecting secrets,
or deploying unfinished acquisition code on production systems. All initial
work uses processes launched by the fixture harness.

## Product thesis

The target is a **hybrid analysis session**:

```text
static ProgramImage ─┐
                     ├─ ProgramSession ─ facts ─ findings ─ evidence packet
runtime capsule ─────┘         │
                               ├─ concrete replay
observed events ────────────────┤
                               └─ bounded symbolic alternatives
```

Static evidence says what may exist. Runtime evidence says what one execution
observed. Symbolic reasoning says what a bounded model can prove feasible,
infeasible, or unknown. These claims must never be silently substituted for one
another.

The first complete use case is:

> Given a stripped Linux x86-64 PIE, a controlled input, and either a stopped
> process or core dump, identify the runtime fault or dangerous operation,
> normalize it to the static image, explain the relevant memory and control
> context, and emit a reproducible evidence packet with explicit unknowns.

## Baseline and current evidence

### Corpus

The corpus has four equal populations. Every source has a `good` control and a
`bad` scenario.

| population | count | purpose |
|---|---:|---|
| Normal behavior | 15 | Establish specificity across files, mappings, pipes, sockets, descriptors, environment, heap, processes, and standard input |
| Deterministic crashes | 15 | Exercise signals, fault addresses, protection failures, invalid control flow, assertion/abort, and stack exhaustion |
| Memory corruption | 15 | Exercise non-crashing overwrites, unsafe copies, integer sizing, indexing, stale pointers, and overlapping copies |
| Dangerous behavior | 15 | Exercise paths, command/format arguments, executable mappings, dynamic loading, permissions, temporary files, allocation, IOCTL, listening sockets, and process trees |

The authoritative inventory and process-level exit/signal oracles are in
[`manifest.toml`](../../../tests/runtime_samples/manifest.toml). Sources are in
[`src/`](../../../tests/runtime_samples/src/).

### Harness

[`tools/runtime_sample_harness.py`](../../../tools/runtime_sample_harness.py)
currently provides:

- GCC and Clang builds;
- `-O0`, `-O1`, `-O2`, `-O3`, `-Og`, and `-Os` selection;
- PIE, non-PIE, and optional static linking;
- paired good/bad execution;
- process-level exit/signal verification;
- entry and exit `SIGSTOP` checkpoints;
- `/proc` maps, status, stat, command line, auxiliary vector, and descriptor
  capture;
- environment-name/value-length/value-hash capture without plaintext values;
- core-file capture with an explicit no-core result when host policy redirects
  or suppresses the dump.

The verified baseline is 960 executions: 60 samples × 2 scenarios × GCC/Clang
× `-O0`/`-O2` × PIE/non-PIE, with no process-oracle mismatch. Two consecutive
current-tree ledgers were byte-identical at
`d7f0478cb7c51c865be09ab40faf0545fc612ebce0c6bb675c102d1452adb7b9` using
`uv run python tools/runtime_sample_harness.py matrix`. One real
`crash_null_write` core and both exit-checkpoint and entry-checkpoint live
captures were also exercised. This proves the workload and harness baseline,
not any analyzer claim.

### Existing Glaurung components to reuse

| existing component | role in this plan |
|---|---|
| `program::ProgramImage` | Static object bytes, target, sections, mappings, symbols, and relocations |
| `program::ProgramSession` | Owner of image-scoped functions, call graph, types, symbols, and environment |
| `analysis::MemoryView` | Common bounded-read seam for file and runtime memory |
| `analysis::{cfg,xrefs,dispatch}` | Static program structure to correlate with observations |
| `exec::Machine` and `exec::Memory` | Deterministic concrete replay substrate |
| `symbolic::{explore,solver}` | Bounded alternative-path and input reasoning |
| `.glaurung` knowledge base | Persistence, provenance, manual precedence, and analyst workflow |
| LLM findings pipeline | Consumer of structured evidence after deterministic analysis exists |

Do not create parallel symbol, type, address, or finding systems for runtime
analysis.

## Required claim vocabulary

Every runtime-facing record carries a claim kind:

| kind | meaning |
|---|---|
| `observed` | Directly present in a captured process, core, or trace |
| `static` | Derived solely from the file image or static analysis |
| `replayed` | Produced by deterministic execution from a captured state |
| `symbolic` | Proved within an explicit bounded symbolic model |
| `inferred` | Joined or interpreted from other facts, with the derivation named |
| `unknown` | Required evidence was absent, ambiguous, unsupported, or outside budget |

“Not observed” is not “unreachable.” “Observed once” is not “the only target.”
“Solver feasible” is not “executed.” A missing page, register, module identity,
or event must produce an incomplete/unknown result rather than fabricated
context.

## Canonical data model

The [hybrid analysis data-model design](../../design/hybrid-analysis-data-model/README.md)
defines the reuse boundary behind this roadmap: static and runtime analysis
share a semantic kernel and explicit evidence relations, but retain separate
image, execution, address, memory, time, and completeness records.

### Process capsule

One versioned, deterministic capsule format must represent live and postmortem
inputs:

```text
ProcessCapsule
  identity
    schema version, capture id, host/kernel/architecture
    executable identity and SHA-256
    acquisition mode and timestamps
  processes
    pid/tid relationships and terminal state
  modules
    path identity, build id, file hash, load bias, mapped ranges
  mappings
    VA range, R/W/X permissions, file offset, backing identity
  threads
    register set, signal/fault state, stack mapping
  pages
    sparse captured bytes, permissions, content hash, omission reason
  descriptors
    type and non-secret metadata
  events
    ordered optional syscall/block/call/memory/mapping events
  provenance
    producer, command, toolchain, source artifact hashes, warnings
  completeness
    what was requested, captured, omitted, denied, truncated, or lost
```

The same Rust structures must be produced by live `/proc` acquisition, ELF core
import, and later trace import. Format-specific details may remain attached as
extensions, but analyzers consume the canonical model.

### Address identity

Every address-bearing fact retains:

- raw runtime virtual address;
- process and mapping identity;
- module identity when resolvable;
- normalized module-relative address;
- static image address when the mapping can be proven;
- file offset when backed by captured/file bytes;
- resolution status and ambiguity reason.

ASLR subtraction alone is insufficient. Resolution must account for PIE,
non-PIE images, split mappings, file offsets, deleted/replaced files, anonymous
executable memory, overlapping aliases, and mappings whose captured bytes no
longer match the file.

### Runtime memory view

Add a read-only runtime implementation of `MemoryView` over sparse capsule
pages. Reads crossing absent pages, permission boundaries, or overflow must
return structured incompleteness. Static code may fill an omitted runtime page
only when the consumer explicitly asks for a file fallback and the mapping's
identity and bytes are still proven.

The first read-only implementation has landed in the
[runtime memory view](../../architecture/runtime-memory-view.md). It supports
process-scoped reads across adjacent captured pages in one mapping, validates
payload identity, and preserves typed absence, omission, ambiguity, permission,
boundary, and overflow failures. The shared `MemoryView` adapter is available
for existing analyses. Explicit static fallback and a public product surface
remain open.

### Event schema

The first event schema covers:

- process/thread start and exit;
- module/map/unmap/protection changes;
- signal delivery and terminal fault;
- syscall entry and exit;
- basic-block and call observations;
- indirect control targets;
- selected memory reads/writes;
- capture/checkpoint markers.

Events carry process, thread, sequence, address identity, acquisition source,
and loss/truncation counters. Wall-clock order is metadata; per-thread sequence
and explicit synchronization are the correctness basis.

## Workstreams

### W0 — Corpus authority and semantic oracles

The current manifest proves only process outcome. Extend it without embedding
answers into the analyzer input.

- [x] Version a semantic-oracle schema separate from runtime capture data.
- [x] Record expected signal/fault class and relevant source object for every
  crash case.
- [x] Record expected changed object, byte interval, original value, and final
  value for every silent-corruption case.
- [x] Record source, sink, and required OS event for every dangerous case.
- [x] Add negative assertions for every good scenario.
- [x] Record which oracle is independent for every populated assertion: guard page, canary, wait status,
  sanitizer build, source/DWARF truth, or kernel result.
- [x] Add fixture IDs and schema validation to the harness.
- [x] Emit a deterministic matrix ledger rather than only terminal JSON.
- [x] Fail if a requested compiler/link lane is silently absent.

**Exit:** all 120 scenarios have machine-readable semantic expectations and an
independent oracle; regenerating the matrix ledger is deterministic.

All 120 scenarios are now populated. The evaluator-only authority is
[`semantic-oracles.toml`](../../../tests/runtime_samples/semantic-oracles.toml),
and `tools/runtime_sample_harness.py matrix --ledger PATH` emits
`glaurung-runtime-matrix-ledger-v1`. Matrix selection requires complete oracle
coverage and the current 960-cell ledger is byte-deterministic. The full W0
exit remains open because memory and OS-event analyzers do not yet emit the
full semantic result population. The post-analysis
`glaurung-runtime-semantic-result-v1` evaluator is implemented: it compares
exact active-lane facts, preserves observed, inferred, static, replayed, and
symbolic claim kinds, treats unknown/unavailable/unsupported evidence as
incomplete, and has mutation gates for crash, memory, dangerous-resource,
normal, and lane-selection facts. Oracle-independent producers now emit
wait-status and bounded `RESULT` stdout facts. The typed crash analyzer also
projects its signal, inferred class, access direction, and fault target without
reading the oracle. For exact null reads and writes, the semantic producer now
joins the observed zero target and proven direction to exactly one matching
LLIR load/store width; incomplete or ambiguous joins remain unsupported. The
real 15-core gate proves that the crash cases satisfy their complete semantic
expectations through these produced facts rather than hand-assembled passing
records, and rejects a mutation of the produced null-read width. A bounded
normally-exiting mapping-trace producer now derives the expected
`RW->unmapped` and `RW->RX->unmapped` histories for `danger_rw_to_rx`; it keeps
execution-of-bytes explicitly unsupported. The same native report detects an
initial RWX mapping, and produced facts fully satisfy both
`danger_rwx_mapping` controls. Mutating a produced history makes oracle
evaluation fail. The first redacted-by-default file-event producer also makes
both `normal_open_file` scenarios pass completely from authorized path plus
descriptor/errno evidence; unrelated loader paths remain private.
The first process-event producer normalizes process-creating
`fork`/`vfork`/`clone`/`clone3` results separately from thread clones and joins
successful `wait4` results back to the created child OS identities. Complete,
coherent event sets satisfy both `danger_fork_tree` oracles for one and three
children; a mutated count and an unknown reap identity fail closed. It does not
manufacture child process snapshots from parent-side syscall observations. A
typed Rust behavior report now owns normalization after acquisition, and the
semantic producer consumes that report rather than reparsing capsule events;
stale completeness counts are rejected.
The first logical-memory producer now projects the DWARF-backed
`memory_read_overflow` pair without reading the oracle. Same-execution
before/after snapshots produce the exact `dst` changed interval, unchanged good
canary, bad canary changed interval, and bad `stack_object:box.dst`
`bounds_violation`. Those facts satisfy both scenarios across the default
8-lane build matrix, and mutating the produced length fails evaluation. The
full W0 exit remains incomplete because the other memory and OS-event
populations do not yet have complete analyzer-produced semantic results.

### W1 — Capsule schema and acquisition contract

The first Rust metadata contract is implemented in
`src/runtime_analysis/capsule.rs` and documented in the
[runtime process capsule architecture](../../architecture/runtime-process-capsule.md).
It provides validated canonical JSON, external sensitive-payload references,
extensions, completeness, and import budgets. The stopped-child harness now
exports this model through the Rust Python binding with atomic publication and
an exact main-executable mapping. The core path also stores sensitive page
payloads separately with ID, length, and hash verification. JSON and CBOR share
one validated model and normalization path. The documented hostile-input matrix
covers encoding, graph, identity, filesystem bundle, and resource-budget
failures.

- [x] Specify `glaurung-process-capsule-v1` and JSON/CBOR serialization rules.
- [x] Separate public metadata from sensitive page/environment payloads for
  procfs metadata and ELF-core page bytes.
- [x] Hash every captured artifact and bind the manifest to exact binary and
  input bytes for the current live-procfs and ELF-core providers.
- [x] Record requested-versus-obtained completeness.
- [x] Make capsule publication atomic: an invalid partial file is never the
  published `process-capsule.json`.
- [x] Add size/count budgets for pages, mappings, threads, descriptors, and
  events.
- [x] Reject path traversal, symlink substitution, oversized lengths, missing
  and extra payloads, and hash disagreement during bundle import.
- [x] Preserve unknown schema extensions while rejecting unsupported required
  features.

**Exit:** the harness exports a capsule, a Rust importer round-trips it
byte-deterministically, and malformed/truncated negative fixtures fail closed.
The JSON bundle path meets this exit shape for a real core and explicit tamper
variants. CBOR has deterministic round-trip, cross-format equivalence,
truncation, trailing-data, and budget tests. A live/core pair built from the
same exact executable agrees on stable target, executable, module-artifact, and
invocation-input identities while retaining provider-specific terminal facts.

### W2 — ELF core importer

Start postmortem because it is reproducible and CI-friendly.

- [x] Parse Linux x86-64 ELF core architecture and program headers.
- [x] Import `NT_PRSTATUS`, signal information, auxiliary vector, file mappings,
  and available FP/vector register notes.
- [x] Build sparse runtime pages from `PT_LOAD` segments.
- [x] Reconcile `NT_FILE` main mappings with the exact executable using path
  plus captured-byte agreement; never open core-supplied paths.
- [x] Represent missing pages and unsupported descriptor evidence explicitly.
- [x] Support multiple threads and identify the faulting thread through Linux's
  `NT_SIGINFO`/thread-note grouping rather than signal-number matching or
  process-leader identity; the real `threaded_worker_fault.c` core is the gate.
- [x] Import the real core generated by `crash_null_write` as the first fixture.

**Exit:** all 15 bad crash scenarios produce importable cores where host policy
permits; each imported capsule identifies the expected terminal signal, and
missing-core hosts report a skip/not-evidence state rather than pass.

The Linux x86-64 W2 exit is exercised in the GCC `-O0` PIE lane by:

```bash
uv run pytest \
  python/tests/test_runtime_sample_harness.py::test_all_bad_crash_cores_import_with_expected_signal \
  -m slow -q
```

On a host that emits cores, the gate requires all 15 rather than accepting a
partial population. On a host that suppresses every core it reports a skip,
not a pass. Provider breadth and live/core equivalence remain later objectives.

### W3 — Live Linux acquisition

Limit v1 to a child process launched by Glaurung on Linux x86-64.

The first product surface is
`glaurung.runtime_capture.capture_stopped_child`. It launches a cooperative
child in a new process group and has no PID-attach entry point. A real corpus
fixture proves canonical capsule output, mapping/thread revalidation, bounded
redacted descriptors, complete single- and multi-thread x86-64 register sets,
bounded hash-verified PC/SP page payloads, and owned-group cleanup. Broader page
selection and detailed partial-failure records remain open. Both live providers
now use the core importer's Rust ELF parser
and agree with core acquisition on the exact main executable's GNU build ID and
SHA-256. The product provider also captures bounded loader/library backing
files through `map_files` or an `O_NOFOLLOW` path whose device/inode is
revalidated against the mapping, then records their hashes, build IDs, module
instances, and provenance. Unavailable backings remain explicit partial
evidence.

The population exit now passes 210 GCC `-O0` PIE cells: good and bad entry
captures for all 60 samples plus good and bad exit captures for all 45
non-crashing samples. The gate asserts its denominator and canonical output.
Two independent captures also differ as raw artifacts while matching the
documented `glaurung-live-capture-stable-facts-v1` projection. Granular
acquisition outcomes are independently keyed by proc artifact, TID, page,
backing identity, mapping revalidation, thread-set revalidation, and descriptor
collection, with denied, disappeared, partial, raced, truncated, and unknown
states kept distinct.

- [x] Promote current `/proc` capture into Rust/Python product code.
- [x] Capture all threads and register sets at one stopped checkpoint.
- [x] Read selected pages through `process_vm_readv` with `/proc/<pid>/mem` only
  as an explicit fallback.
- [x] Revalidate mappings before and after reads to detect races.
- [x] Capture module build IDs and backing-file hashes.
- [x] Bound descriptor metadata and redact sensitive values by default.
- [x] Terminate/resume only the child process tree owned by the capture session.
- [x] Record permission denial, disappeared threads, partial reads, and changed
  mappings independently.
- [x] Never offer arbitrary PID attach in the first product milestone.

**Exit:** every sample supports an entry capsule; all non-crashing samples
support an exit capsule; repeated captures normalize to the same stable facts
after volatile fields are excluded.

### W4 — Runtime/static correlation

The first address primitive is implemented in the
[runtime-to-static correlation architecture](../../architecture/runtime-static-correlation.md).
It joins a capsule mapping/module to an immutable `ProgramImage` only through
SHA-256, optional build ID, and checked file-offset translation. Wrong images,
overlapping mappings, absent mappings, and omitted/modified bytes remain typed
outcomes. A real-core gate now exercises `crash_null_write` across GCC/Clang,
`-O0`/`-O2`, and PIE/non-PIE, proving exact PC normalization through split ELF
mappings and rejecting a different same-lane build in all eight cells.
The resolved static VA is also joined to the immutable `ProgramImage`
`.eh_frame` index with an explicit exact/interior/ambiguous/missing function
verdict, then to a targeted static CFG and decoded instruction. The code
relation preserves resolved, ambiguous, incomplete, and missing outcomes so a
budget-truncated CFG is not reported as absence. Source-addressed LLIR
operations are attached as static relations with distinct lifted, empty, and
unavailable outcomes; every matrix null-write PC maps to a `store` operation.
Explicit `RuntimeModule`, `RuntimeMapping`, and `RuntimeAddress` correlation
endpoints now project one capsule process without adding runtime state to
`ProgramImage`; module membership remains optional for anonymous and special
mappings. The graph is available through a shipping Python API. A second typed
relation compares hash-verified complete page payloads with the exact static
artifact and distinguishes unchanged, modified, anonymous, and unknown backing
without path inference or static-byte substitution. Its real live gate captures
bounded main-executable code pages, while Rust negative controls cover a
one-byte modification and unknown backing.
Exact address relations can now be written to a `.glaurung` project through
`resolve_and_persist_address`. The API performs native correlation itself,
checks the resulting image identity against the project binary, and stores the
capture, process, mapping, module, raw VA, file offset, static VA, and
module-relative address as one append-only inferred relation. Re-import is
idempotent, separate captures do not collide, and static annotations are not a
write target. The real eight-lane null-write gate proves persistence across
close/reopen and preserves a manual comment at the same static VA.
Observed indirect calls and jumps now produce separate occurrence-scoped
target relations. Each retains process, thread, event sequence, raw runtime
successor, exact source and target resolution, immutable LLIR operation
identity, and an `OperationOccurrence`. A volatile function-pointer fixture
proves one exact indirect call across GCC/Clang, `-O0`/`-O2`, and PIE/non-PIE.
GCC also exposes a distinct incidental indirect jump in the same trace; Clang
does not, confirming that the gate does not depend on compiler-specific extra
transfers. Replacing the call successor with an unmapped address makes both
the target and occurrence unknown. The exact relation persists through the
ordinary runtime project report/occurrence path. It is deliberately not added
to `ProgramEnvironment` or the static CFG: one observed target is evidence for
one execution, never an exhaustive static target set.
The instruction-trace report now also carries an explicit
`main_image_address_coverage` denominator. It selects mappings only through the
exact analyzed-image content identity, counts every instruction-step PC in
those mappings, resolves each through the ordinary correlation path, and lists
every non-exact result rather than dropping it. Across the eight-cell indirect
target matrix, every captured analyzed-image PC resolved exactly and every
failure list was empty. Supplying a one-byte-different image makes the coverage
unknown rather than producing a vacuous zero-step pass. Together with the
existing eight-cell different-build rejection, this closes the stated W4
fixture exit. The remaining Objective 2 controls are now explicit Rust gates:
a same-basename different-content image is rejected; overlapping aliases are
ambiguous; disjoint duplicate loads preserve distinct module/mapping/raw
identities while sharing the static VA; missing and omitted pages retain typed
absence; and authenticated changed or invalid code bytes withhold static code
and LLIR semantics. This also closes the stated Objective 2 exit without
claiming that missing runtime bytes were observed.

- [x] Add `RuntimeModule`, `RuntimeMapping`, and `RuntimeAddress` to the program
  model.
- [x] Join a runtime module to `ProgramImage` by build ID and content identity,
  not basename.
- [x] Normalize PIE and non-PIE addresses across split mappings.
- [x] Distinguish file-backed unchanged, file-backed modified, anonymous, and
  unknown pages.
- [x] Resolve runtime PCs to static functions/basic blocks with an explicit
  exact/interior/ambiguous/missing verdict.
- [x] Feed observed indirect targets into the program environment as evidence,
  not exhaustive truth.
- [x] Persist both raw and normalized addresses in the KB.

**Exit:** across GCC/Clang, `-O0`/`-O2`, and PIE/non-PIE lanes, every captured
main-module PC used by a fixture maps to the correct exact build and static
function; deliberate wrong-build controls are rejected. **Closed:** the
eight-cell indirect-target trace supplies the complete PC denominator, and the
null-write matrix supplies independent different-build rejection.

### W5 — Crash reconstruction

Deliver the first end-to-end product workflow here.

The first [runtime crash report](../../architecture/runtime-crash-report.md)
now joins a core capsule to the exact image and emits typed JSON. Across the
eight-lane `crash_null_write` matrix it identifies the observed fault context,
resolves the exact static instruction and LLIR store, infers write access, and
classifies the unmapped zero target as `null_write`. The semantic-result
projection preserves that separation while joining the observed null target
and direction to the unique matching LLIR load/store width. The 15-core GCC
`-O0` PIE gate additionally proves all 15 evidence-backed null, protection, invalid
control-target, recursive-stack-exhaustion, self-generated-signal, failed
assertion, and explicit-abort classes, plus the precise null-read semantic fact;
mutating its produced width is rejected. Explicit abort requires a captured stack
return from a direct static call to the relocation-backed `abort@plt`; an empty
stderr stream is not evidence. Intentional guard-page role is proved only for
the child-owned traced-core provider: a successful anonymous read/write
`mapping_create` event must precede a successful `mapping_protect` to no access
on the same thread and both ranges must contain the fault address. Removing the
events weakens the same report back to a generic protection fault. A core-only
snapshot therefore remains generic rather than acquiring intent from final
`PROT_NONE` permissions, adjacency, page size, or anonymous backing. This is the
first narrow consumer of W7 mapping events; it does not complete the broader W7
mapping/protection workstream.

- [x] Identify faulting process, thread, signal, PC, SP, and architecture.
- [x] Classify read/write/execute protection faults where evidence permits.
- [x] Render the containing module, function, block, and instruction in the
  typed JSON report and deterministic analyst-readable text.
- [x] Show the bounded faulting-thread register set and fixed-size memory
  windows around PC, SP, and the fault address, with sparse-read failures kept
  explicit.
- [x] Recover a bounded x86-64 frame-pointer stack with per-frame confidence,
  exact location attempts, ABI bounds, and an explicit stop reason; CFI and
  additional architectures remain later breadth work.
- [x] Distinguish explicit self-generated signals, failed assertion, bad
  control target, execute-protection fault, and recursive stack exhaustion.
- [x] Prove explicit abort separately from other self-generated `SIGABRT`.
- [x] Prove guard-page role separately from a generic inaccessible mapping.
- [x] Compare independently analyzed bad and completed good-control capsules
  under one exact image, preserving an unknown bad class rather than upgrading
  it through contrast.
- [x] Emit typed JSON and deterministic analyst-readable evidence packets,
  with sensitive memory and process-output contents redacted from text.

**Primary samples:** all `crash_*` cases.

**Exit:** the 15 bad crash cases receive their correct crash class, all 15 good
controls receive no crash finding, and every asserted frame/address cites its
source artifact and resolution confidence.

The GCC `-O0` PIE gate covers all 15 bad cores and independently executed good
controls. The two guard cases add real traced-core runs because the core alone
cannot contain their creation history. Together these gates satisfy the first
Linux x86-64 W5 exit; compiler/optimization breadth beyond the null-write matrix
and CFI unwinding remain later coverage rather than stronger claims about the
available evidence.

### W6 — Memory-object and corruption analysis

Non-crashing corruption requires observation beyond terminal process status.

The canonical capsule now has runtime-object and object-snapshot records.
Runtime objects retain process, optional mapping, kind, concrete extent, and
event-scoped creation/destruction positions. Snapshots retain object-relative
intervals, event positions, and external hash-bound payloads under independent
count and byte budgets.

The first real provider is deliberately narrow: a caller-supplied, hash-bound
glibc interposer records bounded `calloc` creation bytes and final bytes at
`free` for one launched child. It also emits bounded `memory_write` events for
`memset` destinations within a live observed object. It uses fixed provider
storage, reports dropped records, does not inspect allocator metadata, and has
no PID-attach surface.
`glaurung-runtime-object-change-report-v1` compares ordered, hash-verified
snapshots by runtime object. The real `memory_heap_canary_overwrite` gate sees
the good write at object interval `7..12` and the bad write at `8..12`. It leaves
the responsible operation explicitly unknown because that object-change input
has no bounded write event. A later instruction-trace relation, described
below, independently captures the direct store occurrence; the aggregate diff
is not retroactively attributed to an event absent from this input. A second
real gate covers
`memory_underallocation`: the bad run's exact changed interval `0..16` is
covered by one observed 16-byte `memory_write` event, while the good run's
additional independently written bytes prevent false whole-change attribution.
In real PIE and non-PIE lanes, the observed interposed-call return address and
loader-reported main-module load bias also resolve to the exact static call
instruction and stable LLIR `call` operation. Wrong-image and tampered-bias
controls preserve the observed write but make this inferred relation unknown.
The object-change report now completes that join as an `OperationOccurrence`:
the observed destination and length are occurrence inputs, and a distinct
runtime-object effect carries the concrete address, length, and object ID.
The uncaptured call return stays unknown. The provider now also records exact
`calloc` arguments and caller identity. Creation and write calls become
separate operation occurrences over the same runtime object. A bounded
allocation-argument slice identifies `Load(n) + 8`, joins the load to one DWARF
scalar, and preserves the resulting prefix/tail split without shrinking the
allocator object. Across eight GCC/Clang `-O0` PIE/non-PIE good/bad cells, the
good write stays within a 16-byte prefix of a 24-byte object and the bad write
crosses an eight-byte prefix by eight bytes inside a 16-byte object. The bad
logical-allocation bounds oracle is now produced from that typed relation.
The combined provider now identifies one bounded allocator object at trace
begin, and acquisition reads that exact object at trace begin, trace end, and
post-trace while the child is stopped. The object-change report relates those
checkpoint snapshots to the exact interposed `memset` occurrence. This separate
typed transition preserves prefix and reserved-tail changes independently.
Across the same eight lanes it proves the good prefix changed from zero to `aa`
while the tail stayed `0x24681357`, and that the bad prefix and tail both changed.
The good prefix semantic oracle now comes from this transition. A write after
destruction retains ended-object identity but cannot create a post-lifetime
snapshot. A bounded instruction trace now closes the adjacent-canary side in a
single capture. A separate all-store stream resolves the direct four-byte
initialization even though it has no stack delta, evaluates its concrete heap
address, and joins its bounded address slice to the DWARF pointer local
`canary`. The allocator interposer now participates in that same launched-child
capture: allocation, trace-begin snapshot, direct-store trace, trace-end
snapshot, `memset` occurrence, post-trace snapshot, and deallocation share one
ordered event stream and capture identity. All eight lanes produce both the
logical-allocation and canary semantic assertions from that capsule; stripped
DWARF preserves the occurrence and bytes but withholds source identity. The
bounded implementation accepts exactly one complete main-module object chain
and fails closed otherwise. A real two-object launched-child negative proves
that an extra complete or incomplete main-module allocation cannot be silently
ignored, and a zero-object negative proves that requested heap evidence cannot
silently disappear. The API also rejects simultaneous generic `[heap]` mapping
capture, which would create overlapping object representations. A worker-owned
object-chain negative additionally prevents process membership from being
substituted for exact thread identity. Provider-stream byte high-water marks at
trace begin, trace end, post-trace, and termination now prove each provider
record's checkpoint phase; a wrong-phase fixture rejects a locally ordered but
temporally incompatible chain.
The checkpoint snapshot path is no longer shaped around an interposed write.
`memory_heap_canary_overwrite` contributes a second eight-lane gate with zero
provider write records. Its direct indexed byte store resolves to the exact
allocator object, before/store/final bytes, and the unique DWARF pointer local
inside a compound `Load(p) + index` LLIR address slice. It reconstructs the
pointer local from the initial stack snapshot plus preceding ordered stack
changes, so the value is scoped to the store occurrence rather than copied into
the static variable. A second bounded slice relates the observed
`calloc(1, n + 8)` occurrence to the DWARF scalar `n`. Together they preserve a
16-byte allocator object while classifying the offset-seven store within an
eight-byte logical prefix and the offset-eight store as crossing that prefix by
one byte. The semantic projection now satisfies the good `p[7]` changed-byte
oracle and the bad indexed-bounds oracle in all eight lanes. A distinct
allocation-tail relation then reconstructs the fixed-width DWARF pointer locals
at the store occurrence and selects the unique value equal to the derived tail
start. This proves `canary` at object offset eight and relates its four-byte
before/store/final history without deriving identity from its name. Both
semantic oracles now match in every good and bad lane. The object diff remains
explicitly unattributed because no provider write event exists. Missing
trace-end bytes, initial stack bytes, and DWARF are separate negative controls
which withhold only the dependent transition, pointer, prefix, or tail
conclusions. Other pointee types and storage forms remain open.
The oracle-independent `memory_interval_semantic_result` producer now projects
these logical changed intervals, bounds violations, and tail-pointer byte facts
from the instruction-trace report. Its name reflects the semantic capability,
not the acquisition mechanism; the older instruction-store name remains as a
compatibility wrapper. A mutation gate changes the index in a real produced
record and proves that the independent evaluator rejects it.
Input, IOCTL, and heap-write producers now share one canonical occurrence-ID
constructor. It binds capture/process/thread/event scope to exact image,
function, LLIR block, operation index, and operation kind, and rejects
cross-process or absent event/object identities.

The first direct-store case uses a second acquisition mechanism.
`capture_instruction_trace_child` single-steps an owned Linux x86-64 child
between cooperative checkpoints under a 4,096-step budget. Per-step changed
bytes are external sensitive payloads, not public event fields. For GCC and
Clang `-O0`, in both PIE and non-PIE forms, all eight good/bad cells resolve the observed
one-byte transition to an exact LLIR `store` occurrence. The existing DWARF
relation identifies `b.data[7]` in the good run and the first byte of
`b.canary` in the bad run. Missing change payload and wrong-image controls
become unknown. The trace payload now keeps pre-instruction registers outside
public metadata, while each static LLIR operation retains an optional bounded
address-expression slice. Evaluating that slice against observed registers and
sparse memory proves that both stores are based on `b.data`: index seven is
within bounds, while index eight crosses by one byte into the concrete
destination field `b.canary`. The semantic producer now satisfies both complete
good/bad oracles without reading them in all eight cells. Clang `-O2` is an
explicit boundary rather than a claimed pass: the compiler represents the
logical result in a register, no matching stack-byte transition is observed,
and the report scopes that absence to its fixed stack window while marking
broader runtime state partial. This is not broad index classification across
the corpus or a runtime object for source storage optimized out of memory.
The same gate now covers a second shape, `memory_index_write`, across another
eight GCC/Clang `-O0` PIE/non-PIE cells. A four-byte store derives `a[3]` as
within the four-element `uint32_t` array and `a[4]` as crossing four bytes into
the concrete `canary` destination. Its semantic facts preserve four-byte
values and state `declared_elements=4`; both good/bad oracles pass without
being visible to the analyzer.
`memory_off_by_one` adds a third eight-cell gate and a multi-write interval.
Whole-field before/after evidence now survives an unknown responsible
operation, satisfying the required partial-reporting path, while duplicate
conclusions from multiple changing steps collapse deterministically. Static
stored-value provenance distinguishes the direct zero terminator from a generic
byte write and derives `terminator:index=8:declared_length=8`; concrete
destination containment still independently names `tag`.
`memory_memcpy_overflow` adds the first semantic-call shape across eight more
GCC/Clang `-O0` PIE/non-PIE cells. One bounded, hash-bound external payload now
retains pre-instruction registers for every public trace step. Exact LLIR call
targets carry static direct-target and relocation-proven import identity, while
SysV destination, source, and length remain occurrence-scoped observations.
The resulting `memcpy` occurrence names the concrete stack-mapping effect; the
existing DWARF relation derives `box.dst` and reports the bad 12-byte copy
crossing its eight-byte bound into the independently changed `canary` bytes.
Missing payload and sequence/address disagreement controls fail closed. This
proves one copy-overflow category; it does not complete the remaining copy,
heap, global, lifetime, or overlap classes.
The same model now passes another eight cells for `memory_memmove_overflow`.
A no-inline wrapper keeps possible source/destination overlap opaque to the
compiler; without it GCC rewrites the source-level operation to `memcpy`, and
the analyzer correctly reports the binary operation rather than the oracle's
source spelling. With real `memmove` preserved, the shared occurrence and
object-bound algorithm produces the expected good and bad facts. This is not
yet temporal overlap analysis: it proves only the call, arguments, destination
effect, endpoint bytes, and field bound.
`memory_strcpy_overflow` adds another eight cells and the first implicit-length
copy. A bounded NUL scan over the hash-verified pre-call stack snapshot derives
`source_bytes`; missing bytes or no captured terminator fail closed. The
occurrence's logical write extent is deliberately distinct from snapshot byte
changes. That distinction exposed and corrected a good-case oracle which had
included an unchanged terminating zero in its `changed_interval`.
`memory_strcat_overflow` adds eight more cells and the first compound string
extent. Bounded pre-call scans independently derive the source and existing
destination lengths. The occurrence keeps append bytes, concrete write start,
and final string extent separate; its memory effect begins at the old
terminator, while the bounds oracle compares the final 12-byte string with the
eight-byte field. Removing the pre-call snapshot makes the occurrence unknown.
Internal library instruction writes remain observed in the report but cannot
manufacture a second operation-named conclusion without a proved static
operation occurrence.
`memory_sprintf_overflow` adds another eight cells without treating formatting
as copying. A fourth typed call contract requires the captured format to be
exactly `%s`, obtains the variadic source from its separate SysV register, and
derives three or 13 output bytes from the bounded source snapshot. Missing
format/source bytes and unsupported formats remain unknown. The logical effect
and DWARF field bound satisfy both oracles; the good changed-byte oracle was
corrected because its terminating zero touched already-zero storage.
`memory_overlapping_copy` adds eight cells for a semantic precondition rather
than another field bound. Exact `memmove` and `memcpy` occurrences carry the
same overlapping object-relative ranges; only `memcpy` produces an overlap
violation. The fixture's bare `char b[16]` forced a separate object-level
snapshot-change relation, so lack of a struct field no longer discards a proved
DWARF stack-object interval or fabricates a field.
`memory_stale_pointer_write` now adds the first lifetime-ordered write slice
across eight GCC/Clang `-O0` PIE/non-PIE cells. The provider preserves ended
allocation identities instead of reusing address-keyed slots, records bounded
post-write bytes, and attaches a post-`free` `memset` to the original dynamic
object. The object-change report independently retains event ordering,
object-relative range, post-write bytes, exact static callsite, and operation
occurrence. Removing the byte payload makes only the byte value unknown. A
separate `heap_object_writes` completeness record prevents lifetime or snapshot
completeness from being misused as write-stream completeness. The static LLIR
call operation now retains bounded candidate ABI-register input expressions;
each recovered position has a stable expression and semantic-value identity,
and the call target has a separate stable semantic-value identity. Indirect
target slices additionally have an expression identity; direct targets do not
invent one. Occurrence construction recomputes these identities and fails
closed on stale or forged values while keeping observed register contents
execution-scoped. The exact `memset` contract assigns destination meaning, and
the observed destination plus a unique DWARF frame-slot load prove that `p` points to the
allocation start in every lane. This relation also found and fixed Clang
pointer locals being assigned pointee width when their pointer DIE omitted an
explicit byte size. The bad semantic result now passes both stale-pointer
oracle assertions. The good result correctly remains incomplete for broad
write-after-free absence because the provider's complete write scope is
`memset`, not arbitrary stores.

The first static variable/type identity edge is now present in both a direct
store-address relation and the `memset` destination relation. DWARF extraction
retains canonical declaration and referenced-type `.debug_info` offsets; the
exact image hash plus those offsets mints separate static variable and type
IDs. These are now complete immutable IR-owned variable and type records, not
dangling strings. A separately identified graph edge links the variable to the
static semantic value that used the pointer.
Real `memory_underallocation` and `memory_stale_pointer_write` controls prove
the joins without copying runtime addresses or values into the DWARF or LLIR
records. This is the debug-proven pointer slice, not yet complete high-variable
or type-graph coverage.
`memory_integer_truncation` adds an arithmetic-to-write relation across eight
GCC/Clang `-O0` PIE/non-PIE cells. The trace begins before the source scalar is
materialized. A bounded LLIR slice retains the exact 64-bit frame load and
low-eight-bit reduction (`& 0xff` for the current x86-64 lifter), while DWARF
independently identifies the `requested` and `narrowed` locals. Occurrence-time
registers resolve GCC's RBP-relative and Clang's RSP-relative expressions to
the same concrete source objects without equating their static offsets. The
subsequent exact `memset` occurrence supplies the observed write length, and
the existing field relation supplies the eight-byte `dst` contract. The good
chain reports `8 -> 8` before a bounded eight-byte write; the bad chain reports
`265 -> 9` before a twelve-byte write crossing `dst` by four bytes. Both
semantic oracles now pass in every lane. This proves one executed narrowing and
subsequent write chain; it does not yet prove general control dependence from
the converted value to the selected call length.

- [x] Extend capsule checkpoints with selected before/after memory regions.
- [x] Add allocation events or a bounded allocator-interposition provider for
  fixture processes.
- [ ] Model stack/global/heap/mapping objects without pretending allocator
  metadata is portable.
- [x] Diff bytes by object and attribute the write instruction/event.
- [ ] Classify off-by-one, adjacent-field overwrite, copy overflow,
  under-allocation, out-of-range index, stale-pointer write, and overlap. The
  stale-pointer lifetime and source-pointer relations are proved, but broad
  write coverage remains incomplete.
- [x] Preserve “changed bytes observed, responsible instruction unknown” as a
  useful partial result.
- [x] Keep ASan/UBSan output as an independent oracle, never analyzer input.

**Primary samples:** all `memory_*` cases, plus `crash_guard_{read,write}`.

**Exit:** every bad silent-corruption scenario identifies the expected changed
object/interval or declares a specific unsupported boundary; good controls have
zero corruption findings.

### W7 — OS-context and dangerous-operation analysis

Build semantic events over a deliberately small Linux process boundary.

The first normally exiting mapping-trace surface shares the traced-core event
normalizer and capsule model. The provider-neutral
[mapping behavior report](../../architecture/runtime-mapping-behavior.md)
reconstructs exact-range lifetimes and emits inferred findings for initial RWX
permissions and writable-to-executable transitions. Real good/bad
`danger_rw_to_rx` and `danger_rwx_mapping` gates keep loader mappings separate,
keep both controls clean, and never infer byte execution from permissions.
Subrange transitions and the broader OS-resource model remain open.

The same bounded provider now normalizes `openat` into independently complete
`file_open` events. The native
[file behavior report](../../architecture/runtime-file-behavior.md) retains a
thread-scoped resource ID, flags, descriptor or errno, and redacted path
identity. Real `normal_open_file` good/bad gates fully match success and
`ENOENT` oracles while keeping loader paths redacted. The next slice links
`normal_create_file` open, creation mode, bounded authorized write bytes, and
close through one runtime resource ID. Both scenarios fully satisfy their
lifecycle and safe-creation oracles; content-identity tampering fails closed.
The path-resource slice now also normalizes `normal_stat_file` success to a
bounded file type and failure to `ENOENT`; both scenarios satisfy their oracles,
and path-identity tampering becomes unknown. The same linked-resource machinery
now covers `normal_write_file` without a new event model and derives
`normal_append_file` from `O_APPEND` plus its observed write; both scenarios for
all four file cases fully satisfy their semantic oracles. Rename, broader stat metadata,
descriptor duplication/lineage, general offset tracking, and file identity remain open, so the
combined file-normalization checkbox is not yet complete.
A bounded `chmod` slice now covers both `danger_world_writable` scenarios. The
provider retains authorized path identity, requested mode, and kernel result as
a separate path operation; the native report does not pretend it is the earlier
open resource. The good `0600` case and bad `0666` case both fully satisfy their
oracles, and malformed mode evidence fails closed. The evaluator mutation now
uses this real produced record.

The selected-read slice links `normal_read_file`'s `/dev/zero` descriptor to an
offset-zero, 16-byte all-zero result in both scenarios. Read content requires
separate caller authorization, unrelated loader reads are omitted by policy,
and content-identity tampering becomes unknown. This records bounded observed
bytes but does not claim W8 stable per-byte provenance or LLIR propagation.

The first descriptor-lineage slice covers both `normal_dup_fd` scenarios. A
`dup` creates another handle for the same runtime resource and shared
open-file-description offset; closing a handle does not end the resource while
another remains. The real gate links open, duplication, write through the new
handle, and both closes. Removing one close removes the positive chain and
weakens leak absence to unknown. `dup2`/`dup3`, inherited descriptors, pipes,
and sockets remain open.

The first non-file descriptor resource now covers both
`normal_pipe_roundtrip` scenarios through a separate provider-neutral report.
It retains one stable pipe identity, explicit read/write endpoint roles,
ordered byte transfers, and both closes. IPC content is separately authorized,
redacted by default, hash-verified when public, and bound into capture identity.
Network sockets, cross-process ownership, and richer descriptor graphs remain
open.

Both `normal_socketpair` scenarios now reuse that descriptor report with
bidirectional peer endpoints and ordered `sendto`/`recvfrom` transfers. The
result retains `AF_UNIX/SOCK_STREAM`, byte `53`, and both closes while keeping
the normal control free of a listener finding. Wrong-role mutations are
rejected. Descriptor passing, inheritance, and cross-process ownership remain
open.

The `danger_bind_listener` pair now adds `AF_INET/SOCK_STREAM` creation, bind,
scoped listen absence, and close. The good endpoint is loopback; the bad endpoint
is wildcard and receives a typed `wildcard_bind` finding. Because `listen` is in
the complete capture scope, both cases can preserve `listen_called=false`
without inferring absence from a missing event in an unrelated trace. Accepted
connections, datagrams, and broader network state remain open.

The selected-IOCTL slice now links `/dev/null` open identity to the exact
numeric request and kernel result for both `danger_ioctl_input` scenarios.
Provider-decoded `_IOC(...)` spelling is reconstructed under the bounded Linux
x86-64 ABI and unsupported spelling fails closed. The good control completely
satisfies its request and no-finding assertions. The bad execution satisfies
the observed `0xdeadbeef:result=-1` assertion but deliberately leaves
`scenario_selected->ioctl` incomplete: an observed request value does not prove
input provenance. Closing that assertion is W8 work, not a sink-name heuristic.
The trace now also retains an exact-image user return frame and a typed relation
to the decoded static call instruction and stable LLIR `call` operation. That
relation passes all eight GCC/Clang, `-O0`/`-O2`, PIE/non-PIE lanes; altered
image identity or return offsets fail closed. It remains a callsite relation,
and now also produces a stable occurrence-scoped record carrying the observed
call inputs, kernel output, and file-IOCTL effect. Input-byte provenance remains
separate and unproved.

The first typed instruction-control slice now exists for paired GCC `-O0` PIE
good/bad lanes. It locates `argv[1]` from kernel argument bounds and verifies
the bytes in captured memory, then joins it to an exact `strcmp`
occurrence and observed result, and represents each executed conditional edge
as a relation between one immutable LLIR operation and one observed successor.
LLIR def-use plus the SysV result contract identifies both the branch consuming
`strcmp` and the caller branch consuming `rs_bad`; intervening clobbers fail
closed. The selected zero or `0xdeadbeef` stack write and ioctl argument load
retain the same static frame-address expression and distinct runtime values.
`InputToCallArgumentRelation` owns the complete join; shifted input-location,
missing-payload, and wrong-successor controls become unknown. This closes the
disconnected-address gap for one lowering shape, but not yet the W8 assertion:
optimized and alternate compilers use different register, memory, and inlining
forms rather than this stack-selected form.

The next path covers GCC `-O2` without fabricating a branch or stack object.
Its conditional move is one LLIR `Ite` occurrence carrying the reaching
`strcmp` result, two static alternatives, and an observed output register. The
typed relation proves that no exactly resolved intervening operation defines
that register before ioctl and that its value equals the observed request.
Together the memory-selected and conditional-value variants pass all eight GCC
good/bad, `-O0`/`-O2`, PIE/non-PIE cells. Clang `-O0` now composes a third
variant from an occurrence-scoped call-result flow, an exact same-address
predicate spill/reload, the observed predicate return, the caller's LLIR
`Ite`, and the selected request store/load. A hash-consistent mutation of the
spill address fails closed. Clang `-O2` adds a fourth variant: the observed
`strcmp`-dependent edge reaches either an exact constant assignment or an
exact zeroing-XOR definition of the ioctl request register. Static expression
evaluation must agree with the post-step register, and that register must be
preserved to the sink. A hash-consistent post-definition mismatch fails
closed. All sixteen good/bad, GCC/Clang, `-O0`/`-O2`, PIE/non-PIE cells pass.

`instruction_trace_semantic_result` now consumes that typed relation rather
than the request value or scenario label. A trace-begin procfs descriptor
snapshot exposes only caller-allowlisted targets, so the exact ioctl
occurrence and return can be joined to `/dev/null` without claiming the earlier
open was observed. The bad `scenario_selected -> ioctl` assertion and the
good zero-request no-finding assertion both pass in all sixteen cells.
Hash-consistent mutations of either Clang propagation path suppress the
dataflow fact and fail the bad oracle.

- [ ] Normalize file open/create/stat/rename-like facts.
- [x] Normalize descriptor, pipe, socketpair, bind/listen, and IOCTL facts.
- [x] Normalize the first bounded process creation and parent-side reap
  relationship; child snapshots, recursive descendants, and exec remain open.
- [ ] Normalize allocation and mapping/protection transitions.
- [x] Identify RWX mappings and W→X transitions.
- [ ] Extract bytes from anonymous executable mappings as runtime-derived
  `ProgramImage` inputs.
- [ ] Represent dynamic-library loads and search provenance.
- [ ] Detect path traversal, command/format metacharacter flow, permissive file
  creation, predictable temporary paths, and attacker-shaped allocation sizes
  only when the necessary source/sink evidence exists.

**Primary samples:** all `normal_*` and `danger_*` cases.

**Exit:** all normal samples provide contextual facts without findings; every
dangerous bad scenario produces its expected typed event/finding; paired good
controls prevent sink-name-only detection.

### W8 — Input provenance and trace-guided replay

The first prerequisite is now present for caller-supplied invocation bytes and
selected event-backed inputs. Each capsule input source receives a deterministic
execution-scoped identity, and any byte has a queryable `(source_id, offset)`
identity without embedding plaintext or expanding every source into an
attacker-sized list. The real `danger_ioctl_input` capture proves stable
distinct IDs for every `argv[1]` byte and fail-closed bounds. Selected file
reads, pipe reads, and socket receives create event-scoped sources and link the
normalized observation to the source name. Public and redacted captures both
retain byte identity; redacted values remain sensitive and absent. No flow
claim follows from identity alone: additional selected syscall-output sources
and propagation through LLIR remain required before the
first checklist item is complete.

Selected file, pipe, and socket input events now also correlate to an exact
static LLIR `call` occurrence. The occurrence records the source that the call
introduced, while keeping downstream provenance explicitly unproved. The file
case passes the default eight-lane GCC/Clang, `-O0`/`-O2`, PIE/non-PIE matrix;
missing source identity fails closed.

Bounded caller-supplied stdin is now a separate pipe-backed input source. The
real `normal_stdin_read` test proves descriptor-zero event identity, returned
length, input source, and exact LLIR call occurrence; a private-policy capture
keeps the same content hash while omitting bytes, and input over 1 MiB fails
before process launch. Default `/dev/null` stdin remains distinct.
The supplied-stdin trace also records the kernel-observed destination pointer
and returned-byte dump. Its LLIR call occurrence now carries the concrete
memory range and input-source ID as a runtime effect. This is the first proved
source-to-memory edge; provenance through subsequent LLIR operations remains
open, so the propagation checklist item is not complete.

Optional raw-read capture now extends that edge to tracked pipes. The real
`memory_read_overflow` pair proves 8-byte good and 12-byte bad writes from one
input source into their concrete runtime destinations and exact LLIR call
occurrences. Its optional cooperative stop now reads the same destination bytes
from the still-running execution and retains their exact containing stack
mapping, a mapping-kind runtime object, and an object-relative hash-bound
snapshot. This proves stack-mapping containment and trace-versus-memory
agreement. The first `glaurung-runtime-stack-write-report-v1` consumer now
infers the `main` frame from bounded captured frame records whose return address
resolves to the exact image, then applies the compiler's authoritative DWARF
frame-base, object, and field contracts. The full 16-cell good/bad matrix across
GCC/Clang, `-O0`/`-O2`, and PIE/non-PIE resolves the 12-byte `b` object and
eight-byte `dst` field despite four distinct frame-base/offset contracts. The
good write remains within `dst`; the bad write crosses its boundary by exactly
four bytes while remaining within `b`.
The same relation carries the exact LLIR `call` occurrence. Missing stack
payload and wrong-image controls become unknown. A dedicated fixture-only
pre-read stop now complements the post-read stop, producing two separately
hash-bound 64-byte destination windows from the same execution. The analyzer
joins those windows to the realized DWARF fields: both executions change
`dst[0..8]`, the good execution preserves `canary == 0x1234abcd`, and the bad
execution changes `canary[0..4]` to `ijkl`. Removing only the pre-read payload
preserves frame/object attribution while making field changes unknown.
An oracle-independent semantic projection emits these exact changed or
unchanged field facts and the bad execution's
`read:length=12:declared_length=8` bounds fact. All expected facts pass across
the 16 compiler/optimization/link/scenario cells; mutating the bounds length
fails evaluation. This is the first exact stack-field write attribution and
semantic corruption result, not general stack-object realization or broad
corruption classification.

The relation now also carries input identity across the first recovered-object
boundary. It intersects the occurrence's exact input memory effect with the
realized DWARF fields: source bytes `0..8` map to `dst`, and the bad run's
source bytes `8..12` map to `canary`, with runtime, object, and field offsets
kept distinct. Removing only the source identity withholds this relation rather
than erasing independent byte-diff and bounds evidence. This is a bounded
source-to-field effect, not yet general provenance propagation through later
LLIR operations.

The direct-store trace above is also the first instruction-level temporal
slice. It joins one ordered machine step and observed byte transition to an
exact instruction, LLIR `store`, canonical `OperationOccurrence`, runtime
mapping object, DWARF stack object, and field. It does not yet form block
occurrences, propagate values, replay state, or support arbitrary processes.

The `danger_ioctl_input` trace adds occurrence-scoped direct and conditional
control edges without mutating the static CFG. Its first focused good/bad lane
retains the two interprocedural call-result dependencies and the selected
request store/load chain described in W7 as one fail-closed typed relation.
The four observed lowering shapes and their semantic projection now pass the
complete default matrix. The next increment is to generalize the
occurrence-scoped value-flow engine beyond this representative request
selection while retaining the same fail-closed mutation controls.

That generalization now has its first independent byte-valued case.
`danger_command_argument` constructs the command it prints with one actual
byte from `argv[1]` inside the bounded instruction trace. The new
`input_value_flows` relation joins the exact hash-verified input location,
immutable LLIR stored-value expressions, observed source bytes, and two
ordered destination writes. The second write reloads the byte from the first
destination, so the runtime provenance map has to create and consume an
intermediate memory version. It retains
`(source_id, source_offset, byte_len)` rather than identity-only taint. The
eight GCC/Clang, `-O0`/`-O2`, PIE/non-PIE lanes
pass, including Clang's partial-register composition; a shifted declared input
location becomes unknown. A hash-valid mismatch in the first write removes
the downstream relation. Runtime validation also found and fixed an LLIR
backward-slice error across `eax`/`rax` storage aliases. This is still one
bounded one-byte, two-store path, not general memory-version propagation or
unchanged-write handling. The new `executed_loads` stream now gives each source
read its own exact LLIR operation occurrence and sequence. A flow edge requires
one matching load between memory-version creation and the consuming store; a
hash-valid effective-address mutation removes only the downstream edge. This
closes the first bounded byte-propagation checklist item without claiming a
general runtime MemorySSA.

The instruction stream now also groups exact, linearly contiguous instruction
occurrences into occurrence-scoped `observed_blocks`. Each relation names the
immutable native CFG block and raw LLIR block separately and retains the exact
runtime/static instruction sequence that proved the join. Sequence gaps,
control transfers, block changes, interior PCs, and unresolved or unlifted
instructions split the stream; unknown steps remain explicit. The same static
block can therefore have multiple execution occurrences without acquiring
runtime fields. The command fixture covers the default eight build lanes, and
an interior-PC mutation fails closed. This supplies the first block substrate
for bounded replay; it is not path completeness or a runtime CFG rewrite.

The first replay-state adapter now seeds `exec::Machine<Concrete>` at the first
exact main-image block. It imports occurrence-time canonical registers and x86
flags, reconstructs a preceding stack-object snapshot through the complete
ordered change stream, initializes only those proven bytes, and verifies every
seeded register and byte by reading the machine back. The seed report retains
its observed-block identity, time bounds, source/seeded memory hashes, and the
explicit rule that unseeded execution memory remains unknown despite the
generic emulator's zero default. It then executes exactly the LLIR operations
identified by the observed block and compares control flow, the known written
register projection, and all seeded memory with the next observed state. A
narrow x86-64 adapter supplies opcode-proven `e8` call-stack and `c3`
return-stack mechanics that raw LLIR intentionally abstracts. Static LLIR VAs
and runtime VAs remain different domains: equality across PIE is accepted only
through an exact capsule mapping and is emitted as a mapping-backed normalized
comparison. `Op::Undef` registers are reported with their poison reason rather
than compared through stale executor bits. The default eight command lanes
pass; removing the initial snapshot payload withholds only the seed. This is a
bounded observed-block replay, not arbitrary path or whole-function replay.
The seed now also carries a typed optional `first_divergence`, including exact
event/instruction/LLIR-operation attribution where available. A hash-consistent
negative control mutates only the observed successor `rsp` and proves a
structured register mismatch at the return operation. Unsupported-operation
and missing-environment variants are distinct. A dedicated real-binary build
executes user-mode `smsw` after trace begin; its later exact block lifts to an
opaque memory intrinsic and replay reports `unsupported_operation` with exact
operation attribution instead of fabricating an effect. Replay seeds now cover
every exact observed block independently. They do not yet chain one replayed
terminal state into the next block's initial state.

Solver-query selection now has its first occurrence-scoped taint gate. For one
exactly located invocation input, it assigns provenance to individual runtime
bytes and propagates those source offsets through exact LLIR register and
concrete memory operations in the observed instruction stream. It emits a
candidate only when an exact LLIR conditional jump consumes that provenance
and joins to one exact observed successor edge. The candidate retains the
input-byte spans, predicate registers, runtime event identity, immutable LLIR
operation identity, and observed branch direction. Calls, opaque intrinsics,
unresolved operations after provenance enters registers, and missing register
state are conservative barriers. This is query selection only; no branch is
yet negated and no solver result is claimed. A dedicated real branch fixture
selects one `argv[1][0]`-dependent edge, while all eight ordinary command build
lanes select none.

The first counterfactual gate now starts at the earliest exactly resolved
instruction in the selected function, seeds a fresh `exec::Machine<Symbolic>`
from occurrence-time registers and captured memory, replaces only the selected
public source-byte spans with symbols, and replays the exact observed LLIR
prefix. Earlier symbolic branches are constrained to their observed edges; the
selected branch is constrained to the opposite edge. The native Axeyum solver
seam returns a byte patch rather than a synthetic whole input. For the
guarded command fixture it changes `argv[1][0]` from `c` to `b`; a second real
execution of the same binary reaches the predicted opposite edge at the same
immutable LLIR operation. Default builds retain the candidate but report the
typed `no_solver` outcome. Calls, unresolved post-seed instructions, symbolic
pointers, uncaptured memory, and non-public input remain explicit unknowns.
The Axeyum lane additionally removes the captured stack payload, inserts the real
opaque `smsw` instruction before the selected branch, and executes a safe load
through an input-derived address; those three variants respectively prove
`missing_environment`, `unsupported_semantics`, and `symbolic_pointer` rather
than producing witnesses. A symbolic unit gate keeps solver wall timeout and
deterministic resource exhaustion as separate typed unknown reasons.

Actual selected `getenv` calls now have a separate bounded provider. It accepts
only explicitly caller-supplied variable names, records present/missing events,
assigns stable identities to returned bytes, redacts values by default, and
fails if a selected call was absent or malformed. The real
`danger_environment_path` gate proves private/public policy separation for
`PATH`. Its raw caller PC remains unresolved because this provider has no
mapping snapshot; it does not guess a PIE base or claim an operation
occurrence.

- [x] Assign stable IDs to bytes read from selected files, stdin, pipes,
  sockets, environment values, invocation arguments, and bounded read/receive
  outputs.
- [x] Carry byte provenance through concrete LLIR operations and memory writes.
- [x] Correlate observed native blocks with lifted blocks.
- [x] Seed `exec::Machine` from captured registers and sparse pages.
- [x] Replay an observed bounded function/path and compare terminal state.
- [x] Report the first divergence with unsupported-operation attribution.
- [x] Use taint to decide which branch conditions are worth solver queries.
- [x] Negate one observed input-dependent branch and produce a new concrete
  input when satisfiable.
- [x] Preserve solver timeout, unsupported semantics, symbolic-pointer
  concretization, and missing-environment boundaries as `unknown`.

**Primary samples:** copy length, array index, under-allocation, path, command,
format, allocation, IOCTL, and generated-code cases.

**Exit:** at least one memory-corruption and one dangerous-operation fixture
have a reproduced observed path plus a solver-generated neighboring input,
validated by running the real compiled binary.

**Exit evidence achieved:** guarded real-binary lanes for
`memory_index_write` and `danger_command_argument` start from public input
`cad`. Native Axeyum changes only byte zero to produce `bad`. The second indexed-
write capture traverses the predicted opposite LLIR edge and the existing
DWARF/LLIR/runtime stack relation places the resulting write in `canary`. The
production validator launches the second command capture, verifies its
predicted opposite LLIR edge, and returns a separate validation relation; an
ordinary execution of the exact same binary and materialized input emits both
`SINK command ;...` and `RESULT metachar 1`. A third guarded lane starts from
the same safe `cad` trace in `crash_null_write`; Axeyum produces `bad`, the
production validator captures its core, and the crash relation classifies a
null write at the predicted exact LLIR store. The original and validation
capture identities remain distinct.

The bounded negative gate uses two input-dependent branches. Negating the
first is satisfiable; negating the later branch while retaining the first
observed condition is unsatisfiable. The result records each condition's event
sequence, immutable LLIR operation identity, required direction, and role, as
well as event-range, instruction-count, symbolic-input, memory-snapshot,
captured-memory, and solver-time bounds. Solver-returned unknowns carry the
same proposition fields. Pre-query failures are typed `unknown` with
`proposition_status: not_constructed`, so absence of a query cannot be read as
a bounded solver conclusion. These real-binary gates satisfy the
representative Objective 10 exit evidence and move the next implementation
increment to W9 persistence without broadening the counterfactual claim beyond
the recorded bounds.

### W9 — Persistence and analyst surfaces

- [x] Add capture/run identities to `.glaurung` without weakening manual
  precedence.
- [ ] Persist modules, mappings, observations, runtime xrefs, events, and
  findings with provenance.
- [x] Support multiple runs of the same exact binary.
- [ ] Compare good/bad and build-to-build runs.
- [x] Add CLI surfaces for the complete analyst workflow.
  - [x] Capture.
  - [x] Import.
  - [x] Run/capture summary.
  - [x] Crash explanation.
  - [x] Observed static-operation xrefs.
  - [x] Mapping history.
  - [x] Evidence export.

**Identity persistence evidence:** `runtime_runs` and `runtime_captures` are
binary-scoped immutable measurement tables, separate from sessions and all
annotation/precedence tables. The public writer validates the capsule through
the native parser, verifies its executable SHA-256 against the selected project
binary, stores the exact capsule artifact hash and acquisition identity, and
rejects reuse of a capture ID for different bytes or a different run. Missing
run IDs default deterministically to the capture ID; grouping multiple captures
requires an explicit caller-supplied run ID rather than PID or timestamp
guessing. A real stopped-child gate persists two independently acquired
captures of one exact binary as two runs, proves idempotent re-import, and
reopens the project with both captures and a pre-existing manual note intact.
This closes only W9's identity and multiple-run bullets; durable runtime object,
event, relation, finding, comparison, and analyst surfaces remain open.

**Identity-graph persistence evidence:** the same atomic import now normalizes
process identity/ancestry/terminal state, thread register and fault
observations, module artifacts/load biases, mapping ranges/backing, and ordered
events into capture-scoped tables. Event uniqueness and ordering stay
scoped to the provider's `(process, optional thread)` stream; persistence does
not invent a total causal order. A real repeated stopped-child gate compares
every normalized record with the validated capsule, closes and reopens the
project, and repeats the count checks. An injected child-import failure proves
the run, capture, and identity graph roll back together. The combined
modules/mappings/observations/events bullet remains open for runtime objects,
runtime/static occurrence relations, xrefs, and findings.

**Observation persistence evidence:** the atomic identity-graph import now also
normalizes capture-owned sparse pages, runtime objects and their ordered
snapshots, output payload references, and descriptor snapshots. These records
retain their original capsule JSON alongside query columns, so reopening a
project reproduces the exact validated observation rather than a lossy static
analogue. The real stopped-child gate compares every imported record with its
capsule source and repeats family counts after reopening. Runtime objects remain
capture-scoped and are not inserted into the decompiler's static memory-object
or variable stores. This advances the observations portion of the combined
bullet; runtime/static occurrence relations, observed xrefs, and findings still
keep it open.

**Analyzer-report persistence evidence:** `runtime_analysis_reports` stores one
canonical, SHA-256-addressed result per exact capture, analyzer, and report
schema. Analysis reloads the capsule and payload bytes from the project and
rechecks supplied executable bytes against capture identity. Re-analysis must
produce byte-identical JSON or fail closed; it cannot replace prior evidence.
The stopped-child gate persists and reopens a no-crash result, while the real
eight-lane null-write core matrix persists and reopens each typed crash report
across GCC/Clang, `-O0`/`-O2`, and PIE/non-PIE. This establishes durable crash
findings with capture provenance, but does not close persistence for all
runtime/static occurrence relations or the remaining finding families.

**Occurrence persistence evidence:** persisted instruction-trace reports now
normalize every inferred `OperationOccurrence` into one capture/process/thread
and event-scoped identity joined to its immutable LLIR operation identity.
That static identity is now a canonical, validated function → block → operation
hierarchy over the exact image, lift-profile generation, operation index, and
operation kind; forged or stale child or parent IDs fail closed. It
deliberately excludes capture, process, thread, event, and concrete values,
which remain in the occurrence.
Recovered LLIR memory-address and stored-value expression roots now carry
separate operation-owned IDs when present. Occurrence construction recomputes
them and rejects an ID without the corresponding immutable expression (or an
expression with a stale ID). Nested expression nodes now carry deterministic
typed paths, root/parent links, semantic kinds, and IDs. The occurrence gate
reconstructs and compares the complete graph; these are still not rendered-token
or recovered-AST identities.
The corresponding store-address and stored-data operands now carry distinct
static semantic-value IDs linked to the operation and expression roots. Their
canonical population is validated at occurrence construction; no concrete
runtime value is stored in the static record.
Conditional expressions and ordinary operation definitions now use the same
root, nested-node, and static-value identity contract. A Clang `-O2` IOCTL lane
proves a real non-store definition; the GCC branchless-selection lane proves
that a runtime-selected condition without a recovered static expression does
not receive an invented identity. Direct and indirect call targets and each
recovered ABI input position now use the same operation-owned expression/value
contract. The decompiler's shipped variable inventory also exposes IR-owned
static-variable records for recovered ABI parameters and uniquely located
frame locals. Those records are keyed by canonical function and storage origin,
not rendered names; ambiguous storage stays unidentified. Parameters with
structured type hints now reference graph-owned recovered type nodes keyed by
semantic shape, target width, exact image, and recovery profile rather than C-
like spelling. Text-only stack-local types still have no type ID. Unit gates
prove rename and spelling invariance, and the real GCC debug fixture exercises
frame-storage nodes through the Python surface. Complete live-range-aware high-
variable identity, structural types for other proven roles, and bindings to all
semantic values remain open.
Content-addressed evidence views are stored separately because the same
occurrence can legitimately appear in several relations with different input
projections. The real direct-store trace gate proves those views coexist under
one occurrence, retains the exact static operation, and reproduces report,
identity, and evidence rows after reopening. No concrete runtime value is
written into LLIR, SSA, variables, or static xrefs. Broader relation and finding
families still keep the combined persistence bullet open.

- [x] Make JSON the stable automation contract; keep terminal rendering pure.
- [x] Route LLM tools only to persisted deterministic facts, never raw secret
  memory by default.

**Stable automation evidence:** `runtime_capture_summary_json` emits the
canonical `glaurung-runtime-project-summary-v1` projection exclusively from
persisted rows. It includes capture identity, process terminal state, module
hashes, path-free mapping context, event-kind counts, redacted descriptor
identity, report hashes/outcomes, and observed static-operation identities.
Payload bytes, registers, page/object snapshots, paths and descriptor targets,
event fields, and occurrence evidence values are explicitly omitted. Both a
stopped live capture and a real trace reproduce byte-identical JSON after
project reopen. Human crash rendering remains a separate projection and is not
parsed as an automation input.

**LLM routing evidence:** runtime-project questions select a dedicated
`runtime_project` intent whose only tool is `runtime_project_summary`. That tool
opens an existing `.glaurung` project and returns only the stable redacted
summary above; it has no live-capture, raw-payload, register, memory, path, or
event-value parameter. Routing tests prove representative runtime-summary,
live-capture, and observed-xref questions select only this tool, and the agent
registration filter leaves no other tool available in that lane. Explicit
analyst APIs can still retrieve detailed evidence outside the default LLM
surface.

**CLI projection evidence:** `glaurung runtime import` passes capsule metadata
and its exact payload directory through the native fail-closed bundle importer,
then persists the canonical metadata and the already-verified bytes into an
existing or newly binary-anchored project. The Python layer never reopens a
validated payload path, avoiding a validation/use race. `glaurung runtime
summary` emits the exact
persisted, redacted `glaurung-runtime-project-summary-v1` contract in JSON mode;
its plain renderer is terminal-only. `glaurung runtime observed-xrefs` projects
only the summary's capture-scoped occurrence-to-immutable-LLIR links, and
`glaurung runtime compare` emits the existing persisted comparison contract.
A real stopped two-thread process is captured, persisted, closed, and then read
through all three CLI paths; summary and comparison bytes match the underlying
canonical APIs exactly. These read-only commands do not reacquire a process or
expose payload, register, path, descriptor-target, event-field, or occurrence-
evidence values. A real bundle round-trip proves import output is byte-identical
to direct persistence. `glaurung runtime crash` returns the exact
content-addressed persisted crash-analysis JSON after verifying its hash,
capture identity, and schema binding. Its plain-text path deserializes that same
stored typed report in Rust and applies the deterministic, sensitive-byte-
redacting renderer; it never reloads capsule payloads or reruns analysis. A real
stopped two-thread no-crash capture proves JSON identity and terminal rendering,
while absent-report and corrupted-hash controls fail closed. Capture and
evidence export remain open; mapping history is described next.

`glaurung runtime mapping-history` reads a separately persisted
`glaurung-runtime-mapping-behavior-report-v1`; it does not reinterpret static
mappings as temporal state. The report retains capture/process/thread scope,
event sequences, exact mapping lifetimes, permission transitions, removals,
findings, completeness, and ignored-event count. JSON is the exact
content-addressed report; terminal rendering is a pure projection. Real
`RW -> unmapped`, `RW -> RX -> unmapped`, and `RWX -> unmapped` controls prove
round-trip persistence and CLI reproduction, while missing reports, repeat
analysis, and a corrupted report hash are explicit gates. Evidence export and
capture are described next.

`glaurung runtime evidence` emits
`glaurung-runtime-evidence-packet-v1` exclusively from persisted rows. The
default policy includes redacted capture summary, content hashes, completeness
states, report claim-kind inventories, and an explicit omission list; it does
not include capsule/report documents, payload bytes, completeness reasons, or
executable bytes. `--include-sensitive` is the explicit analyst authorization
boundary that adds the exact capsule, typed report documents, and base64 payload
bytes, while still identifying rather than embedding the executable. Both modes
verify capsule, report, and payload hashes before export. A real stopped process
proves deterministic reopen/CLI output and corruption rejection; a real core
proves sensitive payload bytes round-trip exactly. The capture surface is
described next.

`glaurung runtime capture` launches only a caller-selected executable as a new
owned process group, waits for its cooperative stop, captures through the
shipping bounded live provider, validates the capsule, and atomically persists
it into the selected exact-binary project. It has no PID or arbitrary-attach
input. Child environment inheritance is off by default in both the Python API
and CLI; individual `NAME=VALUE` entries and full inheritance require explicit
flags. The real two-thread fixture proves an inherited sentinel secret cannot
reach the child while an explicitly supplied value does, persists the capture,
and reproduces its summary after reopen. Invalid environment syntax fails
before process launch or project creation. This closes the W9 CLI workflow
checklist, not the broader W9 persistence and cross-build comparison bullets.

**Run-comparison evidence:** `compare_runtime_captures_json` contrasts two
captures in one project, and `compare_runtime_summaries_json` accepts the same
redacted contract from separate build projects. Independent same-build repeats
produce zero count and event-kind deltas with matching analyzer outcomes. A
real null-read good/bad pair reports `no_crash` versus `crash`. The eight-lane
null-write core gate compares GCC `-O0` and `-O2` projects as different
executables while retaining their common crash outcome. Cross-build operation
alignment deliberately remains unavailable until a stable cross-build
operation/function identity is proved, so the combined good/bad and
build-to-build bullet remains open rather than matching absolute VAs or LLIR
indices heuristically.

**Exit:** a fresh process can import a capsule, reopen the project, reproduce
the same deterministic report, and distinguish observations from static and
symbolic claims.

### W10 — Hardening, performance, and broader coverage

- [ ] Fuzz capsule/core parsers and sparse memory reads.
- [ ] Enforce acquisition and analysis budgets independently.
- [ ] Make event loss, trace truncation, and page omission measurable.
- [ ] Add reproducibility and deterministic-serialization gates.
- [ ] Measure capture pause, artifact size, import time, query latency, and peak
  RSS on the corpus.
- [ ] Gate the native Glaurung/Axeyum boundary: no subprocess or SMT-LIB path in
  production, with separate translation/import/solve/model/cache timings,
  allocation and retained-state measurements, and cold/warm corpus baselines.
- [ ] Add AArch64 only after Linux x86-64 exit criteria hold.
- [ ] Add network-service request capture after file/stdin provenance works.
- [ ] Add arbitrary attach only with an explicit security and authorization
  design.
- [ ] Add Windows minidump/KDNET or driver/IOCTL workflows only through the same
  capsule and evidence model.

The first Axeyum boundary hardening step is enforced in the build graph:
ordinary/default builds use the in-process Rust Axeyum API, while all external
solver process discovery and pipe transport is compiled only by the explicit
comparison feature `solver-pipe-oracle`. The ordinary pipe-module test inventory
contains only pure SMT-LIB rendering tests. The W10 item remains open until the
separate timing, allocation, retained-state, and cold/warm corpus baselines are
implemented and gated.

The second hardening substrate now removes text transport from cache identity:
each assertion is captured as a typed native DAG with dense topological
references and hashed directly. Equivalent queries can therefore match across
separately allocated expression pools without depending on process-local IDs.
Runtime counterfactual analysis now consults a bounded per-worker exact cache,
with replay validation for SAT models and bypass in explicit comparison builds.
On `test_counterfactual_neighbor_reaches_real_index_corruption`, an Axeyum
profile records two backend calls for two unique hashes where the prior path
made three calls and solved one hash twice.

Direct-delta retained sessions are now also the normal cache-miss path for
runtime counterfactuals. A capture-scoped exploration lineage owns one Axeyum
session in a domain separate from ordinary symbolic-explorer paths. Observed
prior conditions are persistent assertions, while the currently selected
negation is a temporary assumption. Every lineage is explicitly closed after
candidate selection, and the existing live-path and assertion caps bound the
retained set. Exact typed native prefix identity is compared across rebuilt
expression pools, so retention does not depend on local `ExprId` allocation.
The retained Axeyum arena now also owns an exact semantic-term cache: typed
Glaurung nodes use structural child identities instead of pool-local `ExprId`s,
so rebuilt expressions recover existing `TermId`s and assertion wrappers. The
cache is reset and dropped with its arena. Warm profile schema v8 records term
and assertion reuse plus current identity/term/assertion entry counts. The
broader W10 item remains open: byte allocation attribution and cold/warm corpus
budgets are not yet complete. The runtime exact-cache wrapper records the
existing non-overlap telemetry for lookup, SAT-model replay, index update,
eviction, backend miss, and total wrapper time; a cache hit is explicitly
recorded as making no backend call and not synchronizing the retained session.

Reproduce that count with a fresh disk-backed profile directory:

```bash
GLAURUNG_PROFILE_RUN="target/axeyum-counterfactual-$(date +%s)"
mkdir -p "$GLAURUNG_PROFILE_RUN"
GLAURUNG_AXEYUM_PROFILE_DIR="$PWD/$GLAURUNG_PROFILE_RUN" \
  uv run pytest -q python/tests/test_runtime_sample_harness.py::test_counterfactual_neighbor_reaches_real_index_corruption -m slow
find "$GLAURUNG_PROFILE_RUN" -type f -name '*.jsonl' -exec wc -l {} \;
```

Reproduce the retained-session evidence with the two-condition real fixture:

```bash
GLAURUNG_PROFILE_RUN="target/axeyum-runtime-retained-$(date +%s)"
mkdir -p "$GLAURUNG_PROFILE_RUN"
GLAURUNG_AXEYUM_PROFILE_DIR="$PWD/$GLAURUNG_PROFILE_RUN" \
  uv run pytest -q \
    python/tests/test_runtime_sample_harness.py::test_counterfactual_unsat_retains_the_observed_prefix \
    -m slow
```

The two profile records for that fixture show `entry_mode: direct_delta`; the
first has `path_created: true`, while the related second query has
`path_created: false`, one newly persistent assertion, one temporary assumption,
two stable-term reuses, and no new AIG nodes. In that second record,
`translated_exprs` falls from thirteen on session creation to four for the
related query. The cross-pool semantic-prefix and exact-term unit gates are:

```bash
cargo test --features python-ext --lib \
  runtime_direct_delta_reuses_exact_native_prefix_across_expression_pools
cargo test --features python-ext --lib \
  retained_translator_recovers_exact_terms_across_expression_pools
```

Implement the remaining boundary work in this order:

1. Attribute time and allocation separately to cache lookup, translation,
   assertion import, solve, replay, and model extraction. Record peak and final
   retained arena/AIG/CNF/session state; wall-clock totals alone are not an
   optimization result.
2. Gate cold, warm-prefix, sibling-fork, and model-producing queries over the
   checked-in matched corpus. Require identical authoritative verdicts and
   replay-valid models, no increase in unknown/error classes, explicit p50/p95
   latency and peak-RSS budgets, and no subprocess/PATH/SMT-LIB activity in the
   production feature lane.

The first fail-closed comparison tool is
`tools/axeyum/runtime_profile_report.py`. It accepts native cold-profile JSONL
and retained direct-delta JSONL, requires the exact same multiset of query
hashes, verdicts, and model-producing classes, rejects incomplete and
non-decisive checks, and reports nearest-rank p50/p95 plus peak retained
arena/AIG/CNF/semantic-cache counts. Generate both sides from the same release
fixture selection with the release gate runner:

```bash
uv run maturin develop --release --skip-install
tools/axeyum/run_runtime_profile_gate.sh
```

The runner creates an isolated directory under
`target/runtime-axeyum-gates/`, captures the two real child fixtures once, then
replays those identical capsule/payload/binary bundles through fresh
analyzer-only cold and retained processes. It binds GNU-time peak RSS for each
analyzer process into `report.json` and prints that report path. Odd repetitions
run cold then optimized; even repetitions reverse that order, preventing a
systematic first-process bias. Before and after each analyzer process, the gate
also records load average, available CPU affinity, and Linux CPU-pressure data
and binds the validated observations into the report. Compiler and
ptrace acquisition memory are outside the solver measurement. It never invokes
a non-Axeyum solver.

The matched corpus schema is now
`glaurung-runtime-axeyum-profile-corpus-v2`. It contains three distinct real
hybrid consequences: a neighboring silent stack corruption in
`memory_index_write`, four related feasible/infeasible command-argument paths
in `danger_command_argument`, and a neighboring null-write crash in
`crash_null_write`. The crash capture itself follows the safe observed path;
the Axeyum model proves the bounded neighboring path. This expands the gate
beyond one corruption and one synthetic retained-prefix shape while retaining
exact expected status checks.

The first v2 end-to-end smoke gate captured all three programs and exercised
both counterbalanced orders. It produced 12 matched authoritative Axeyum
checks: eight SAT/model-producing and four UNSAT, comprising four cold
singletons, two created retained sessions, and six session reuses. Exact
query/verdict/model-class parity passed. Recorded one-minute load was
1.75–2.18 with zero Linux CPU pressure `some avg10`. Aggregate p50 changed by
+4.8%, p95 by -3.1%, and optimized peak RSS by +12,264 KiB. Two repetitions
remain smoke evidence, not a budget. The release-mode dirty-tree source-state
hash was
`ab1ea539c4753eca878b17ef1f27ab6dc84792bf6fb972f8a4ca60652a81bdbe`.

If acquisition has already succeeded, set
`GLAURUNG_RUNTIME_PROFILE_CORPUS=/absolute/path/to/corpus.json` to rerun only
the analyzer processes. Each analysis revalidates the capsule, payload, and
binary hashes before use. The runner records the reused path and keeps stdout,
stderr, RSS, and host observations per lane and repetition, so a killed or
failing analyzer leaves an attributable artifact rather than an unexplained
partial profile.

This is measurement infrastructure, not yet a budget claim. A broader
checked-in fixture selection, true allocation attribution, and numeric release
budgets remain required before W10 closes.

The first repeated gate-run observation used the checked-in
`memory_index_write` satisfiable-neighbour fixture and the
`danger_command_argument` retained-prefix UNSAT fixture. Three process
repetitions produced nine matched query occurrences: six SAT model-producing
checks and three UNSAT checks. The comparator accepted exact
population/verdict/model-class parity. With nearest-rank percentiles, cold
totals were p50 61,806 ns and p95 398,400 ns; retained totals were p50 83,795 ns
and p95 390,939 ns. The three genuinely reused-session checks were p50 37,597 ns
and p95 49,160 ns. Analyzer-only peak RSS was 78,264 KiB cold and 78,144 KiB
retained. The report binds Glaurung revision
`8b02bd4bb36953edbf97408520f353e3e6a3c759`, Axeyum revision
`a9991fdad6c1e4b2bda596b46d2c8c715556ceae`, release mode, native Axeyum
authority, and the fact that the Glaurung worktree was dirty. Its source-state
hash was `23481b4338569961fbe8bf9a0c12709d10b4fa95c95bba24b9417be41085af3e`.

This small diagnostic population says something narrower than “warm is
faster”: reuse itself is cheaper, but six of nine queries created sessions, so
aggregate retained median latency was worse. The next optimization target is
capture-scoped lineage/session coverage and creation cost, not the SAT adapter.
The sample remains too small and the tree too dirty to establish a release
budget. Reproduce it with `tools/axeyum/run_runtime_profile_gate.sh` above; its
default is three repetitions and a 30-second test-only trace budget.

The Axeyum profile times exclude trace acquisition, so the larger test-only
capture deadline does not enter the reported solver timings.

The first counterbalanced protocol smoke run used two repetitions and ten
matched query occurrences. It proved both orders (`cold, optimized` and
`optimized, cold`), exact verdict/model-class parity, and complete host
observations. One-minute load stayed between 1.67 and 1.73 and Linux CPU
pressure `some avg10` remained zero at every observation. Cold p50/p95 was
195,812/226,290 ns; optimized p50/p95 was 44,665/235,322 ns, with six retained
checks at 40,668/45,652 ns. Peak analyzer RSS was 93,640 KiB cold and 90,584
KiB optimized. The source-state hash was
`d874c661393cce3aad44838e9be6d06ad5d6ce4ff0f2bc458bb2dae0f36b7c13`.
This is evidence that the counterbalanced gate and native Axeyum reuse execute
correctly, not a latency or memory budget: two repetitions are deliberately
insufficient for a release threshold, and the worktree was dirty.

A subsequent full 20-repetition analyze-only run over that exact hash-verified
corpus produced 100 matched checks with exact Axeyum verdict/model-class
parity. Each lane ran first ten times. Cold p50/p95 was 83,528/406,749 ns;
optimized p50/p95 was 75,722/426,296 ns. Thus aggregate median improved 9.3%,
while p95 regressed 4.8%. The 60 retained checks had p50/p95
46,041/102,742 ns; 20 session creations cost 389,862/478,412 ns. Peak RSS was
90,020 KiB cold and 93,780 KiB optimized, a 3,760 KiB increase. One-minute
load ranged from 7.23 to 10.86 and Linux CPU-pressure `some avg10` from zero to
8.0, so this remains diagnostic rather than budget-setting evidence. The
source-state hash was
`b3aa33a280d0451e4662a6aafd6d5cd5946e1bb31c3e234035def38de2986b76`.
The report now emits signed absolute and integer-parts-per-million relative
changes for aggregate p50, p95, and peak RSS so a later budget gate does not
have to reinterpret raw measurements.

The comparator also accepts an optional strict
`glaurung-runtime-axeyum-profile-budget-v1` JSON artifact through `--budget`,
or through `GLAURUNG_RUNTIME_PROFILE_BUDGET` in the runner. It evaluates the
minimum matched population and process repetitions; maximum p50, p95, and RSS
relative changes; and maximum one-minute load per logical CPU and Linux CPU
pressure. It records all checks and exits nonzero if any fail. Unknown, missing,
or extra budget fields fail closed. No threshold artifact is checked in yet:
choosing one from the noisy dirty-tree diagnostic above would turn an
uncontrolled observation into policy rather than establish a release budget.
An end-to-end two-repetition smoke gate accepted a permissive temporary policy;
the same gate exited 1 and preserved a report naming `matched_population` when
the temporary minimum was raised from 10 to 1,000. The temporary policies were
not retained.

An analyzer-only Valgrind DHAT probe was also attempted with
`PYTHONMALLOC=malloc`. It completed, but optimized stack unwinding collapsed
nearly all Rust allocation sites into the PyO3 binding frame: only one 32-byte
allocation remained visibly beneath `solve_runtime_for_path_delta`. That result
is rejected as allocation evidence. A useful DHAT lane needs a separate
frame-pointer/inlining-controlled audit build, followed by a normal release
rebuild; alternatively, Glaurung as the consumer must approve an opt-in global
allocator meter. Axeyum itself deliberately does not install a process-global
allocator from a library. Until one of those routes is implemented and tested,
W10 allocation attribution remains open.

**Exit:** documented budgets fail closed; hostile artifact tests pass; a second
architecture/provider reuses analyzers without introducing a parallel model.

## Ordered milestones

| milestone | outcome | workstreams | corpus gate |
|---|---|---|---|
| M0 — Oracle authority | Semantic expectations and deterministic ledger | W0 | 120 scenarios fully described |
| M1 — Capsule contract | One versioned, secure, round-trippable artifact | W1 | Entry/exit captures for representative four-category set |
| M2 — Postmortem vertical | Core → normalized crash report | W2, W4, W5 | Five crash shapes across four compiler/link lanes |
| M3 — Live snapshot vertical | Owned child → registers/pages/modules → same report | W3, W4 | Entry captures for 60; exit captures for 45 non-crash cases |
| M4 — Crash completeness | Full crash population and controls | W5 | 30 crash good/bad scenarios |
| M5 — Silent corruption | Before/after object evidence | W6 | 30 memory-corruption good/bad scenarios |
| M6 — Contextual behavior | Normal OS facts and dangerous findings | W7 | 60 normal/dangerous good/bad scenarios |
| M7 — Hybrid reasoning | Observed trace → replay → bounded alternative | W8 | At least two independently validated input-producing analyses |
| M8 — Product and hardening | Persistence, CLI, budgets, hostile artifacts | W9, W10 | Default matrix plus determinism/security/performance gates |

Do not start M7 by expanding symbolic execution in isolation. Do not start M6
by writing a large syscall table. Each milestone consumes the exact evidence
contract established below it.

## Test and evidence matrix

### Tier A — per-change core lane

- GCC `-O2` PIE;
- all 60 good scenarios;
- affected bad scenarios;
- capsule/schema unit tests;
- no network and no elevated privilege.

### Tier B — runtime fixture gate

- GCC and Clang;
- `-O0` and `-O2`;
- PIE and non-PIE;
- all 120 scenarios;
- process oracles plus semantic oracles;
- live entry capture for every sample;
- live exit capture where reachable.

### Tier C — postmortem/provider gate

- real core files for all crash cases supported by host policy;
- wrong-build, missing-page, truncated-note, and corrupt-capsule negatives;
- live-versus-core equivalence for stable facts;
- sanitizer oracle runs kept separate from analyzed binaries.

### Tier D — scheduled breadth

- `-O1`, `-O3`, `-Og`, `-Os`;
- optional static linking;
- alternate libc/container image;
- AArch64 when supported;
- performance and artifact-size baselines.

A tier is not green if a requested lane silently disappears, a core was not
produced, a live capture lost required pages, or an analyzer returned a partial
answer without declaring incompleteness.

## Sample-to-capability map

### Normal behavior

| samples | capability forced |
|---|---|
| `normal_open_file`, `normal_create_file`, `normal_read_file`, `normal_write_file`, `normal_append_file`, `normal_stat_file` | File/descriptor identity, paths, offsets, results, and absence of false findings |
| `normal_mmap_read`, `normal_heap_lifecycle` | Mapping and heap lifecycle context |
| `normal_pipe_roundtrip`, `normal_socketpair`, `normal_dup_fd`, `normal_stdin_read` | Descriptor graph and input-channel identity |
| `normal_environment`, `normal_arguments` | Redacted process inputs and provenance |
| `normal_fork_wait` | Owned process-tree capture and parent/child events |

### Deterministic crashes

| samples | capability forced |
|---|---|
| `crash_null_read`, `crash_null_write` | Access direction and null classification |
| `crash_guard_read`, `crash_guard_write`, `crash_readonly_write`, `crash_execute_nonexec` | Mapping permissions and read/write/execute fault classification |
| `crash_bad_function_pointer` | Invalid indirect-control target |
| `crash_stack_overflow` | Stack bounds and recursive exhaustion |
| `crash_abort`, `crash_assert` | Deliberate termination versus memory fault |
| `crash_trap`, `crash_raise_segv`, `crash_raise_bus`, `crash_raise_fpe`, `crash_raise_ill` | Signal provenance without overclaiming an inferred root cause |

### Memory corruption

| samples | capability forced |
|---|---|
| `memory_struct_field_overwrite`, `memory_heap_canary_overwrite` | Adjacent-object byte attribution |
| `memory_off_by_one`, `memory_index_write` | Exact bound and index classification |
| `memory_memcpy_overflow`, `memory_memmove_overflow`, `memory_strcpy_overflow`, `memory_strcat_overflow`, `memory_sprintf_overflow`, `memory_read_overflow` | Copy/read source, destination, requested length, and changed interval |
| `memory_integer_truncation`, `memory_underallocation` | Arithmetic-to-allocation-to-write chain |
| `memory_format_n` | Format-controlled write sink |
| `memory_stale_pointer_write` | Lifetime evidence and uncertainty |
| `memory_overlapping_copy` | Invalid overlap distinct from out-of-bounds corruption |

### Dangerous behavior

| samples | capability forced |
|---|---|
| `danger_path_traversal`, `danger_command_argument`, `danger_format_string`, `danger_environment_path` | Input-to-semantic-sink evidence |
| `danger_rwx_mapping`, `danger_rw_to_rx`, `danger_mprotect_exec` | Mapping history and executable-page transitions |
| `danger_dlopen_input` | Runtime module loading and search provenance |
| `danger_symlink_follow`, `danger_world_writable`, `danger_predictable_temp` | Filesystem policy context without path-name-only findings |
| `danger_large_allocation` | Input/condition to allocation-size evidence |
| `danger_ioctl_input` | Descriptor/device/request tuple |
| `danger_bind_listener` | Socket endpoint and exposure context |
| `danger_fork_tree` | Multi-process ownership and event correlation |

## Security and privacy constraints

- Never capture arbitrary environment values by default.
- Never persist full pages merely because they are readable; select regions by
  analysis need and record omissions.
- Treat captured artifacts as potentially secret and hostile.
- Never follow capsule paths outside the approved artifact root.
- Never trust captured lengths, offsets, architecture tags, or hashes.
- Never attach to a PID that the requested capture did not launch until a later
  authorization design explicitly permits it.
- Never use a dangerous sample against real paths, services, devices, or
  credentials.
- Never pass captured memory directly to an LLM without an explicit redaction
  and user-authorized export boundary.

## Non-goals for the first programme

- Whole-OS or kernel-memory analysis.
- Scheduler reconstruction.
- Full filesystem or packet capture.
- General debugger UI.
- Faithful libc/kernel emulation.
- Exhaustive symbolic execution.
- JIT compilation of the LLIR interpreter.
- macOS/Windows parity before the Linux capsule contract holds.
- Production-service attachment.
- Treating observed coverage as proof of unreachability.

## Risks and controls

| risk | control |
|---|---|
| Fixture-specific instrumentation makes the product depend on `SIGSTOP` helpers | Treat checkpoints as acquisition timing only; analyzer inputs are ordinary process/core facts |
| Undefined behavior changes across compilers | Keep process and semantic oracles per lane; reject silent drift through the matrix ledger |
| Core availability depends on host policy | Record no-core as not evidence; retain live capture and generated-core CI lanes separately |
| `/proc` capture races with process change | Stop owned threads, re-read mappings, and report partial/racy capture |
| Runtime facts pollute static truth | Persist claim kind and run identity on every fact |
| Captures leak credentials or file contents | Redact by default, use explicit region selection, and hash identities |
| Symbolic results overstate reality | Require bounded-model metadata and real-binary witness validation |
| A provider creates a second program model | Make every provider emit the canonical capsule and consume `ProgramSession` |
| Event volume overwhelms storage | Start with semantic events and explicit budgets; add instruction traces only for bounded slices |

## Definition of programme completion

This roadmap is complete only when all of the following are true:

1. All 120 good/bad scenarios have independent semantic oracles.
2. The default 960-cell compiler/optimization/link matrix remains green.
3. Live and core providers emit one versioned capsule model.
4. PIE/non-PIE runtime addresses join exact static images fail-closed.
5. All crash cases produce correct, evidence-linked classifications.
6. All silent-corruption cases produce exact changed-object evidence or a
   declared unsupported boundary.
7. Normal cases produce contextual facts without dangerous findings.
8. Dangerous cases produce the expected typed findings with clean controls.
9. At least one observed memory defect and one dangerous sink support
   trace-guided replay and a real-binary-validated alternate input.
10. Results persist and reproduce through `.glaurung` with claim provenance.
11. Hostile/truncated artifacts, missing pages, event loss, and resource limits
    fail closed.
12. Capture privacy, ownership, and authorization boundaries are documented and
    enforced.
13. A second provider or architecture demonstrates that the model is reusable,
    not Linux-x86-64 fixture-shaped.

## Next bounded increment

Finish **M0/W0** with independent semantic-result producers. Wait-status,
bounded `RESULT` stdout, typed crash-report projection, the first normalized
mapping-history projection, and the logical memory-interval projection have
landed; next:

1. Expand the memory-interval producer to additional proved object/subobject
   shapes; unsupported identities remain explicit rather than fixture-named.
2. Expand OS-event producers as their acquisition evidence lands; unsupported
   facts remain explicit incomplete results. The first bounded file, descriptor,
   mapping, and parent-side process lifecycle producers have landed.
3. Continue adding mutations at producer boundaries. The retained crash,
   memory, stat, and world-writable mutation gates now all use real produced
   records; no evaluator test constructs facts from oracle expectations solely
   to mutate them.
4. Keep oracle loading confined to the evaluator process.

This closes the remaining gap between a complete oracle population and an
independently enforced truth set.
