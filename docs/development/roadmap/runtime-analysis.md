# Runtime and hybrid analysis roadmap

> **Kind:** plan · **Status:** proposed

This is the implementation roadmap for turning Glaurung's static binary,
concrete-execution, symbolic-execution, and persistent-project foundations into
a runtime-aware analysis product. Its executable baseline is the 60-program C
corpus in [`tests/runtime_samples`](../../../tests/runtime_samples/README.md),
landed at `bffa6dd2` on 2026-09-15.

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
× `-O0`/`-O2` × PIE/non-PIE, with no process-oracle mismatch, measured at
`bffa6dd2` with `uv run python tools/runtime_sample_harness.py matrix`. One real
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

- [ ] Version a semantic-oracle schema separate from runtime capture data.
- [ ] Record expected signal/fault class and relevant source object for every
  crash case.
- [ ] Record expected changed object, byte interval, original value, and final
  value for every silent-corruption case.
- [ ] Record source, sink, and required OS event for every dangerous case.
- [ ] Add negative assertions for every good scenario.
- [ ] Record which oracle is independent: guard page, canary, wait status,
  sanitizer build, source/DWARF truth, or kernel result.
- [ ] Add fixture IDs and schema validation to the harness.
- [ ] Emit a deterministic matrix ledger rather than only terminal JSON.
- [ ] Fail if a requested compiler/link lane is silently absent.

**Exit:** all 120 scenarios have machine-readable semantic expectations and an
independent oracle; regenerating the matrix ledger is deterministic.

### W1 — Capsule schema and acquisition contract

- [ ] Specify `glaurung-process-capsule-v1` and JSON/CBOR serialization rules.
- [ ] Separate public metadata from sensitive page/environment payloads.
- [ ] Hash every captured artifact and bind the manifest to exact binary and
  input bytes.
- [ ] Record requested-versus-obtained completeness.
- [ ] Make publication atomic: incomplete captures never appear complete.
- [ ] Add size/count budgets for pages, mappings, threads, descriptors, and
  events.
- [ ] Reject path traversal, symlink substitution, oversized lengths, and hash
  disagreement during import.
- [ ] Preserve unknown schema extensions while rejecting unsupported required
  features.

**Exit:** the harness exports a capsule, a Rust importer round-trips it
byte-deterministically, and malformed/truncated negative fixtures fail closed.

### W2 — ELF core importer

Start postmortem because it is reproducible and CI-friendly.

- [ ] Parse ELF core architecture and program headers.
- [ ] Import `NT_PRSTATUS`, signal information, auxiliary vector, file mappings,
  and available FP/vector register notes.
- [ ] Build sparse runtime pages from `PT_LOAD` segments.
- [ ] Reconcile `NT_FILE` mappings with the exact executable/modules.
- [ ] Represent missing threads, notes, or pages explicitly.
- [ ] Support multiple threads and identify the faulting thread without assuming
  it is the first note.
- [ ] Import the real core generated by `crash_null_write` as the first fixture.

**Exit:** all 15 bad crash scenarios produce importable cores where host policy
permits; each imported capsule identifies the expected terminal signal, and
missing-core hosts report a skip/not-evidence state rather than pass.

### W3 — Live Linux acquisition

Limit v1 to a child process launched by Glaurung on Linux x86-64.

- [ ] Promote current `/proc` capture into Rust/Python product code.
- [ ] Capture all threads and register sets at one stopped checkpoint.
- [ ] Read selected pages through `process_vm_readv` with `/proc/<pid>/mem` only
  as an explicit fallback.
- [ ] Revalidate mappings before and after reads to detect races.
- [ ] Capture module build IDs and backing-file hashes.
- [ ] Bound descriptor metadata and redact sensitive values by default.
- [ ] Terminate/resume only the child process tree owned by the capture session.
- [ ] Record permission denial, disappeared threads, partial reads, and changed
  mappings independently.
- [ ] Never offer arbitrary PID attach in the first product milestone.

**Exit:** every sample supports an entry capsule; all non-crashing samples
support an exit capsule; repeated captures normalize to the same stable facts
after volatile fields are excluded.

### W4 — Runtime/static correlation

- [ ] Add `RuntimeModule`, `RuntimeMapping`, and `RuntimeAddress` to the program
  model.
- [ ] Join a runtime module to `ProgramImage` by build ID and content identity,
  not basename.
- [ ] Normalize PIE and non-PIE addresses across split mappings.
- [ ] Distinguish file-backed unchanged, file-backed modified, anonymous, and
  unknown pages.
- [ ] Resolve runtime PCs to static functions/basic blocks with an explicit
  exact/interior/ambiguous/missing verdict.
- [ ] Feed observed indirect targets into the program environment as evidence,
  not exhaustive truth.
- [ ] Persist both raw and normalized addresses in the KB.

**Exit:** across GCC/Clang, `-O0`/`-O2`, and PIE/non-PIE lanes, every captured
main-module PC used by a fixture maps to the correct exact build and static
function; deliberate wrong-build controls are rejected.

### W5 — Crash reconstruction

Deliver the first end-to-end product workflow here.

- [ ] Identify faulting process, thread, signal, PC, SP, and architecture.
- [ ] Classify read/write/execute protection faults where evidence permits.
- [ ] Render the containing module, function, block, and instruction.
- [ ] Show relevant registers and bounded memory around referenced addresses.
- [ ] Recover a bounded native stack with per-frame confidence.
- [ ] Distinguish explicit `raise`, assertion/abort, guard-page access, bad
  control target, execute-protection fault, and stack exhaustion.
- [ ] Compare the bad crash with its good control.
- [ ] Emit JSON and analyst-readable evidence packets.

**Primary samples:** all `crash_*` cases.

**Exit:** the 15 bad crash cases receive their correct crash class, all 15 good
controls receive no crash finding, and every asserted frame/address cites its
source artifact and resolution confidence.

### W6 — Memory-object and corruption analysis

Non-crashing corruption requires observation beyond terminal process status.

- [ ] Extend capsule checkpoints with selected before/after memory regions.
- [ ] Add allocation events or a bounded allocator-interposition provider for
  fixture processes.
- [ ] Model stack/global/heap/mapping objects without pretending allocator
  metadata is portable.
- [ ] Diff bytes by object and attribute the write instruction/event.
- [ ] Classify off-by-one, adjacent-field overwrite, copy overflow,
  under-allocation, out-of-range index, stale-pointer write, and overlap.
- [ ] Preserve “changed bytes observed, responsible instruction unknown” as a
  useful partial result.
- [ ] Keep ASan/UBSan output as an independent oracle, never analyzer input.

**Primary samples:** all `memory_*` cases, plus `crash_guard_{read,write}`.

**Exit:** every bad silent-corruption scenario identifies the expected changed
object/interval or declares a specific unsupported boundary; good controls have
zero corruption findings.

### W7 — OS-context and dangerous-operation analysis

Build semantic events over a deliberately small Linux process boundary.

- [ ] Normalize file open/create/stat/rename-like facts.
- [ ] Normalize descriptor, pipe, socketpair, bind/listen, and IOCTL facts.
- [ ] Normalize process creation and parent/child relationships.
- [ ] Normalize allocation and mapping/protection transitions.
- [ ] Identify RWX mappings and W→X transitions.
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

- [ ] Assign stable IDs to bytes read from files, stdin, sockets, environment,
  and selected syscall outputs.
- [ ] Carry byte provenance through concrete LLIR operations and memory writes.
- [ ] Correlate observed native blocks with lifted blocks.
- [ ] Seed `exec::Machine` from captured registers and sparse pages.
- [ ] Replay an observed bounded function/path and compare terminal state.
- [ ] Report the first divergence with unsupported-operation attribution.
- [ ] Use taint to decide which branch conditions are worth solver queries.
- [ ] Negate one observed input-dependent branch and produce a new concrete
  input when satisfiable.
- [ ] Preserve solver timeout, unsupported semantics, symbolic-pointer
  concretization, and missing-environment boundaries as `unknown`.

**Primary samples:** copy length, array index, under-allocation, path, command,
format, allocation, IOCTL, and generated-code cases.

**Exit:** at least one memory-corruption and one dangerous-operation fixture
have a reproduced observed path plus a solver-generated neighboring input,
validated by running the real compiled binary.

### W9 — Persistence and analyst surfaces

- [ ] Add capture/run identities to `.glaurung` without weakening manual
  precedence.
- [ ] Persist modules, mappings, observations, runtime xrefs, events, and
  findings with provenance.
- [ ] Support multiple runs of the same exact binary.
- [ ] Compare good/bad and build-to-build runs.
- [ ] Add CLI surfaces for capture, import, run summary, crash explanation,
  observed xrefs, mapping history, and evidence export.
- [ ] Make JSON the stable automation contract; keep terminal rendering pure.
- [ ] Route LLM tools only to persisted deterministic facts, never raw secret
  memory by default.

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
- [ ] Add AArch64 only after Linux x86-64 exit criteria hold.
- [ ] Add network-service request capture after file/stdin provenance works.
- [ ] Add arbitrary attach only with an explicit security and authorization
  design.
- [ ] Add Windows minidump/KDNET or driver/IOCTL workflows only through the same
  capsule and evidence model.

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

Implement **M0/W0**, not process memory reading:

1. Define `runtime-sample-oracle-v1` beside the manifest.
2. Populate exact semantic expectations for five representatives:
   `normal_open_file`, `crash_null_write`,
   `memory_struct_field_overwrite`, `danger_rw_to_rx`, and
   `danger_bind_listener`.
3. Make the harness emit a deterministic, hashed matrix ledger.
4. Add negative controls proving the oracle is not handed to the analyzer.
5. Specify `glaurung-process-capsule-v1` from the evidence those five cases
   actually require.

This increment establishes the measurement contract before implementation
choices harden around today's ad hoc `/proc` directory layout.
