# Runtime process capsule

> **Kind:** architecture · **Status:** maintained

`src/runtime_analysis/capsule.rs` defines the first provider-neutral runtime
artifact, `glaurung-process-capsule-v1`. It is captured evidence, not a live
process handle, static `ProgramImage`, emulator state, or decompiler IR.

The model has validated canonical JSON and CBOR representations. The runtime
sample harness emits it for stopped live children through the Rust-backed
`glaurung.runtime_analysis` binding and imports Linux x86-64 ELF cores into the
same contract. Exact runtime/static correlation consumes these capsules;
the crash analyzer consumes both snapshot and normalized event evidence, while
corruption analysis remains unimplemented.

## Ownership boundary

```text
ProgramImage                     ProcessCapsule
immutable file bytes             captured process evidence
static image addresses           process-scoped virtual addresses
sections and file mappings       runtime mappings and module instances
possible program structure       snapshot state and observed events
           │                            │
           └── evidence correlation ───┘
```

Runtime bytes never replace or extend `ProgramImage.bytes`. A captured page
names its process and mapping and refers to a separately stored payload by ID,
length, sensitivity, and SHA-256. An omitted page records why it is absent.

Runtime objects and object snapshots are separate from pages. A page says which
virtual-address bytes one process snapshot captured. A runtime object says that
one allocation or storage instance existed over a bounded lifetime, while an
object snapshot records an object-relative byte interval at one event position.
This permits before/after bytes at the same virtual address without creating
overlapping pages or mutating `ProgramImage`. Object kinds are stack, global,
heap, mapping, or unknown; they are runtime classifications, not recovered
decompiler variables.

## Top-level contract

`ProcessCapsule` contains:

- schema and version;
- capture identity, acquisition mode, host, kernel, and capture time;
- runtime target and exact executable artifact identity;
- process and parent identities with terminal state;
- exact module instances and their runtime mappings;
- mappings with range, permissions, backing, file offset, and optional module;
- threads, provider-spelled register observations, and optional terminal fault;
- bounded stdout/stderr records whose sensitive bytes are stored as separately
  hashed payloads;
- sparse page metadata and external payload references;
- runtime object instances with process, mapping, kind, extent, and event-scoped
  lifetime;
- bounded object-relative byte snapshots at explicit event positions;
- bounded descriptor metadata;
- per-process or per-thread ordered events;
- producer, command, input artifacts, and warnings;
- requested-versus-obtained completeness records; and
- optional extension values preserved across import and export.

The raw register spelling remains explicitly provider-owned. Projection from a
core/debugger register into Glaurung's target storage model is a correlation
relation that has not landed; the capsule does not reuse `VReg::Phys` as runtime
identity.

## Wire encodings

JSON and CBOR are two encodings of the same validated Rust model; neither is a
second schema. Canonical JSON is compact UTF-8 with one trailing newline.
Canonical CBOR is the byte output of the pinned `ciborium` encoder after the
same model normalization. Arrays whose order is not evidentiary are sorted by
their stable IDs or documented tuple keys, and extension maps use sorted keys.
Both readers apply the same manifest/count/page budgets and reject trailing
CBOR data. Artifact identities should hash the canonical bytes, including the
JSON newline when JSON is the artifact.

This is a Glaurung byte-stability contract for schema version 1, not a claim
that arbitrary third-party CBOR encoders will emit identical bytes. A consumer
may accept another valid CBOR representation, but must re-encode it before
using canonical-byte identity.

## Artifact and payload identity

Executables, modules, and provenance inputs carry SHA-256 and byte length, plus
optional build ID and display path. Paths are presentation evidence, never
identity.

Invocation bytes are represented separately as `InputBytesIdentity`: a
provider-scoped role, SHA-256, byte length, and sensitivity, but never the raw
value in public metadata. The live provider binds its executable, every raw
procfs artifact it retained, and the exact scenario argument. The core provider
binds the supplied core, supplied executable, and caller-supplied invocation
input. Thus a capsule cannot silently drift to a different binary, core,
procfs snapshot, or test input while retaining the same provenance record.

`glaurung.runtime_analysis.process_capsule_input_provenance` projects these
records into stable, execution-scoped input-source identities. Individual
bytes use the compact identity `(source_id, offset)` and can be resolved with
`resolve_process_capsule_input_byte`; the returned ID is deterministic for the
same canonical capture and changes when the capture, source role, content
identity, length, or offset changes. This avoids materializing an
attacker-sized list while still giving later LLIR provenance an unambiguous
byte endpoint. The projection identifies bytes but does not disclose their
values or claim that they reached any operation.

Captured page bytes are not embedded in public metadata. `PayloadReference`
contains:

- a capsule-local payload ID;
- lowercase SHA-256;
- exact byte length; and
- `public`, `sensitive`, `secret`, or `unknown` sensitivity.

The bundle importer accepts an explicit payload directory whose regular files
are named `<payload-id>.bin`. It requires the directory to contain exactly the
referenced payload set and verifies every byte length and SHA-256 before
returning bytes to a consumer. Payload IDs are identifiers, not paths.
`glaurung runtime import` consumes those already-opened and verified Rust-owned
bytes directly when persisting a capture; it does not validate a path and then
reopen it from Python.

## Completeness

`CompletenessRecord` names one evidence class, whether it was requested, its
status, obtained count, optional expected count, and reason. Status is one of:

- complete;
- partial;
- omitted;
- denied;
- raced;
- unsupported;
- truncated; or
- unknown.

A record marked complete cannot have an obtained count different from its
expected count. Completeness of a capsule or core import says nothing about
execution-history completeness.

## Validation

`ProcessCapsule::from_json` applies a manifest-size budget before parsing and
then validates:

- exact schema and version;
- rejection of unsupported required features;
- non-empty bounded textual identities;
- lowercase 64-digit SHA-256 values and non-zero artifact lengths;
- supported address widths;
- independent count, captured-page-byte, and object-snapshot-byte budgets;
- unique process, module, mapping, thread, payload, and completeness IDs;
- all process, thread, module, mapping, page, descriptor, and event references;
- module/mapping ownership consistency;
- non-empty mapping ranges;
- page containment in the named process mapping;
- object containment in its named mapping when one is known;
- object-snapshot containment in its runtime object and exact event-position
  references;
- payload length matching its page;
- register value width matching its hexadecimal representation;
- event threads belonging to their process; and
- strictly increasing sequence numbers within each process/thread stream.

Unknown optional top-level extensions are retained through a canonical JSON
round trip. Unknown required features fail closed.

## Canonical JSON

`to_canonical_json` validates before serialization and sorts unordered record
collections by stable identity. `BTreeMap` supplies deterministic key ordering,
and the output is compact UTF-8 JSON terminated by one newline.

Event order is semantic rather than cosmetic. Events are validated in their
supplied per-stream order before canonical serialization; the serializer does
not repair duplicate or reversed sequence numbers.

The canonical bytes are suitable for hashing and reproducibility comparisons.
They are not a signature format and do not establish trust in the producer.

## First live provider

`glaurung.runtime_capture.capture_stopped_child` is the first shipping live
acquisition surface. It accepts an executable and arguments, never an existing
PID. It launches the child in a new process group, waits for a cooperative
`SIGSTOP`, captures bounded procfs metadata, validates the result through the
Rust capsule implementation, and kills only that owned process group before
returning. Descriptor targets are omitted and marked redacted. Mapping and
thread snapshots are read twice: agreement is complete evidence, while change
is retained as raced completeness rather than silently accepted. While the
owned group is stopped, the provider privately attaches to each enumerated TID
and records the same 27 x86-64 kernel register fields used by the core importer.
It detaches each TID before cleanup and retains per-TID attach, wait, read, or
detach failures in the provider extension.

The Python API and `glaurung runtime capture` do not inherit the caller's
environment by default. Callers may supply individual child environment values;
copying the full caller environment requires the explicit
`inherit_environment`/`--inherit-environment` switch. The CLI accepts an exact
binary and child arguments but no PID, validates and persists the returned
capsule, and emits the same persisted summary used by the read-only runtime
surfaces.

For every captured thread, the provider selects the unique pages containing
its observed RIP and RSP. It reads each page with `process_vm_readv`, stores the
bytes only in separately returned sensitive payloads, and puts their length and
SHA-256 identity in public capsule metadata. `/proc/<pid>/mem` is disabled by
default and is used only when the caller explicitly enables fallback. Missing,
unreadable, permission-denied, and partial reads remain omitted page records
and provider read outcomes rather than zero-filled bytes.

The surface does not yet distinguish every procfs permission error or
disappearing thread as an empty observation. The `acquisition_outcomes`
extension instead keys proc files, register sets by TID, page reads by payload
identity, module backings by device/inode, mapping revalidation, thread-set
revalidation, and descriptor collection independently. Outcomes distinguish
captured, denied, disappeared, partial, raced, truncated, and unknown states;
mapping snapshots retain both hashes and thread-set races retain appeared and
disappeared TIDs. There is deliberately no arbitrary-PID attach API; ptrace and
memory reads are implementation details scoped to children created and owned
by the capture call.

`stable_live_capture_projection` defines the W3 repeatability comparison. It
retains target and exact artifact identities, mapping lengths/permissions and
backing kinds, register shapes, page availability, redacted descriptors,
controlled-input identity, and completeness. It excludes capture IDs,
timestamps, OS PIDs/TIDs, raw virtual addresses, register values, page bytes,
paths, and provider extensions. This is narrower than the later live/core
semantic-equivalence projection.

The exact main executable receives both a full-file SHA-256 and, when present,
its GNU build ID. Live and core acquisition call the same Rust ELF parser for
that build ID, and a cross-provider real-binary gate requires equality. Other
executable file backings are opened first through the kernel-owned
`map_files` handle. When host policy denies that path, the provider may open
the observed pathname with `O_NOFOLLOW`, but accepts it only when the opened
file's device and inode exactly match the mapping snapshot. It then reads the
file within per-artifact, aggregate-byte, and count budgets, records SHA-256
and GNU build ID, groups every mapping of that backing into a module instance,
and retains the artifact in provenance. Deleted, replaced, symlinked,
oversized, denied, or changed backings remain explicit failures; an observed
pathname alone is never promoted to module identity.

`tools/runtime_sample_harness.py live` translates one procfs snapshot into the
canonical model and publishes `process-capsule.json` atomically beside the raw
capture. It records the exact fixture executable as a module only when a maps
entry resolves to that executable. Other file mappings remain unknown because
a pathname is not artifact identity.

The provider enumerates mappings, task IDs, and descriptors. It deliberately
does not synthesize register values or page contents: registers are marked
unsupported and pages not requested. Procfs collections are marked raced
because separate reads are not an atomic process snapshot. The raw procfs files
remain provider evidence and their hashes are retained in the
`provider.procfs` optional extension.

Python does not reimplement the schema validator. The
`glaurung.runtime_analysis` extension exposes validation and canonicalization
functions backed by the Rust `ProcessCapsule` implementation and default import
budgets.

## First mapping-trace providers

`glaurung.runtime_capture.capture_traced_child_core` launches one owned Linux
x86-64 child under a mapping-only `strace` scope. It has no existing-PID attach
surface. Core size is governed by the core importer; raw trace and process
outputs have separate acquisition budgets. Host suppression or redirection of
the core, multiple core candidates, oversized output, malformed UTF-8, and
capsule validation errors fail explicitly.

`glaurung.runtime_capture.capture_mapping_trace_child` applies the same bounded
event scope to a normally exiting owned child. It emits terminal status and
hash-bound stdout/stderr payloads in the same capsule rather than requiring a
core. Timeout cleanup targets only the new process group. The traced child PID
comes from provider output rather than being confused with the `strace`
process, and both the executable and public invocation input remain
hash-bound. Its bounded scope also includes `openat`. File paths are
hash/length-only unless the caller explicitly authorizes an exact path through
the capped `public_paths` argument.

The provider parses successful `mmap`, `mprotect`, and `munmap` results into
provider-neutral `mapping_create`, `mapping_protect`, and `mapping_remove`
events. Each event carries process/thread scope, a strictly increasing stream
sequence, range start and length, normalized permissions, result status, and
the provider syscall name. The public extension records the exact trace hash,
length, selected syscall scope, normalized count, truncation status, and loss
count. The raw trace is discarded and is never accepted by an analyzer.

These providers establish narrow history sufficient to prove the two guard
page fixtures and the permission history of `danger_rw_to_rx`. They do not
claim complete syscall tracing or close the W7 mapping-event workstream. In
particular, completeness applies only to the requested mapping syscall scope,
not to all execution history or whether bytes in a mapping executed.

The provider-neutral consumer is the
[runtime mapping behavior report](runtime-mapping-behavior.md). It reconstructs
exact-range lifetimes and protection changes without importing provider state
into the static program model.

The [runtime file behavior report](runtime-file-behavior.md) separately
normalizes file resources, descriptor duplication, selected reads,
open/write/close lifecycles, and separate path-based
metadata observations. Path and content
disclosure require separate caller authorization, and the native consumer
hash-verifies either before treating it as observed. Mapping and file
completeness are independent even though this first acquisition provider
captures both scopes.

The [runtime descriptor behavior report](runtime-descriptor-behavior.md) owns
non-file resources such as pipes. It retains endpoint handles and roles under a
runtime resource ID rather than pretending a pipe is a file or a static memory
object. IPC content has an independent disclosure policy bound into capture
identity.

Successful non-empty selected file reads and descriptor reads/receives also
create capsule input-provenance sources. The source name is derived from the
event's process, thread scope, sequence, and kind, while its public identity
retains only content SHA-256, byte length, and sensitivity. Publicly authorized
content is marked `public`; redacted content remains `sensitive` without
placing plaintext in capsule metadata. The normalized read/receive observation
links back to that source name, and callers can resolve a compact stable byte
identity as `(source_id, offset)`. This establishes which bytes entered the
process at one observed event. It does not claim that those bytes reached any
later LLIR value, branch, address, or memory write.

`correlate_process_capsule_input_events` can join that event and source to the
exact immutable-image LLIR call occurrence when the provider captured a valid
main-module return frame. The runtime source remains capsule-owned and the
static operation remains image-owned; only the occurrence relation connects
them.

The mapping-trace provider can also supply at most 1 MiB of caller-owned stdin
bytes through a pipe. Descriptor zero reads become `descriptor_stdin_read`
events with the provider kind, requested and returned lengths, content
identity, and the same occurrence correlation. Plaintext is omitted unless
`public_stdin_content=True`; the disclosure choice is part of capture identity.
Oversized stdin is rejected before launch. The default remains `/dev/null`.
For supplied stdin, the provider combines raw `read` arguments with strace's
bounded descriptor-zero byte dump. The normalized event therefore retains the
concrete destination address and returned byte interval as well as content
identity; a missing or truncated dump fails acquisition.

Callers may separately request `capture_read_destinations=True`. In that mode,
the bounded tracer records raw arguments and returned-byte dumps for all read
descriptors, then normalizes only resources already selected by file or IPC
policy. Loader and unrelated reads do not become public inputs. This mode can
attach concrete destination ranges to selected file and pipe reads; incomplete
returned-byte dumps fail rather than producing partial content identity.

Callers may additionally request `capture_read_checkpoint=True` together with
destination capture. The provider enables the corpus child's existing
cooperative exit stop, waits for `strace` to identify that actual `SIGSTOP`,
and reads the affected bytes from the same stopped execution. It publishes the
containing `[stack]` mapping, a mapping-kind runtime object, and an exact
object-relative snapshot whose sensitive payload must agree with the traced
read. The checkpoint also retains the exact mapping table, main-module
identity, observed RIP/RSP, and bounded hash-verified stack bytes. These remain
provider-neutral capsule evidence. The separate [runtime stack-write
relation](runtime-stack-writes.md) may use them to realize a DWARF object and
field; the capsule itself still claims only stack-mapping containment. The
provider resumes only its newly created process group.

## First environment-read provider

`glaurung.runtime_capture.capture_environment_trace_child` launches one owned
Linux x86-64 child under a bounded `ltrace` `getenv` scope. Callers must name
between one and 64 variables, and every selected variable must be supplied
explicitly rather than inherited implicitly from the acquisition process. The
provider rejects a selected call that is absent, malformed, truncated, or over
the 1 MiB per-value budget.

Each actual selected `getenv` call becomes an `environment_read` event with
process/sequence scope, variable name and hash, present/missing result, and a
hash/length identity for returned bytes. Values are redacted by default;
`public_environment` is a separate subset authorization incorporated into
capture identity. Successful non-empty values receive the same stable
input-source and per-byte identities as file, socket, and stdin inputs. Raw
`ltrace` text is discarded after its bounded hash is recorded.

The event retains the provider-observed raw caller PC, but this provider does
not capture mappings. That address therefore remains runtime-only and is not
joined to static code by subtracting a guessed PIE base. A future combined
provider must add exact module/mapping evidence before producing an operation
occurrence.

## First heap-object snapshot provider

`glaurung.runtime_capture.capture_heap_snapshots_child` launches one owned
Linux x86-64 child with an exact caller-supplied interposer. Both executable and
provider are hash-bound in capsule provenance. The provider currently observes
`calloc`, matching `free`, and `memset` writes whose destination begins inside
an observed live object. It uses fixed storage for at most 1,024 live objects
and captures at most 256 bytes per object endpoint. Its final summary reports
dropped records, and any loss makes acquisition fail rather than appear
complete. Raw provider records and stdout/stderr are independently bounded.

Each observed allocation becomes a heap `RuntimeObjectRecord`, allocation and
deallocation events, and object-relative snapshots immediately after `calloc`
and immediately before `free`. An intercepted `memset` adds a bounded
provider-neutral `memory_write` event with object identity, address, and byte
length. It also retains the observed caller return address and the loader's
main-module PT_LOAD extent and `dlpi_addr` load bias when the caller belongs to
that module. The provider neither reads nor depends on glibc allocator
metadata. It has no existing-PID surface.
This is a fixture-oriented first provider, not portable allocator coverage:
arbitrary machine stores, other copy/write APIs, `malloc`, `realloc`, aligned
allocation, objects still live at process exit, other C libraries, and other
architectures remain explicit future scope.

## First postmortem provider

`src/runtime_analysis/elf_core.rs` imports Linux x86-64 ELF cores through the
same capsule model. It accepts core and exact-executable bytes from its caller;
it never opens an `NT_FILE` pathname on the importing host. The importer:

- validates `ET_CORE`, architecture, endianness, counts, note sizes, and file
  ranges before interpreting provider data;
- imports `NT_PRSTATUS` register sets, `NT_SIGINFO`, `NT_PRPSINFO`, `NT_AUXV`,
  and `NT_FILE`;
- records FP and XSAVE note identities and lengths without creating invented
  scalar-register projections;
- creates mappings and sparse captured/omitted ranges from `PT_LOAD` segments;
- returns captured bytes as separate sensitive payloads bound by ID, length,
  and SHA-256; and
- identifies the main module only when an `NT_FILE` pathname agrees with the
  supplied executable path and at least one captured file range agrees with
  the supplied executable bytes.

Linux writes process-wide notes immediately after the dumping thread's first
thread-specific `NT_PRSTATUS`. The importer therefore associates `NT_SIGINFO`
with the active thread-note group instead of matching `pr_cursig`: Linux fills
the same fatal signal into every thread's status. The committed
`threaded_worker_fault.c` support fixture proves this distinction with a worker
TID that differs from the process leader while the leader is blocked in
`pthread_join`.

`siginfo_t` is interpreted by origin as well as signal number. The importer
reads `_sigfault.si_addr` only for positive, signal-specific `si_code` values.
User-generated origins such as `SI_TKILL` retain their signal, code, sender
PID, and sender UID but no address; those fields come from the appropriate
`_kill` union arm and are never presented as a fault address.

Core acquisition can attach complete stdout and stderr as `outputs` after the
process terminates. Each record is process-scoped, stream-typed, marked for
truncation, and bound to a separate sensitive payload by length and SHA-256.
Output count and aggregate bytes have independent capsule limits. Bundle import
requires the exact union of page and output payloads; output text is never
trusted merely because it appears in public metadata.

The harness can also emit a minimal terminal-result capsule from completed wait
status. It records the exact executable, PID, exit/signal state, invocation-byte
identity, and hashed stdout/stderr, while explicitly omitting mappings, threads,
and pages. This gives good controls a positive artifact and lets crash analysis
return `no_crash`; absence of a core file is not used as the evidence.

The harness writes payloads mode `0600` below a capsule-hash-named directory,
rejects unsafe IDs, symlink substitution, length disagreement, and hash
disagreement, then atomically publishes the public capsule metadata. A core
whose host policy suppressed collection remains an explicit no-artifact result.

`src/runtime_analysis/bundle.rs` is the corresponding fail-closed consumer. It
reads bounded metadata, validates it through `ProcessCapsule`, rejects missing
or unreferenced files, opens payloads without following symlinks, checks file
identity across the open/read boundary, and then verifies declared length and
hash. The Python binding exposes the importer for harness and integration tests;
it does not weaken the Rust validation boundary.

## Current proof boundary

The v1 hostile-input matrix is explicit rather than open-ended:

| boundary | fail-closed cases |
|---|---|
| encoding | malformed/truncated JSON and CBOR, trailing CBOR data, wrong schema/version, unsupported required feature, manifest budget |
| graph | duplicate identities, dangling/cross-process relations, invalid mapping/page ranges, event-order and completeness disagreement |
| identity | malformed artifact/payload/input hashes, duplicate input roles, page/payload length disagreement |
| bundle | unsafe payload ID, missing/extra/truncated/corrupt payload, metadata or payload symlink, payload-directory symlink |
| resources | process/module/mapping/thread/page/descriptor/event/extension counts and aggregate page-byte budget |

These are parser and storage-boundary claims. They do not claim resistance to
resource exhaustion outside the declared budgets or compromise of the process
performing the import.

Unit tests currently prove:

- canonical JSON round-trip stability;
- explicit missing-page acceptance;
- cross-reference and page-containment rejection;
- unknown optional extension preservation;
- unknown required-feature rejection;
- exact executable, provider-artifact, and invocation-byte identity;
- payload hash/length validation;
- bundle rejection of traversal IDs, symlink payloads, missing or extra files,
  truncated bytes, and same-length hash corruption;
- per-thread event-order validation; and
- count, manifest-size, and page-byte budget enforcement.

One real stopped-child test additionally proves that the live provider emits an
exact executable identity, executable mapping relations, explicit omissions,
atomic output, and byte-stable Rust re-import. It does not prove procfs
acquisition completeness.

A second real stopped-child test exercises the shipping product API against a
compiled corpus program. It proves child ownership and cleanup, stable mapping
and thread revalidation, bounded redacted descriptors, canonical Rust
validation, complete register capture, and explicit omitted-page evidence. A
two-thread support fixture separately requires complete register sets for both
the main and worker TIDs. Both tests require hash-verified sensitive PC/SP page
payloads produced by the default `process_vm_readv` path. The dynamically
linked fixture also requires exact main, loader, and C-library module artifacts,
mapping-to-artifact hashes, build IDs, and provenance membership.

The W3 population gate performs 210 real captures in the GCC `-O0` PIE lane:
both good and bad entry checkpoints for all 60 samples, plus both good and bad
exit checkpoints for all 45 non-crashing samples. Every cell must produce a
canonical capsule with threads, pages, and separate payloads. A repeated real
capture separately proves equality under the stable projection while requiring
the raw capsules to differ.

A real `crash_null_write` core test proves import of the terminal signal,
fault address, RIP, exact executable/build identity, five main-image mappings,
sparse payloads, and explicit omitted ranges. A separate real two-thread core
proves that the worker fault is attached to its TID and not to the process
leader. The Tier-C GCC `-O0` PIE gate imports all 15 bad crash cases, checks
their expected terminal signal, and verifies that deliberate `raise` cases do
not acquire a fabricated fault address. These tests do not yet prove
live/core equivalence, runtime/static correlation, or analyzer behaviour.
Those remain later gates.

The next consumer is the
[runtime-to-static correlation relation](runtime-static-correlation.md), which
uses capsule identity and mapping evidence without copying runtime state into
`ProgramImage`.
