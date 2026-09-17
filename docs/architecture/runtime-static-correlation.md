# Runtime-to-static address correlation

> **Kind:** architecture · **Status:** maintained

`src/runtime_analysis/correlation.rs` implements the first typed relation
between a `ProcessCapsule` and an immutable `ProgramImage`. It does not add
process state to `ProgramImage` and does not treat a raw VA or load bias as a
static address.

## OS-event callsites

The same identity discipline applies before an OS event is connected to static
semantics. The bounded Linux trace provider may retain a main-executable user
return frame, but the normalized event stores only the exact artifact SHA-256,
module-relative return offset, and provider symbol spelling. Library paths and
raw stack text do not enter the capsule event.

`correlate_process_capsule_ioctl_events` and
`correlate_process_capsule_input_events` implement this relation. They require
the supplied immutable `ProgramImage` to match both the
capsule executable and frame artifact identities, converts the module-relative
offset through the image's declared base for PIE and non-PIE, decodes the
preceding direct call, and requires a stable LLIR `call` operation at that
machine instruction. Its report keeps the observed event occurrence separate
from the inferred static callsite. A missing frame, wrong image, altered return
offset, indirect-call encoding, absent function, or lift failure remains typed
unknown.

For an exact call, the report also emits an `OperationOccurrence` with stable
identity, occurrence scope, static code origin, the observed descriptor,
request and scalar argument, the kernel result, and the linked file-IOCTL
effect. Input-byte identities remain separate until a propagation relation
proves the join. The occurrence must not infer taint merely because the callee
is an IOCTL wrapper.

For successful selected file reads, pipe reads, and socket receives, the input
event report additionally joins the capsule input-source identity to the exact
LLIR call occurrence that introduced those bytes into the process. The
occurrence retains descriptor and requested length as call inputs, returned
length as output, and the source identity as an introduced process input. This
is not downstream taint: it does not claim that a later LLIR value, branch,
address, or write derived from those bytes. Missing source identity, wrong
image/frame identity, or a non-call return location leaves the occurrence
unknown.

The supplied-stdin lane adds one stronger effect: raw syscall arguments and a
bounded returned-byte dump prove the concrete destination range, so the LLIR
call occurrence carries `(address, byte_len, input_source_id)` as an observed
runtime memory effect. This is not rewritten into static MemorySSA and does not
claim provenance beyond the call's write.

`memory_read_overflow` exercises the same relation on a tracked pipe: good and
bad executions produce 8-byte and 12-byte source-to-memory effects at exact
LLIR call occurrences. An optional same-execution checkpoint independently
reads those exact bytes and publishes their containing stack mapping plus a
mapping-scoped object snapshot. The relation still deliberately stops at the
runtime range: a stack mapping is not the recovered `struct box`. The separate
[runtime stack-write relation](runtime-stack-writes.md) now derives the `main`
frame from captured stack records, applies GCC's CFA-relative or Clang's
RBP-relative DWARF contract, and resolves the 12-byte `b` object and eight-byte
`dst` field. The bad 12-byte read therefore has four evidence-backed bytes
beyond the field while remaining within the enclosing object. No address-based
or canary-name assumption participates in that result.

## Runtime identity endpoints

`RuntimeModule`, `RuntimeMapping`, and `RuntimeAddress` are explicit
capture/process-scoped correlation endpoints. `runtime_identity_graph`
projects the validated capsule records for one process without copying them
into `ProgramImage` or making `ProgramSession` own mutable process state. A
module retains exact artifact identity and mapping IDs. A mapping retains raw
range, permissions, backing, optional file offset, and optional module
membership. Anonymous and special mappings therefore remain valid runtime
identities with no invented module.

`RuntimeAddress` similarly makes module membership optional. Exact static
resolution still requires a proven module and produces `Some(module_id)`;
unowned runtime addresses can exist as runtime facts without pretending they
resolve to the static image. The Python
`process_capsule_runtime_identities` surface returns this graph and rejects an
absent process ID.

## Resolution contract

For one process ID and runtime VA, resolution requires:

1. exactly one containing mapping in that process;
2. a mapping-to-module relation already validated by the capsule;
3. file-backed mapping identity equal to the module artifact identity;
4. module SHA-256 equal to the supplied `ProgramImage` bytes;
5. build-ID equality when the capsule provides a build ID;
6. a checked runtime-VA-to-file-offset calculation; and
7. one unambiguous file-offset-to-static-VA result from the image index.

Address identity and instruction semantics are separate gates. If an
authenticated captured instruction byte differs from the image, or its
declared payload is missing or invalid, the raw/module/file/static address
relation may remain exact but static code and LLIR semantics are withheld. A
consumer cannot turn a correct load-bias calculation into authority to decode
contradicted bytes.

The result retains capture, process, mapping, module, raw VA, file offset,
static VA, module-relative address, and image SHA-256. Failure is typed as
missing, ambiguous, wrong image, or invalid capsule. Paths and basenames are
never identity evidence.

After exact image-address resolution, the same immutable `ProgramImage`
`.eh_frame` index supplies an independent function-boundary relation. Its
verdict is `exact`, `interior`, `ambiguous`, or `missing`; exact and interior
results carry the authoritative interval and an optional static symbol name.
Absence of unwind metadata remains missing rather than becoming a guessed
nearest symbol.

For an exact or interior function result, address-scoped CFG discovery reuses
the existing static analysis pipeline. The code-location relation identifies
the containing basic block and decodes forward from its leader to the
instruction covering the PC. It reports resolved, ambiguous, incomplete, or
missing; a discovery budget recorded on the static `Function` becomes an
incomplete result with the fired budget names. The decoded instruction records
whether the PC is exactly at its start or in its interior.

The same targeted function is lifted through the existing image-aware LLIR
lifter. Every LLIR operation whose source VA is the resolved machine
instruction carries exact image SHA-256, function entry, machine VA,
machine-operation ordinal, and the `glaurung-raw-llir-v1` lift profile, alongside
its lift-local LLIR block start, operation index, and operation kind. These
indices are not durable across lifter revisions: the profile identifies the raw
unoptimized representation, not a content-addressed implementation version.
Persistence across implementation revisions must additionally bind producer
revision and an exact serialized lift artifact before treating these as durable
operation identities. Lift failure and a valid
instruction that emits no LLIR operations are separate outcomes. These are
static semantic relations; they do not assert that every operation completed at
runtime merely because the containing instruction was the captured PC.

`ProgramImage::file_offset_to_va` is the shared static seam. It de-duplicates
segment/section mappings that yield the same VA and fails closed if one file
offset maps to different VAs.

## Byte evidence

Address identity does not imply byte identity. The relation separately reports:

- captured byte matches the static image;
- captured byte differs from the static image;
- captured payload is unavailable or fails its declared hash/length;
- the capsule explicitly omitted the byte and why; or
- the file-backed range was not captured.

No case mutates `ProgramImage`. An omitted core code page remains omitted; the
resolver does not silently use the executable as if those bytes were observed.
A later decoder may request a proven static fallback, but that is a separate
policy and must preserve this byte-origin record.

Captured byte disagreement and invalid/unavailable declared payloads now also
make `StaticCodeResolution` missing with an explicit reason. This prevents a
later consumer from attaching stale file-decoded operations while overlooking
the adjacent byte-status field. A page that was never requested or was
explicitly omitted may still carry separately labelled static-image semantics,
but never an observed-runtime-byte claim.

`classify_runtime_pages` applies the same rule to complete captured ranges.
Each result retains capture, process, mapping, range, and payload availability.
Anonymous backing is classified directly without inventing a file. Unknown and
special backing remain unknown. A file-backed range becomes unchanged or
modified only when its artifact SHA-256 equals the supplied `ProgramImage`, its
file offset is valid, and its complete payload passes declared length and hash
checks. Modified results report the first changed offset and exact changed-byte
count. Omitted, invalid, absent, wrong-image, or out-of-file bytes remain
unknown rather than being compared against guessed data.

The Python `classify_process_capsule_pages` surface exposes these typed
relations. The live provider captures bounded PC/SP pages plus executable pages
of the exact main module, prioritised under a 64-page cap, so a real process
proves unchanged code-page classification. Rust fixtures independently prove a
one-byte modification, anonymous backing, and unknown backing.

## Project persistence

`glaurung.llm.kb.runtime_relations.resolve_and_persist_address` is the durable
boundary for an exact address relation. It calls the native resolver rather
than accepting a caller-authored normalized address, verifies that the exact
image hash is the binary selected by the `.glaurung` project, and stores both
address namespaces with capture, acquisition, process, mapping, and module
provenance. The capsule artifact bytes are SHA-256 bound to the row.

`runtime_address_relations` is an append-only measurement table. It is not the
static `xrefs` table and has no `set_by` or annotation setter: runtime evidence
cannot overwrite a manual name, type, comment, stack variable, or decompiler
fact. Re-importing the same relation is idempotent, while another capture of
the same static address remains a distinct row. Function and code relations
are retained as canonical JSON evidence; concrete operation values and event
occurrences are not stored here and will require their own execution-scoped
records.

The enclosing execution identities now persist separately in `runtime_runs`
and `runtime_captures`. The public capsule writer validates the full native
schema, binds the executable hash to the selected project binary, and treats
the exact capsule bytes as immutable evidence. Two acquisitions of the same
binary remain distinct captures and may be assigned to explicit runs; neither
table changes the static address relation or annotation precedence. Modules,
mappings, occurrences, and findings still require their own capture-scoped
records rather than being hidden in the run row.

Processes, threads, modules, mappings, and raw events now have those normalized
capture-scoped records. They retain provider spellings and evidence—including
register observations and mapping backing—without promoting it into static
state. Event sequence remains meaningful only in its recorded process/thread
stream. Runtime objects, operation occurrences, findings, and observed xrefs
remain open persistence work.

## Current evidence and limit

Rust tests prove exact PIE-style mapping, same-basename wrong-image rejection,
overlapping mapping ambiguity, payload verification, matching captured bytes,
and modified captured bytes with stale semantics withheld. Two disjoint loads
of one artifact retain distinct module/mapping/raw identities while resolving
to the same static VA. Missing and explicitly omitted pages retain typed byte
absence rather than claiming runtime bytes. They also prove a graph containing
both an exact module mapping
and an anonymous mapping with no module identity, plus full-page unchanged,
modified, anonymous, and unknown classifications. A real live capsule projects
all captured modules and mappings through the shipping Python surface. Real
`crash_null_write` cores resolve their RIPs across the
GCC/Clang, `-O0`/`-O2`, PIE/non-PIE matrix. The gate proves PIE ASLR
normalization, identity-preserving non-PIE translation, split-mapping file
offsets, and wrong-build rejection in all eight cells. On the current host, the
clean code page is absent from each core and remains an explicit
`provider_unsupported` omission.

This primitive now resolves functions backed by exact unwind intervals, static
basic blocks, decoded instructions, and their source-addressed LLIR operations.
The eight-cell indirect-control trace reports every analyzed-image PC as the
coverage denominator, resolves all of them exactly, rejects a wrong image, and
persists occurrence-scoped indirect targets without modifying the static CFG.
Together with the null-write different-build matrix and the adversarial Rust
controls above, this satisfies the stated W4 and Objective 2 exits.
