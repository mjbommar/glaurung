# Runtime file behavior report

> **Kind:** architecture · **Status:** maintained

`src/runtime_analysis/behavior.rs` produces
`glaurung-runtime-file-behavior-report-v1` from provider-neutral `file_open`,
`file_read`, `file_write`, `file_close`, `file_dup`, `file_stat`, `file_chmod`,
and `file_ioctl` events in a validated
`ProcessCapsule`. The Python surface is
`glaurung.runtime_analysis.analyze_process_capsule_file_behavior`.

An open observation retains process, optional thread, event sequence, stable
resource ID, flags, optional creation mode, path hash and length, and either the
returned descriptor or errno. A write and close retain the same resource ID and
descriptor, so consumers can reconstruct the ordered lifetime without treating
a reused descriptor number as resource identity. Writes additionally retain
requested and returned lengths plus content hash and length.

A stat observation has its own operation-scoped resource ID, path evidence, and
either a normalized file type or errno. It is not fabricated as an opened
descriptor resource: `newfstatat` can address a path without establishing a
descriptor lifetime, and equal paths across operations remain distinct observed
occurrences.

A chmod observation likewise remains a path operation rather than an opened
descriptor lifetime. It retains an operation-scoped resource ID, hash-bound or
redacted path, requested mode, and kernel outcome. A successful mode with the
world-write bit set produces a `world_writable` finding; open-time mode alone
does not establish the post-`chmod` state.

A selected read observation retains the linked resource ID, descriptor,
resource-relative offset, requested and returned lengths, and bounded content
identity. Read events are normalized only for paths separately authorized in
`public_content_paths`; unrelated loader reads are omitted by acquisition
policy rather than converted into sensitive capsule payloads. A selected read
that cannot be normalized rejects acquisition instead of weakening a declared
complete selected-read scope.

Each successful non-empty selected read also carries the name of its capsule
input-provenance source. That source binds the event to content hash and byte
length and provides stable per-byte `(source_id, offset)` identities. The link
survives redaction: a sensitive source can identify incoming bytes without
publishing their values. This is event provenance only, not evidence that a
byte influenced a later static operation.

When the trace supplies an exact-image user frame,
`correlate_process_capsule_input_events` resolves the selected read to its
static LLIR call and emits an occurrence carrying the introduced input source.
The real gate covers GCC/Clang, `-O0`/`-O2`, and PIE/non-PIE builds. A missing
source or invalid frame fails closed.

A duplication observation links source and returned descriptor handles to the
same resource ID. Acquisition tracks the shared open-file-description offset by
resource rather than copying an offset onto each handle. Closing one duplicate
removes only that handle; resource state ends after the last handle closes. An
append write makes the resulting offset unknown unless later evidence restores
it, rather than guessing an end-of-file position.

Paths and write content are independently redacted by default. Acquisition
exposes a plaintext path only when the caller supplies that exact path in the
bounded `public_paths` set. It exposes write bytes only when the same path is
also listed in `public_content_paths`; content authorization never follows from
path authorization alone. The content set must be a subset of the path set.
Unrelated loader and library paths remain hash/length-only. Resource IDs include
process and thread scope, so equal per-thread sequence numbers cannot collide.

The analyzer never reads raw `strace` output. It accepts authorized plaintext
paths and content as observed evidence only after their recorded hash and length
agree; disagreement becomes unknown. Redacted values remain unknown with an
explicit reason. Successful descriptors, write lengths, closes, and failed
errno values remain observed kernel results.
`file_events` completeness is independent from mapping-event completeness.

An IOCTL remains an operation on the identified file resource rather than a
second descriptor object. The bounded Linux x86-64 provider reconstructs the
numeric 32-bit request from either a raw integer or strace's `_IOC(...)`
rendering, retains the scalar argument and kernel result, and rejects an
unsupported rendering on a tracked descriptor. It does not dereference an
IOCTL pointer argument or treat the request value as proof of input taint.
`scenario_selected -> ioctl` therefore remains unknown until static/runtime
provenance supplies an explicit relation; a suspicious constant alone cannot
produce `untrusted_ioctl_request`.

When the provider obtains a bounded user stack, it retains only the first frame
from the exact launched executable: artifact SHA-256, module-relative return
offset, and provider symbol spelling. No library paths are copied into the
normalized event. `correlate_process_capsule_ioctl_events` verifies the frame
artifact against the immutable `ProgramImage`, normalizes PIE and non-PIE image
bases, proves that the return is immediately after a decoded call, and requires
that instruction to resolve to a stable LLIR `call` operation. The report also
emits an `OperationOccurrence` scoped by capture, process, optional thread, and
event sequence. It attaches the observed descriptor, request, scalar argument,
kernel result, and file-IOCTL effect to that one static operation. It is still
not evidence that any input byte influenced the request.

The first real gates cover `normal_open_file`, `normal_create_file`,
`normal_write_file`, `normal_append_file`, `normal_stat_file`, and
`danger_world_writable`:

- the good case observes authorized `input.txt` opening successfully;
- the bad case observes authorized `missing-runtime-sample` failing with
  `ENOENT`;
- all other captured paths remain redacted; and
- neither case produces a dangerous-file-open finding;
- both create scenarios link `O_CREAT|O_TRUNC`, mode `0600`, the two written
  bytes `6f6b`, and successful close under one resource ID; and
- the same lifecycle logic covers the eight-byte `normal_write_file` payload,
  while `normal_append_file` derives its append fact from `O_APPEND` and the
  linked write rather than a provider-specific append event;
- tampering with public write content while retaining its original identity
  weakens that content to unknown and prevents a complete lifecycle fact; and
- authorized `/dev/null` metadata normalizes to `character_device`, while the
  missing-path control retains `ENOENT`; tampered path evidence becomes unknown;
  and
- both `normal_read_file` scenarios link `/dev/zero` to an offset-zero,
  16-byte all-zero read; content tampering prevents a complete semantic fact;
  and
- both `normal_dup_fd` scenarios preserve one `/dev/null` resource across the
  original and duplicated handles, attribute the write to the duplicate, and
  prove both handles closed. Removing either close destroys the positive chain
  and leaves leak absence unknown.
- both world-writable scenarios retain the authorized `permissions.out` chmod
  result and kernel mode; `0600` keeps the good control clean, while `0666`
  produces the typed finding and semantic fact. A malformed mode prevents both
  conclusions.

The produced semantic results fully satisfy both pairs of good/bad oracles, and
mutating a produced open result or lifecycle makes evaluation fail. Successful
creation with a group- or world-writable mode produces an
`unsafe_file_create` finding. This report does not yet model `dup2`/`dup3` or
descriptor inheritance, file identity, rename, full stat metadata, arbitrary seeks, partial writes as a continued
logical operation, or write content beyond the provider's bounded trace string.
An unnormalizable `openat` or selected operation on a tracked file resource rejects
acquisition instead of being silently omitted from a complete scope. An empty
finding set is scoped only to the implemented rules and the complete captured
`openat,newfstatat,chmod,read(selected-content),write,close,dup,ioctl` event
scope.
Hash-bound selected-read bytes now have W8 stable input-byte IDs, but their
provenance is not yet carried through LLIR operations.
