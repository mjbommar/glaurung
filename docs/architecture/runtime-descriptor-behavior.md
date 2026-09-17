# Runtime descriptor behavior report

> **Kind:** architecture · **Status:** maintained

`src/runtime_analysis/behavior.rs` produces
`glaurung-runtime-descriptor-behavior-report-v1` from provider-neutral
descriptor events in a validated `ProcessCapsule`. The Python surface is
`glaurung.runtime_analysis.analyze_process_capsule_descriptor_behavior`.

This report owns non-file descriptor resources. It does not put pipes into the
file report and does not reuse a `ProgramImage`, decompiler variable, or static
memory object as a runtime resource. Each resource retains execution process,
optional thread, creation sequence, stable resource ID, kind, flags, endpoint
descriptors and roles. Transfers and closes refer to that resource ID while
retaining the concrete descriptor handle used by the occurrence.

The first provider normalizes bounded `pipe2`, `socketpair`, `socket`, `bind`,
`listen`, `read`/`write`/`sendto`/`recvfrom`, and `close` events for one
launched child. Pipe endpoints are explicitly `read` and `write`; socket-pair endpoints are
bidirectional `peer0` and `peer1`. The native consumer rejects a transfer whose
operation is incompatible with its endpoint role. An unnormalizable operation
on a tracked endpoint rejects acquisition rather than disappearing from a
complete `descriptor_events` scope.

IPC content is redacted by default. `public_ipc_content=True` is a separate
caller authorization from file path and file content disclosure. Both policies
are incorporated into capture identity, so capsules that expose different
evidence cannot share a capture ID. Authorized bytes are still accepted as
observed only after hash and length verification.

Every successful non-empty pipe read or socket receive links to a capsule
input-provenance source named for that exact event. The source retains content
hash, byte length, and sensitivity and provides stable per-byte
`(source_id, offset)` identities. Private captures therefore preserve the
identity of incoming bytes while keeping their values redacted. Writes and
sends are effects of this process, not new process-input sources.

The same source can be joined to the exact-image LLIR call occurrence that
performed the read or receive. This records where bytes entered the program,
not where they subsequently flowed.

Supplied standard input uses a distinct `standard-input:<process>` runtime
resource and `descriptor_stdin_read` event rather than pretending descriptor
zero is an opened file. The event distinguishes a provider pipe from the
default `/dev/null`, applies an independent plaintext-disclosure policy, and
participates in the same input-source and LLIR-occurrence relation. General
standard-stream inheritance and descriptor reassignment remain open.

For supplied stdin, the transfer also retains the observed destination virtual
address. Its `OperationOccurrence` records a runtime memory effect containing
that address, returned length, and input-source ID. This proves that the
syscall introduced those source bytes into that concrete range. It does not
identify a static stack variable or propagate provenance through later LLIR
loads/stores; those require mapping/frame and temporal execution evidence.

The same optional raw-read evidence applies to tracked pipes. The real
`memory_read_overflow` good/bad pair records respectively 8 and 12 returned
bytes, their concrete stack destinations, input-source identities, and exact
LLIR read-call occurrences. The 12-byte effect is not yet labelled an overflow:
the capsule does not currently prove which runtime stack object and field
boundary the destination realizes.

The real `normal_pipe_roundtrip` gate covers both good and bad scenarios. It
links one pipe resource through write byte `51`, read byte `51`, and closure of
both endpoints. Both semantic results fully satisfy their roundtrip and clean
IPC oracles. The same executions under the private policy retain hashes and
lengths but no plaintext bytes and receive distinct capture IDs.

The real `normal_socketpair` gate likewise covers both scenarios. It retains
`AF_UNIX`, `SOCK_STREAM`, protocol, two peer identities, byte `53` sent through
one peer and received through the other, and both closes. Its clean result does
not classify a connected socket pair as a listener merely because socket APIs
were used. A wrong-role mutation is rejected by the native normalizer and makes
the semantic result incomplete.

The `danger_bind_listener` pair establishes network context without deciding
risk from `socket` or `bind` names alone. Both create `AF_INET/SOCK_STREAM`
resources and bind ephemeral ports. The good case binds `127.0.0.1`; the bad
case binds `0.0.0.0` and receives a typed `wildcard_bind` finding. Neither calls
`listen`, and that absence is supported only because `listen` belongs to the
complete descriptor-event scope. Changing the bind's resource ID removes the
semantic relation rather than joining by endpoint text.

This is not yet a general descriptor graph. Accepted network connections,
datagrams, descriptor passing, duplicated IPC endpoints, inherited handles, polling,
partial transfers, and cross-process ownership remain open. Observed content
has W8 stable per-byte identity at read/receive events, but that provenance is
not yet propagated through LLIR operations.
