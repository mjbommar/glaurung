# Runtime analysis sample corpus

This corpus contains small, real C executables for runtime acquisition and
static/runtime correlation tests. Each program accepts `good` or `bad` as its
first argument. The optional second argument is a numeric parameter. Programs
that finish normally print one stable `RESULT` line.

`manifest.toml` is authoritative for category and expected outcome. Build and
run it with:

```bash
uv run python tools/runtime_sample_harness.py list
uv run python tools/runtime_sample_harness.py build --compiler gcc --opt O2 --link pie
uv run python tools/runtime_sample_harness.py matrix
uv run python tools/runtime_sample_harness.py run --sample normal_open_file --scenario good
uv run python tools/runtime_sample_harness.py live --sample memory_struct_field_overwrite --scenario bad
uv run python tools/runtime_sample_harness.py live --sample crash_null_write --scenario bad --checkpoint entry
uv run python tools/runtime_sample_harness.py core --sample crash_null_write --scenario bad
```

`semantic-oracles.toml` is a separate, evaluator-only authority for semantic
expectations. It begins with the five M0 representatives and records both good
and bad assertions, their independent oracle, and the process outcome against
which the file is validated. Execution and capture functions do not receive
these expectations. Assertions can carry `applies_to` selectors such as
`opt:O0` or `compiler:gcc,opt:O2`; this is required where undefined behaviour
produces different real programs in different compiler lanes.

Write a deterministic matrix ledger with:

```bash
uv run python tools/runtime_sample_harness.py matrix \
  --sample normal_open_file \
  --sample crash_null_write \
  --sample memory_struct_field_overwrite \
  --sample danger_rw_to_rx \
  --sample danger_bind_listener \
  --compiler gcc --opt O2 --link pie \
  --ledger target/runtime-samples/m0-ledger.json
```

The `glaurung-runtime-matrix-ledger-v1` record contains stable lane identities,
source, producer, manifest, binary, scenario-input, and semantic-oracle hashes,
plus expected and observed process outcomes. It deliberately excludes elapsed
time, absolute build paths, stdout, and stderr. The oracle contents are not
copied into analyzer inputs or the ledger; the evaluator joins them by case ID
after execution.

Build products and captures live below `target/runtime-samples` by default and
are not source artifacts. `live` launches with
`GLAURUNG_RUNTIME_CHECKPOINT=1`, waits for the sample's `SIGSTOP`, records
`/proc` metadata, and leaves a normalized artifact before terminating the
process. `--checkpoint entry` stops in a constructor before `main`, so even a
crashing path can be inspected live; the default `exit` checkpoint observes
normal and silent-corruption cases after their principal behavior. `core` uses
a private working directory and reports whether the host's
core policy produced a readable core; it never claims success when the kernel
redirected or suppressed the dump.

The default matrix is GCC and Clang, `-O0` and `-O2`, and PIE and non-PIE
dynamic linking. Repeat `--compiler`, `--opt`, or `--link` to select other
lanes; `--link static` is available when the host has static libc development
files. The matrix executes both scenarios and checks their process-level
exit/signal oracles.

Live artifacts never store environment values in plaintext. They record each
variable name, value length, and SHA-256 digest so runs can be compared without
copying credentials into an artifact.

Each successful live capture also contains `process-capsule.json`, validated
and canonicalized by Glaurung's Rust capsule implementation. This first
provider includes exact main-executable identity, mappings, thread IDs, and
descriptor metadata. It records registers as unsupported and memory pages as
not requested instead of filling either with guessed data.

Capsule provenance binds the exact executable, retained procfs artifacts, and
scenario-argument bytes by SHA-256 and length. The argument itself is not copied
into public metadata. Core capsules similarly bind the exact core, executable,
and scenario argument supplied to the importer.

When `core` produces exactly one ELF core, the harness imports it through the
same Rust capsule model. Public metadata remains in `process-capsule.json`;
captured `PT_LOAD` bytes are stored as mode-`0600` sensitive payloads in a
capsule-hash-named directory. If host core policy suppresses the dump, the
manifest records that absence and no capsule is fabricated.

The integration test re-imports that public manifest and payload directory
through the Rust bundle boundary. Import requires the exact referenced file
set, non-path payload IDs, non-symlink regular files, declared lengths, and
matching SHA-256 values; traversal, truncation, corruption, extra files, and
symlink substitution are negative cases.

`support/threaded_worker_fault.c` is a provider support fixture, not a 61st
corpus sample. Its worker thread faults while the process leader waits, proving
that core import preserves both TIDs and attaches fault evidence to the dumping
worker rather than the leader.

`support/heap_snapshot_multiple_objects.c` is likewise a negative provider
fixture rather than a corpus sample. It creates two main-module heap objects
during one instruction-trace capture and proves that the bounded combined
provider rejects ambiguity instead of selecting one convenient object chain.
`support/heap_snapshot_no_object.c` proves that a requested provider stream
containing only its completion summary is rejected rather than normalized as a
successful trace with silently absent heap evidence.
`support/heap_snapshot_worker_object.c` places the otherwise valid object chain
on a worker and proves that it cannot be assigned to the main thread's
instruction trace merely because both belong to one process.
`support/heap_snapshot_wrong_phase.c` emits a valid provider write before trace
begin and proves that provider-local order alone cannot justify placing an
event between later instruction-trace checkpoints.

Semantic oracles now cover both scenarios for all 15 crash programs, including
the expected signal and a source-grounded fault/access class. They also cover
both scenarios for all 15 silent-corruption programs, including object/interval
facts and explicit GCC `-O2` non-materialization where undefined writes are
optimized away. The integer-truncation fixture uses 265 -> `uint8_t(9)` so its
bad path actually selects the intended 12-byte overwrite; the earlier 264 -> 8
path was in bounds in every default lane. Both scenarios for all 15 dangerous
programs name their source, sink/resource, and required event or explicit
marker-only boundary. All 120 scenarios now have semantic records and every
good scenario includes a negative finding/effect assertion. Two consecutive
960-cell ledgers from the current tree were byte-identical at
`d7f0478cb7c51c865be09ab40faf0545fc612ebce0c6bb675c102d1452adb7b9`.
Semantic analyzer-result comparison and mutation gates have landed.
`tools/runtime_sample_harness.py evaluate RESULT.json` consumes a
separate `glaurung-runtime-semantic-result-v1` record, applies its exact lane,
and fails on mismatches or incomplete evidence. Analyzer-side result production
remains separate and incomplete. `run --semantic-result-dir` provides the first
oracle-independent producer: wait status and generic `RESULT` output are
observed, while crash class/access facts unavailable from that evidence are
explicitly unsupported. Typed crash reports can also be projected without
reading the oracle. This preserves observed versus inferred claims and emits
explicit unknown/unsupported facts; the 15-core gate proves complete semantic
evaluation for the seven deliberate-signal, abort, and assertion cases.
Memory-interval and broader OS-event producers remain open.

The first OS-event producer uses a bounded normally exiting mapping trace. For
`danger_rw_to_rx`, it derives `RW->unmapped` and `RW->RX->unmapped` from one
complete anonymous mapping lifetime without reading the oracle. Its event scope
cannot prove that the bytes executed, so that assertion remains explicitly
unsupported. A mutation of the produced permission history fails evaluation.
The same native report distinguishes an initial RWX mapping from a later W→X
transition. Both `danger_rwx_mapping` scenarios fully satisfy their semantic
oracles, while their good control produces no finding.

The bounded trace also normalizes `openat`, `newfstatat`, selected tracked-file
`read`, `write`, and `close` calls. Paths and content are hash/length-only by default and require
separate bounded caller authorization. The native file-behavior report retains
resource identity across the lifecycle, flags, creation mode, descriptor or
errno, write result, and completeness. Both `normal_open_file` and
`normal_create_file`, `normal_write_file`, `normal_append_file`, and
`normal_stat_file`, and `normal_read_file` scenarios fully satisfy their semantic oracles. The ordinary
write case reuses the create lifecycle; append is inferred from flags plus its
linked resource write. Mutations of the produced open result, lifecycle, append
fact, stat result, authorized-content identity, or authorized-path identity fail
evaluation.

The same trace now normalizes `dup` as descriptor lineage over one resource and
one shared open-file-description offset. Both `normal_dup_fd` scenarios fully
match `open->dup->write:length=1->close_both`; removing one close removes the
positive chain and weakens descriptor-leak absence to unknown.

A separate native descriptor report now covers both `normal_pipe_roundtrip`
scenarios. One pipe resource owns explicit read/write endpoints, the ordered
transfers both retain byte `51`, and both handles close. IPC bytes are redacted
unless independently authorized; public and private disclosure policies produce
different capture identities. This is bounded observed content, not yet W8
per-byte LLIR provenance.

Both `normal_socketpair` scenarios now use the same descriptor report with
bidirectional peer roles. The report retains `AF_UNIX/SOCK_STREAM`, ordered
send/receive byte `53`, and both closes without treating a connected socket
pair as a network listener. A wrong endpoint-role mutation fails closed.

The `danger_bind_listener` good/bad pair now retains one `AF_INET/SOCK_STREAM`
resource from creation through bind and close. Loopback and wildcard endpoints
normalize separately; wildcard bind produces a typed finding. Both prove that
`listen` was not called from the complete scoped event stream. A mismatched
resource identity prevents endpoint correlation.

The real null-write core also exercises runtime/static address correlation. Its
RIP resolves through exact module SHA-256/build ID and mapping file offset to
the supplied `ProgramImage`; a different valid executable returns
`wrong_image`. If the host omits clean file-backed code from the core, byte
status remains `provider_unsupported` rather than silently falling back to file
bytes. The first
postmortem population gate compiles and imports all 15 bad crash
cases in the GCC `-O0` PIE lane:

```bash
uv run pytest \
  python/tests/test_runtime_sample_harness.py::test_all_bad_crash_cores_import_with_expected_signal \
  -m slow -q
```

If the host emits any requested core, the gate requires all 15 and checks each
terminal signal. If policy suppresses every core, the test skips explicitly.

The programs intentionally contain unsafe and undefined behavior. Never run
them outside the harness or against valuable paths, credentials, or services.
