# Persistent project databases

> **Kind:** architecture · **Status:** maintained

Glaurung stores analyst and analysis state in a SQLite file with the conventional
`.glaurung` suffix. The database is separate from the target binary: its binary
row records the content hash and original path, while analysis tables store
knowledge, names, types, xrefs, comments, stack variables, bookmarks, journal
entries, and other subsystem evidence.

The target is never executed by opening a project.

## CLI lifecycle

Create and populate an explicit project with the deterministic kickoff workflow:

```bash
BIN="samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
DB="${TMPDIR:-$HOME/.cache/glaurung/tmp}/hello-docs.glaurung"
mkdir -p "$(dirname "$DB")"

uv run glaurung kickoff "$BIN" --db "$DB"
uv run glaurung repl "$BIN" --db "$DB"
```

`kickoff` uses a temporary database when `--db` is omitted, so supply `--db`
when the result must persist. `repl` persists by default; without `--db`, it
appends `.glaurung` to the binary filename (for example,
`program.exe.glaurung`). Use `--session NAME` to isolate KB nodes and edges for
different analyst sessions on the same binary.

Most daily CLI commands that operate on accumulated analysis take a project
path. Their positional and `--db` conventions are not uniform, so check the
specific command help rather than guessing:

```bash
uv run glaurung xrefs --help
uv run glaurung frame --help
uv run glaurung find --help
uv run glaurung export --help
```

The [tutorial](../tutorial/README.md) exercises project creation, annotations,
undo/redo, bookmarks, frames, xrefs, search, and export against checked-in
fixtures.

## Python API

`PersistentKnowledgeBase.open` creates a missing database or opens an existing
one. A new file requires `binary_path`; an existing file can select its most
recent binary row when that argument is omitted.

```python
from pathlib import Path
from tempfile import TemporaryDirectory

from glaurung.llm.kb.models import Node, NodeKind
from glaurung.llm.kb.persistent import PersistentKnowledgeBase

binary = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/"
    "hello-gcc-O2"
)

with TemporaryDirectory() as directory:
    database = Path(directory) / "example.glaurung"
    with PersistentKnowledgeBase.open(
        database,
        binary_path=binary,
        session="main",
    ) as knowledge:
        knowledge.add_node(
            Node(kind=NodeKind.note, label="reviewed", text="docs example")
        )

    with PersistentKnowledgeBase.open(database, session="main") as reopened:
        assert any(node.label == "reviewed" for node in reopened.nodes())
```

The context manager saves only on a clean exit. `close()` saves in a `finally`
path; call `save()` explicitly before a risky operation when durability at that
point matters.

An analysis tool that needs triage, budgets, and persistent storage together can
use `MemoryContext.open_persistent`:

```python
from glaurung import triage
from glaurung.llm.context import MemoryContext

artifact = triage.analyze_path(str(binary))
context = MemoryContext.open_persistent(
    file_path=str(binary),
    artifact=artifact,
    db_path=database,
    session="main",
)
try:
    print(context.kb.path)
finally:
    context.kb.close()
```

Keep the database and binary pairing explicit in reusable code. An existing
multi-binary project opened without `binary_path` selects the most recently
discovered binary, which may not be the one a caller intended.

## Storage architecture

`PersistentKnowledgeBase` is an in-memory `KnowledgeBase` backed by SQLite:

- opening hydrates the selected session's nodes and edges into memory;
- node and edge mutations update the in-memory indexes;
- `save()` writes the current node/edge diff in one transaction;
- SQLite WAL mode and foreign-key checks are enabled; and
- subsystem modules create additional tables idempotently for types, xrefs,
  functions, frames, undo history, and specialized evidence.

The base schema version is currently `1`. Opening a database with any different
base version fails closed: migrations are not yet implemented. Some subsystem
tables evolve through idempotent column/table checks without changing that base
version, so consumers must use Glaurung APIs rather than treating the SQLite
layout as a stable third-party schema.

The content SHA-256 identifies binary rows. Session names are scoped to one
binary. Core KB nodes/edges are session-specific, while many analysis tables are
binary-wide and carry their own provenance or precedence fields.

Runtime address correlation uses the binary-wide
`runtime_address_relations` table owned by
`glaurung.llm.kb.runtime_relations`. Each row retains the capture and process
scope alongside raw and normalized addresses. It is an immutable measurement,
not an annotation: it neither participates in `set_by` precedence nor writes
to static xrefs, names, types, comments, or decompiler IR. The public writer
resolves through the native analyzer and verifies the selected project
binary's SHA-256 before inserting a row.

The same module owns `runtime_runs` and `runtime_captures`. Runs are explicit
project-scoped identities; captures are immutable capsule artifacts within a
run. `persist_process_capsule` first invokes the native capsule validator and
checks the capsule executable hash against the selected binary. It retains the
exact capsule bytes and SHA-256 plus acquisition, host, kernel, and capture-time
identity. Re-importing identical evidence is idempotent, while reusing a
capture ID for different bytes or moving it between runs fails closed. With no
caller-supplied run ID, the capture ID defines a one-capture run; the database
never guesses grouping from OS PIDs or timestamps. These tables have no
`set_by` field and do not participate in manual/debug/analysis precedence.

Each capture import transaction also fills `runtime_processes`,
`runtime_threads`, `runtime_modules`, `runtime_mappings`, `runtime_events`,
`runtime_pages`, `runtime_objects`, `runtime_object_snapshots`,
`runtime_outputs`, and `runtime_descriptors`.
These are normalized identities and observations, not copies in the static
model. Process ancestry, terminal state, raw provider register names, faults,
module artifacts, load biases, mapped ranges, permissions, backing, and event
fields remain scoped by capture. Event order is indexed per process and
optional thread stream, matching the capsule contract rather than inventing a
cross-thread causal order. Any failed child-row import rolls back its run and
capture rows as one transaction.

Deterministic analyzer output lives in `runtime_analysis_reports`, keyed by
the exact capture, analyzer name, and report schema. The first report fixes the
canonical JSON and its SHA-256; rerunning that analyzer for the same
capture/schema must reproduce identical bytes or fail closed. Crash analysis
loads the capsule and payloads back from the project and verifies the supplied
executable bytes against the capture before analysis. Mapping behavior instead
normalizes only already-persisted provider-neutral mapping events and stores
their capture-scoped lifetimes and permission transitions; it does not infer a
history from final mapping snapshots. Reports do not enter the
manual-precedence annotation tables, and their foreign keys remain entirely
inside the runtime measurement schema.

Exact runtime-to-LLIR joins are normalized into
`runtime_operation_occurrences`. One row owns only occurrence identity: capture,
process/thread event position, code origin, and immutable `StaticOperation`
identity. `runtime_operation_occurrence_evidence` stores content-addressed
evidence views separately. This matters because several valid relations may
project different inputs or effects for the same operation occurrence; those
views must neither collide nor create several static operations. No foreign key
from either table enters the decompiler or annotation schema.

`runtime_capture_summary_json` is the stable default automation projection over
these tables. It emits canonical `glaurung-runtime-project-summary-v1` JSON and
deliberately excludes raw payloads, registers, memory snapshots, paths,
descriptor targets, event fields, and occurrence evidence values. Observed
operations expose only their occurrence scope and immutable static-operation
identity. Terminal rendering is downstream presentation, never an input to
automation or persistence.

`runtime_evidence_packet_json` is a separate, explicit export boundary. Its
default policy contains only the redacted summary, completeness states, hashes,
claim-kind inventories, and declared omissions. The sensitive policy must be
requested by the caller and then includes exact capsule/report documents and
base64 payload bytes. Both policies recheck every stored content address before
emission and omit executable bytes.

`compare_runtime_captures_json` compares two summaries from the selected
project; `compare_runtime_summaries_json` compares summaries exported from
different projects or builds. Both report count, event-kind, terminal-state,
analyzer-outcome, and exact static-operation-set differences without loading
raw evidence. Different executable hashes are explicit. Static operations are
not aligned across different builds: that requires a separate proved
cross-build identity and cannot be inferred from addresses or LLIR indices.

### Function identity across builds

Every annotation table is keyed on `(binary_id, absolute VA)`, and a recompile
moves both halves at once: the file hashes differently, so a fresh `binaries`
row is inserted, and the stored VAs now name different code. Queries return zero
rows rather than an error, and the annotations sit orphaned under the previous
`binary_id`.

`function_identity` is the one table not anchored that way. It stores
`(binary_id, entry_va, scheme, identity)` where `identity` is derived from what
the function *is*, indexed on `(scheme, identity)` so a lookup can cross
`binary_id` on purpose. `glaurung.llm.kb.function_identity` computes and stores
it (`index_function_identities`), resolves it (`find_by_identity`,
`resolve_entry_va`), and carries annotations from an older build onto a newer one
(`port_annotations`).

`scheme` names the algorithm rather than fixing one: `STRUCTURAL_V1` —
`glaurung-structural-v1` — is what can be computed today, with room for a WARP
function GUID (see
[`../decisions/whole-binary-serialization.md`](../decisions/whole-binary-serialization.md))
as another `scheme` value in the same TEXT column: no schema change, no
migration, and a function may carry several identities at once.

Two limits are deliberate. Identity is *structural*, so functions that compile to
the same shape share it (identical PLT thunks are routine); `port_annotations`
refuses to carry anything across an ambiguous match and reports the count.
And it addresses the recompile case, not the rebase case — a binary whose bytes
are unchanged but whose load address moved keeps its `binary_id`, so its stale
identity rows collide with the fresh ones on the primary key.

## Durability and safety boundaries

- Keep the target binary available at its recorded path for commands that need
  to reread bytes; the database does not embed the complete binary.
- Do not edit tables manually while Glaurung is running.
- Do not copy only the main SQLite file while a writer has an active WAL; close
  the project or use SQLite's backup facilities.
- A `.glaurung` file can contain analyst notes, target paths, recovered strings,
  and other sensitive evidence. Apply the same access controls as the case data.
- Source revision and command output remain necessary for reproducibility; the
  database is accumulated state, not a proof that every analysis completed.

## See also

- [`python-package-map.md`](python-package-map.md) — the full table list and
  which of the nine modules owns each one.
- [`../reference/provenance.md`](../reference/provenance.md) — the `set_by`
  ladder every write in these tables is checked against.
- [`module-boundaries.md`](module-boundaries.md) §6 — the storage boundary this
  layer is meant to hold, and the migration gap it has not closed.

Focused persistence coverage lives in `python/tests/test_persistent_kb.py`.
