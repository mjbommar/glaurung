# Persistent project databases

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
DB="/tmp/hello-docs.glaurung"

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

Focused persistence coverage lives in `python/tests/test_persistent_kb.py`.
