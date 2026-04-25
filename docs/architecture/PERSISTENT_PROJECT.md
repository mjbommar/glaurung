# Persistent project database

## Why

Today every Glaurung run starts blank. The agent re-discovers the same
facts about a binary on every invocation. There is no place to record
the analyst's decisions — no rename, no comment, no struct definition
survives the process exit. This is the single biggest gap between
Glaurung and a real RE workflow tool: an IDA `.idb` or a Ghidra `.gpr`
holds all of that state and is what an analyst opens every morning.

We need the same: an on-disk file that stores a binary's analysis state
plus the analyst's accumulated work, openable across processes and
shareable between users.

## Goals

- A single `.glaurung` file per binary (or shared across binaries) that
  holds **everything an agent or human discovered or decided**.
- Survives process exit. Round-trips byte-identical for a write-then-
  read with no edits.
- Cheap to open (sub-second on a 100K-function database).
- Concurrent access is acceptable (SQLite WAL mode).
- The file format is a *promise we can keep* — schema versioned, with
  forward-compat reads or explicit migration.
- Backwards compatible: existing `MemoryContext` + in-memory
  `KnowledgeBase` keep working when no `.glaurung` file is supplied.

## Non-goals (for v1)

- Multi-user simultaneous writes with merge resolution. (One writer at
  a time; if two analysts collaborate, they sync via diff/export.)
- Rich querying language. The Python API is the query language for now.
- Cloud storage / sharing primitives. The file is local; users move it
  themselves.

## Data model

The schema is the union of three concerns. They share a `binaries`
table as the root foreign key.

### Core tables

```sql
-- One row per analysed binary, keyed by content sha256 so two paths
-- pointing at the same bytes share one record.
CREATE TABLE binaries (
    binary_id    INTEGER PRIMARY KEY,
    sha256       TEXT NOT NULL UNIQUE,
    first_path   TEXT,         -- first path the user gave us
    format       TEXT,         -- elf, pe, macho, …
    arch         TEXT,
    bits         INTEGER,
    size_bytes   INTEGER,
    discovered_at INTEGER      -- unix epoch
);

-- Sessions group an analyst's work. Default session is "main".
CREATE TABLE sessions (
    session_id   INTEGER PRIMARY KEY,
    binary_id    INTEGER REFERENCES binaries(binary_id),
    name         TEXT NOT NULL,
    created_at   INTEGER,
    UNIQUE (binary_id, name)
);

-- KB nodes — generalisation of the existing in-memory KnowledgeBase.
CREATE TABLE kb_nodes (
    node_pk      INTEGER PRIMARY KEY,
    session_id   INTEGER REFERENCES sessions(session_id),
    node_id      TEXT NOT NULL,           -- existing UUID-like id
    kind         TEXT NOT NULL,
    label        TEXT,
    text         TEXT,
    props_json   TEXT NOT NULL DEFAULT '{}',
    tags_json    TEXT NOT NULL DEFAULT '[]',
    UNIQUE (session_id, node_id)
);

CREATE TABLE kb_edges (
    edge_pk      INTEGER PRIMARY KEY,
    session_id   INTEGER REFERENCES sessions(session_id),
    edge_id      TEXT NOT NULL,
    src_node_id  TEXT NOT NULL,
    dst_node_id  TEXT NOT NULL,
    kind         TEXT NOT NULL,
    props_json   TEXT NOT NULL DEFAULT '{}',
    UNIQUE (session_id, edge_id)
);

-- Per-node tags index for fast tag-filter queries.
CREATE TABLE kb_node_tags (
    node_pk      INTEGER REFERENCES kb_nodes(node_pk) ON DELETE CASCADE,
    tag          TEXT NOT NULL,
    PRIMARY KEY (node_pk, tag)
);

-- FTS index over labels + text for the existing search_text path.
CREATE VIRTUAL TABLE kb_fts USING fts5(
    label, text,
    content='kb_nodes', content_rowid='node_pk'
);
```

### Tables added by #153 (type system) and #154 (xrefs)

These are sibling concerns — not part of #152's bare KB persistence —
but the schema is sketched here so #152's design doesn't preclude them.

```sql
-- #153: Persistent type definitions.
CREATE TABLE types (
    type_id      INTEGER PRIMARY KEY,
    binary_id    INTEGER REFERENCES binaries(binary_id),
    name         TEXT NOT NULL,
    kind         TEXT NOT NULL,         -- struct, enum, typedef, …
    body_json    TEXT NOT NULL,         -- canonical layout
    confidence   REAL DEFAULT 0.5,
    source       TEXT,                  -- llm, dwarf, manual, …
    UNIQUE (binary_id, name)
);

CREATE TABLE type_field_uses (
    binary_id    INTEGER,
    type_name    TEXT,
    field_name   TEXT,
    use_va       INTEGER,
    function_va  INTEGER
);
CREATE INDEX idx_type_field_uses_va ON type_field_uses(use_va);

-- #154: Persistent cross-references.
CREATE TABLE xrefs (
    xref_id      INTEGER PRIMARY KEY,
    binary_id    INTEGER REFERENCES binaries(binary_id),
    src_va       INTEGER NOT NULL,
    dst_va       INTEGER NOT NULL,
    kind         TEXT NOT NULL,         -- call, jump, data_read,
                                         -- data_write, struct_field
    src_function_va INTEGER             -- nullable
);
CREATE INDEX idx_xrefs_dst ON xrefs(binary_id, dst_va);
CREATE INDEX idx_xrefs_src ON xrefs(binary_id, src_va);

-- Function namings + comments survive across runs.
CREATE TABLE function_names (
    binary_id    INTEGER REFERENCES binaries(binary_id),
    entry_va     INTEGER NOT NULL,
    canonical    TEXT NOT NULL,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    set_by       TEXT,                   -- llm, dwarf, manual
    PRIMARY KEY (binary_id, entry_va)
);

CREATE TABLE comments (
    binary_id    INTEGER REFERENCES binaries(binary_id),
    va           INTEGER NOT NULL,
    body         TEXT NOT NULL,
    set_at       INTEGER,
    PRIMARY KEY (binary_id, va)
);
```

### Schema version

```sql
CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT);
INSERT INTO schema_meta VALUES ('schema_version', '1');
INSERT INTO schema_meta VALUES ('glaurung_version', '0.1.0');
```

## Python API

A new module `python/glaurung/llm/kb/persistent.py`:

```python
class PersistentKnowledgeBase(KnowledgeBase):
    """SQLite-backed KnowledgeBase. Inherits the in-memory query API
    (`add_node`, `add_edge`, `search_text`, `nodes`, `edges`) so every
    existing tool keeps working unchanged. Mutations dirty an in-memory
    write buffer; `save()` commits the buffer to SQLite in one
    transaction. `open(path)` loads an existing file; `create(path)`
    initialises a fresh schema.
    """

    @classmethod
    def open(cls, path: str | Path, session: str = "main") -> "PersistentKnowledgeBase": ...

    @classmethod
    def create(cls, path: str | Path, binary_path: str, session: str = "main") -> "PersistentKnowledgeBase": ...

    def save(self) -> None: ...
    def close(self) -> None: ...

    def __enter__(self) -> "PersistentKnowledgeBase": ...
    def __exit__(self, *args) -> None: ...
```

`MemoryContext` gets an optional `db_path` argument:

```python
ctx = MemoryContext(file_path=binary, artifact=art, db_path="malware.glaurung")
# ctx.kb is now a PersistentKnowledgeBase opened on that file.
# Closing the context (or program exit) saves outstanding changes.
```

When `db_path` is `None`, `MemoryContext` falls back to today's
in-memory `KnowledgeBase` — every existing test continues to work
unchanged.

## File location convention

- Per-binary default: `<binary>.glaurung` next to the binary.
- Per-project: `--db /path/to/project.glaurung` flag overrides.
- The CLI's `glaurung repl <binary>` opens (or creates)
  `<binary>.glaurung` automatically.

## Migration strategy

`schema_version` lives in `schema_meta`. On open:

- If version matches → use as-is.
- If version is older but our migration table covers the gap → run
  every migration in order, bump the stored version.
- If version is newer than us → refuse to open, tell the user to
  upgrade glaurung. We never silently downgrade.

Migrations live in `python/glaurung/llm/kb/migrations/{N→N+1}.sql`.

## Testing

- `test_persistent_kb_round_trip` — create, add nodes+edges+tags, save,
  close, reopen, assert byte-identical content.
- `test_persistent_kb_concurrent_reads` — two opens, two reads, no
  blocking.
- `test_in_memory_kb_unchanged` — every existing test that uses
  `MemoryContext` without `db_path` still passes.
- `test_migration_v0_to_v1` — synthetic v0 file loads cleanly after
  migration.

## Implementation plan

Sprint 1 — `PersistentKnowledgeBase` core (this task #152).
- Schema creation + opening.
- `add_node`/`add_edge` write-through.
- `save()` commits.
- FTS index for `search_text`.
- Round-trip test.

Sprint 2 — Wire into MemoryContext (#152 final piece).
- `db_path` argument.
- Recover-source pipeline opens the file once and reuses across function
  passes.

Sprint 3 — Type table (#153).
- Schema added.
- Type-aware decompile-render pass.
- Manual `add_type` API.

Sprint 4 — Xref table (#154).
- Schema added.
- One-time index build on first analysis.
- `list_xrefs_*` tools become SQL queries.

Sprint 5 — REPL (#155).
- Loads the file, exposes navigation grammar, persists every change.

This document is the blueprint for #152–#155. Subsequent tasks
(#157 DWARF ingest, #159 benchmark) consume the schema but don't
extend it.
