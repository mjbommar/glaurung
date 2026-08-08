# §X — One-shot kickoff

`kickoff` is Glaurung's bounded, deterministic first pass. It does not call an
LLM and does not require an API key. It does create or update a SQLite project,
so give `--db` an explicit path when you want to keep the result.

This chapter uses the checked-in Linux sample. From the repository root:

```bash
BIN="samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0"
DB="demo.glaurung"

uv run glaurung kickoff "$BIN" --db "$DB"
```

The current output is captured in
[`_fixtures/05-kickoff-anatomy/kickoff.out`](../_fixtures/05-kickoff-anatomy/kickoff.out).
The tutorial verifier reruns this exact sample; use the fixture instead of
copying its function or type counts into scripts, because analyzer changes can
legitimately change those counts.

## What the pass does

In order, kickoff:

1. checks for known packers and high-entropy packed content;
2. triages the file format, architecture, entry point, strings, and IOCs;
3. opens the project database and loads the applicable standard-library type
   bundle;
4. discovers functions, indexes call edges, and demangles persisted names;
5. imports available debug types, including DWARF and optional PDB data;
6. discovers stack slots, propagates call-site types, and looks for struct
   candidates for a bounded set of functions; and
7. appends one `kickoff_analysis` row to `evidence_log` when evidence logging
   succeeds.

The default per-function lift cap is 64. Change it explicitly for a larger or
smaller first pass:

```bash
uv run glaurung kickoff "$BIN" --db "$DB" --max-functions 16
```

Kickoff normally stops before deep analysis when packer detection is positive.
That is a safety and signal-quality default. `--analyze-packed` overrides it,
but use that only when you understand why the detector fired.

## Deterministic does not always mean offline

The analysis itself contains no model call. For a PE with a CodeView record,
however, kickoff may fetch a missing PDB from Microsoft's symbol server. To
make a cache-only run, add `--no-fetch-pdb`; to disable PDB processing entirely,
add `--no-pdb`:

```bash
uv run glaurung kickoff "$BIN" --db "$DB" --no-fetch-pdb
```

The ELF sample used here does not take the PDB path.

## Inspect what was persisted

The project is an ordinary SQLite database. Start with the tables and the
kickoff evidence row:

```bash
sqlite3 "$DB" ".tables"
sqlite3 "$DB" \
  "SELECT cite_id, tool, summary FROM evidence_log ORDER BY cite_id;"
```

The verified row is in
[`evidence-log-head.out`](../_fixtures/05-kickoff-anatomy/evidence-log-head.out).
Its `cite_id` identifies a recorded tool observation; it is not, by itself,
proof that every conclusion drawn from the observation is correct.

Useful project tables include `function_names`, `xrefs`,
`function_prototypes`, `types`, `stack_frame_vars`, and `evidence_log`.
Population varies by binary format and available metadata. Query the project
rather than assuming every table has rows.

## Reruns and project ownership

Kickoff is designed to update an existing project safely, and provenance fields
such as `set_by` distinguish analyzer, debug-info, propagated, and manual data.
An invocation also appends a new evidence row, so rerunning is not a byte-for-byte
no-op. Keep one database per analysis case unless you intentionally want a
shared history.

Kickoff is a first pass, not a whole-program proof. It does not decompile every
function, validate every recovered type, or turn IOC-like strings into malware
attribution. Use the deterministic inspection commands from Tiers 2–4 to check
the interesting addresses before asking an agent to synthesize them.

Next: [§Y — Chat-driven triage](chat-driven-triage.md).
