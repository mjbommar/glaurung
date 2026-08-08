# §Z — Evidence and citations

`evidence_log` is an append-only record of selected tool observations in a
persistent `.glaurung` project. It stores the tool name, serialized inputs,
summary, optional address range, serialized output, and timestamp.

It is an audit aid, not a truth oracle. A row proves what Glaurung recorded for
that invocation; it does not prove that the tool interpreted the binary
correctly or that an agent's conclusion follows from the output.

## Create a verified example

From the repository root:

```bash
BIN="samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0"
DB="demo.glaurung"

uv run glaurung kickoff "$BIN" --db "$DB"
```

Kickoff attempts to append one binary-scope row:

```bash
sqlite3 "$DB" \
  "SELECT cite_id, tool, summary FROM evidence_log ORDER BY cite_id LIMIT 10;"
```

The current result is captured in
[`evidence-log-head.out`](../_fixtures/05-kickoff-anatomy/evidence-log-head.out).
Analyzer counts are intentionally read from that live fixture rather than
duplicated here.

## Inspect the schema

```bash
sqlite3 "$DB" ".schema evidence_log"
```

See the verified
[`evidence-log-schema.out`](../_fixtures/05-kickoff-anatomy/evidence-log-schema.out)
for the exact schema. The important columns are:

| Column | Meaning |
| --- | --- |
| `cite_id` | Database-local integer identifier for the row |
| `binary_id` | Binary in this project to which the row belongs |
| `tool` | Recorded tool name |
| `args_json` | JSON-serialized tool inputs |
| `summary` | Short display summary |
| `va_start`, `va_end` | Optional half-open virtual-address range |
| `file_offset` | Optional file offset when no VA applies |
| `output_json` | Optional JSON-serialized structured result |
| `created_at` | Unix timestamp in seconds |

Inspect the structured fields instead of relying only on `summary`:

```bash
sqlite3 -header -column "$DB" \
  "SELECT cite_id, tool, args_json, output_json
     FROM evidence_log
    ORDER BY cite_id
    LIMIT 3;"
```

The verifier also captures shortened fields in
[`evidence-log-args-output.out`](../_fixtures/05-kickoff-anatomy/evidence-log-args-output.out).
Repository paths and timestamps are normalized only in checked-in fixtures;
your database retains the actual values.

## Logging scope and limitations

Persistent logging is best-effort. Logging failures are deliberately prevented
from breaking analysis, so a missing row does not prove a tool was never run.
Conversely, a row with an error summary records a failed attempt, not successful
evidence.

The generic evidence wrapper logs deterministic memory-tool calls only when the
agent context uses a persistent knowledge base. This distinction matters:

- `kickoff --db PROJECT` uses a persistent project and records its aggregate
  kickoff observation;
- `repl BINARY --db PROJECT`, including its `ask` command, reuses that project;
- standalone `ask BINARY -a QUESTION` currently uses an in-memory knowledge
  base, so generic tool rows disappear when the command exits; and
- not every internal helper is necessarily an evidence-wrapped tool.

Therefore, do not promise “one row for every model action.” Check the actual
project and preserve `--show-tools` output when using standalone `ask`.

## Verify a cited claim

Suppose a report references cite ID 7. Resolve the row first:

```bash
sqlite3 -json "$DB" \
  "SELECT cite_id, tool, args_json, summary,
          va_start, va_end, file_offset, output_json, created_at
     FROM evidence_log
    WHERE cite_id = 7;"
```

Then review it in this order:

1. Does the row exist in the intended project and for the intended binary?
2. Do `tool` and `args_json` match the operation the report describes?
3. Does `output_json` directly support the narrow claim, or is the claim an
   inference?
4. If a VA range is present, does independent disassembly or decompilation
   agree?
5. Could a tool error, truncation, analysis budget, packer, or missing metadata
   explain an incomplete result?

If any link is missing, label the statement as unverified or unsupported. A
confident model sentence does not repair a mismatched citation.

## Useful queries

Recent observations:

```bash
sqlite3 -header -column "$DB" \
  "SELECT cite_id, datetime(created_at, 'unixepoch') AS utc, tool, summary
     FROM evidence_log
    ORDER BY cite_id DESC
    LIMIT 20;"
```

Calls for one tool:

```bash
sqlite3 -header -column "$DB" \
  "SELECT cite_id, va_start, va_end, summary
     FROM evidence_log
    WHERE tool = 'view_function'
    ORDER BY cite_id;"
```

Rows whose recorded VA range contains `0x1160`, plus binary-scope rows:

```bash
sqlite3 -header -column "$DB" \
  "SELECT cite_id, tool, summary
     FROM evidence_log
    WHERE va_start IS NULL
       OR (va_start <= 0x1160 AND va_end > 0x1160)
    ORDER BY cite_id;"
```

The `NULL` branch is intentional: binary-scope observations such as kickoff do
not have a function-specific range.

## Preserve and share evidence safely

A project can contain local paths, analyst comments, model/tool inputs,
recovered strings, and structured outputs. Treat it as case data:

- record the binary hash, Glaurung commit, command/options, and model name;
- keep the usage log and standalone `--show-tools` output when applicable;
- inspect or redact sensitive rows before sharing the database;
- use access controls appropriate for the underlying binary; and
- never treat a changed analyzer count after an upgrade as silent proof of a
  regression—reproduce it on the same revision and options first.

Reproducibility is conditional on the binary, Glaurung version, configuration,
available debug metadata, and any external symbol data. Natural-language model
responses add another nondeterministic layer. Preserve those inputs if another
analyst must reproduce the conclusion.

This completes the tutorial track. Continue with the
[CLI cheatsheet](../reference/cli-cheatsheet.md),
[sample corpus](../reference/sample-corpus.md), or the broader
[documentation index](../../README.md).
