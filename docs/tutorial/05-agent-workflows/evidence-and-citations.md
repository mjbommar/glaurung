# §Z — Evidence and citations

The `evidence_log` table is Glaurung's truth ledger. Every memory
tool the agent calls records a row capturing what was asked, what
came back, and a one-line summary. The agent's responses cite
these rows by id.

This chapter shows you how to read the log directly — useful for
spot-checking the agent's claims, building your own analyst
report, or debugging a session where the agent's answer didn't
match expectations.

## Reading the log

The `.glaurung` file is SQLite. The evidence table is queryable
with any sqlite3 client:

```bash
sqlite3 demo.glaurung "SELECT cite_id, tool, summary FROM evidence_log ORDER BY cite_id LIMIT 10;"
```

```
1  | kickoff_analysis | kickoff: ELF/x86_64, 6 functions, 18 propagated, 38 ioc strings
2  | list_strings     | sampled 20 of 38 strings
3  | view_function    | main @ 0x1160 — 432-byte frame, snprintf+memcpy+printf
4  | list_xrefs_to    | xrefs to 0x4040: 6 data_read sites
5  | get_function_prototype | snprintf(char *, size_t, const char *, ...)
...
```

Each row is one tool call.

## The full schema

```bash
sqlite3 demo.glaurung ".schema evidence_log"
```

```sql
CREATE TABLE evidence_log (
    cite_id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    tool TEXT NOT NULL,             -- e.g. "view_hex", "decompile_function"
    args_json TEXT NOT NULL,        -- inputs the tool was called with
    summary TEXT NOT NULL,          -- short human-readable description
    va_start INTEGER,               -- nullable: VA range this evidence covers
    va_end INTEGER,
    file_offset INTEGER,            -- nullable file-offset alternative
    output_json TEXT,               -- structured output (caller-defined schema)
    created_at INTEGER NOT NULL
);
```

Useful columns:

- `cite_id` — the int the agent's responses cite.
- `tool` — which memory tool was invoked.
- `args_json` — exactly what the agent passed in.
- `summary` — one-line digest used in agent responses.
- `output_json` — the full structured result.
- `va_start` / `va_end` — for tools anchored to a VA range
  (decompile, view, xrefs).

## Verify a citation

The agent said "C2 endpoints found at 0x4040 (cite 12)." Check it:

```bash
sqlite3 demo.glaurung "SELECT tool, summary, args_json, output_json
                       FROM evidence_log WHERE cite_id = 12;"
```

```
tool: list_xrefs_to
summary: xrefs to 0x4040: 6 data_read sites
args_json: {"va": 16448, "kinds": ["data_read"]}
output_json: [{"src_va": 4505, "kind": "data_read", ...}, ...]
```

Match? The agent's claim of "C2 endpoints at 0x4040" is grounded
in `list_xrefs_to(va=0x4040, kinds=['data_read'])` returning 6
sites. ✓

## Filter by tool

```bash
sqlite3 demo.glaurung "SELECT cite_id, summary FROM evidence_log
                       WHERE tool = 'view_function' ORDER BY cite_id;"
```

Lists every function the agent decompiled this session. Pair this
with `va_start` to see *which* functions:

```bash
sqlite3 demo.glaurung "SELECT cite_id, printf('0x%x', va_start), summary
                       FROM evidence_log WHERE tool = 'view_function';"
```

## Filter by VA range

The agent claimed something at 0x1160. What did it look at near
that VA?

```bash
sqlite3 demo.glaurung "SELECT cite_id, tool, summary FROM evidence_log
                       WHERE va_start BETWEEN 0x1100 AND 0x1300
                       ORDER BY cite_id;"
```

## Build your own report from the log

Every analyst session leaves a complete audit trail. Generate a
markdown summary:

```bash
sqlite3 demo.glaurung -separator $'\t' \
  "SELECT cite_id, tool, printf('0x%x', va_start), summary
   FROM evidence_log ORDER BY cite_id;" | \
  awk -F'\t' '{ printf "- [%s] **%s** %s — %s\n", $1, $2, $3, $4 }'
```

```markdown
- [1] **kickoff_analysis** — ELF/x86_64, 6 functions, ...
- [2] **list_strings** — sampled 20 of 38 strings
- [3] **view_function** 0x1160 — 432-byte frame, snprintf+memcpy
- [4] **list_xrefs_to** 0x4040 — 6 data_read sites
- ...
```

This is the agent's working transcript. Keep it as part of your
case file.

## What this enables

**Reproducibility.** Re-run the same kickoff on the same binary
and you get the same `evidence_log`. The agent's answer might
phrase differently between runs (LLM nondeterminism), but the
underlying tool calls are deterministic and recorded.

**Audit.** "Why does the agent think 0x4040 is the C2 endpoint
table?" Look up the citations in evidence_log. If the agent's
claims trace back to a sequence of tool calls that match the
binary's actual structure, the conclusion is sound. If the
citations are vague or unrelated, the answer is suspect.

**Sharing.** A `.glaurung` file with its evidence_log is a
complete artifact of an analysis session. Send it to a teammate
and they can re-read every tool call you (or your agent) made.

## What's next

You've finished the tutorial track. Next steps are project-
specific — open a real binary, run kickoff, and start asking
questions.

For the broader roadmap: see
[`docs/architecture/IDA_GHIDRA_PARITY.md`](../../architecture/IDA_GHIDRA_PARITY.md)
for what's shipped and what's pending.

For deeper dives:

- [Tier 4 — Recipes](../04-recipes/) — short copy-paste recipes
  for diff / export / typed-locals / bench.
- [Reference](../reference/) — CLI cheatsheet, REPL keymap,
  set_by ladder, sample corpus.
