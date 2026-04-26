# §Z — Evidence and citations

The `evidence_log` table is Glaurung's truth ledger. Every memory
tool the agent calls records a row capturing what was asked, what
came back, and a one-line summary. The agent's responses cite
these rows by id.

This chapter shows you how to read the log directly — useful for
spot-checking the agent's claims, building your own analyst
report, or debugging a session where the agent's answer didn't
match expectations.

> **Verified output.** Every block is captured by
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/05-kickoff-anatomy/`](../_fixtures/05-kickoff-anatomy/).
> The fixtures show the evidence_log on a fresh post-kickoff
> `.glaurung` (one row, one tool call). After an agent session
> the table will have many more rows — the schema and shape are
> the same.

## Reading the log

The `.glaurung` file is SQLite. The evidence table is queryable
with any sqlite3 client. Right after a fresh `kickoff`:

```bash
$ sqlite3 demo.glaurung \
    "SELECT cite_id, tool, summary FROM evidence_log ORDER BY cite_id LIMIT 10;"
```

```text
1|kickoff_analysis|kickoff: 6 fns, 6 named, 90 slots, 18 propagated, 0 structs
```

(Captured: [`_fixtures/05-kickoff-anatomy/evidence-log-head.out`](../_fixtures/05-kickoff-anatomy/evidence-log-head.out).)

One row, because only one tool has run — `kickoff_analysis`
itself. After a few rounds of agent chat the log fills up with
`view_function`, `list_xrefs_to`, `get_function_prototype`, etc.
rows.

## The full schema

```bash
$ sqlite3 demo.glaurung ".schema evidence_log"
```

```sql
CREATE TABLE evidence_log (
    cite_id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    tool TEXT NOT NULL,             -- e.g. "view_hex", "decompile_function"
    args_json TEXT NOT NULL,        -- inputs the tool was called with
    summary TEXT NOT NULL,          -- short human-readable description
    va_start INTEGER,               -- nullable: VA range this evidence covers
    va_end INTEGER,                 -- exclusive end
    file_offset INTEGER,            -- nullable file-offset alternative
    output_json TEXT,               -- structured output (caller-defined schema)
    created_at INTEGER NOT NULL
);
CREATE INDEX idx_evidence_binary
    ON evidence_log(binary_id);
CREATE INDEX idx_evidence_tool
    ON evidence_log(binary_id, tool);
CREATE INDEX idx_evidence_va
    ON evidence_log(binary_id, va_start);
```

(Captured: [`_fixtures/05-kickoff-anatomy/evidence-log-schema.out`](../_fixtures/05-kickoff-anatomy/evidence-log-schema.out).)

Useful columns:

- `cite_id` — the int the agent's responses cite.
- `tool` — which memory tool was invoked.
- `args_json` — exactly what the agent passed in.
- `summary` — one-line digest used in agent responses.
- `output_json` — the full structured result.
- `va_start` / `va_end` — for tools anchored to a VA range
  (decompile, view, xrefs).

A row's `args_json` and `output_json` start with the tool's input
shape and structured output respectively:

```bash
$ sqlite3 demo.glaurung \
    "SELECT cite_id, tool, summary, va_start, va_end,
            substr(args_json, 1, 80) AS args_head,
            substr(output_json, 1, 80) AS output_head
     FROM evidence_log ORDER BY cite_id LIMIT 3;"
```

```text
1|kickoff_analysis|kickoff: 6 fns, 6 named, 90 slots, 18 propagated, 0 structs|||{"binary_path": "/nas4/data/workspace-infosec/glaurung/samples/binaries/platform|{"arch": "x86_64", "auto_structs_emitted": 0, "by_set_by": {"analyzer": 6}, "cal
```

(Captured: [`_fixtures/05-kickoff-anatomy/evidence-log-args-output.out`](../_fixtures/05-kickoff-anatomy/evidence-log-args-output.out).)

The `va_start` / `va_end` columns are empty for `kickoff_analysis`
because it's a binary-scope tool, not anchored to a VA range.
Per-function tools like `view_function` and `list_xrefs_to`
populate them.

## Verify a citation

> **Illustrative**: the example below assumes the agent has run
> several tool calls (cite_id 12 in particular). The query shape
> is what's verified; the row contents will reflect whatever the
> agent actually saw in your session.

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
