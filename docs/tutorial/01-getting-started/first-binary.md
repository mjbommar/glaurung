# §B — Analyze your first binary

> **Kind:** guide · **Status:** maintained

Goal: turn a shipped ELF into a persistent `.glaurung` project, locate useful
functions, and inspect one address without mistaking pseudocode for proof.

Run every command from the repository root.

## Choose the sample

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug
file "$BIN"
```

This sample is a small x86-64 ELF with debug information. The current captured
`file` result is in [`file.out`](../_fixtures/01-first-binary/file.out).

## Create a project with `kickoff`

```bash
uv run glaurung kickoff "$BIN" --db tutorial.glaurung
```

`kickoff` performs the default first-touch pipeline and writes its durable
results to `tutorial.glaurung`. Read the report by category:

- **File identity**: format, architecture, entry point, and input size.
- **Functions and names**: discovered code plus names recovered from available
  sources. Placeholder analyzer names are lower-confidence than debug or manual
  names.
- **Type information**: prototypes, stack slots, and inferred structures that
  later views can reuse.
- **Strings and IOCs**: candidate evidence for investigation, not a malware
  verdict.
- **Completion**: whether the bounded pipeline finished and where the project
  was written.

Counts are intentionally absent here because analysis improves over time. The
full output from the currently verified revision is
[`kickoff.out`](../_fixtures/01-first-binary/kickoff.out).

## Inspect provenance in SQLite

A `.glaurung` file is a SQLite database. Read-only SQL is useful when auditing
what the CLI persisted:

```bash
sqlite3 tutorial.glaurung -cmd ".mode column" \
  "SELECT printf('%#x', entry_va) AS entry_va, canonical, set_by \
   FROM function_names \
   WHERE canonical IN ('_start', 'main') \
   ORDER BY entry_va;"
```

The `set_by` column records who supplied a name. In this sample both landmarks
are currently analyzer-provided; do not silently treat them as manual or debug
facts. See [`sqlite-fnames.out`](../_fixtures/01-first-binary/sqlite-fnames.out)
and the [`set_by` reference](../../reference/provenance.md).

Use the CLI for normal navigation and SQLite for audits or automation. Avoid
editing the database directly: CLI and REPL writes preserve provenance and undo
history.

## Find `main`

```bash
uv run glaurung find tutorial.glaurung main --kind function
```

`find` searches the persisted project. Copy the returned virtual address for
subsequent commands rather than assuming it is the same in another build. The
verified result is [`find-main.out`](../_fixtures/01-first-binary/find-main.out).

## Inspect a synchronized view

The sample entry point reported by `kickoff` can be opened with:

```bash
uv run glaurung view tutorial.glaurung 0x11e0 \
  --binary "$BIN" \
  --hex-window 32 \
  --pseudo-lines 6
```

`view` aligns three representations around one virtual address:

- bytes from the original binary;
- decoded instructions;
- experimental pseudocode informed by project names and types.

Use bytes and disassembly as primary evidence. Pseudocode is a hypothesis that
can be incomplete or wrong, especially around control flow, calling
conventions, and recovered types. The checked result is
[`view.out`](../_fixtures/01-first-binary/view.out).

## Scan strings

```bash
uv run glaurung strings "$BIN" --min-len 6 --raw-limit 30
```

String output can be large. Filter or bound it for the question at hand, then
follow interesting values through `strings-xrefs` after `kickoff`; do not infer
reachability or behavior from presence alone.

## What you have now

You have a real binary, a persistent analysis project, a provenance-aware name
lookup, and a synchronized inspection workflow. Keep `tutorial.glaurung` for
the next chapters, or recreate it with `kickoff` when you want a clean state.

Continue to [§C — CLI tour](cli-tour.md).
