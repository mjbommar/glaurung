# §H — Strings and data

> **Kind:** guide · **Status:** maintained

Goal: separate “string exists in the file” from “the current xref index records
a use,” then add a type-correct label to a global pointer.

## Set up

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
DB=demo.glaurung
uv run glaurung kickoff "$BIN" --db "$DB"
```

Current results are under
[`_fixtures/02-strings-and-data/`](../_fixtures/02-strings-and-data/).

## Browse persisted strings and indexed uses

```bash
uv run glaurung strings-xrefs "$DB" --binary "$BIN" --limit 10
uv run glaurung strings-xrefs "$DB" --binary "$BIN" \
  --min-len 12 --limit 10
uv run glaurung strings-xrefs "$DB" --binary "$BIN" \
  --used-only --limit 10
```

`--min-len` filters noise. `--used-only` removes strings without a recorded
`data_read` use. In the current sample that filtered view is empty, even though
interesting strings exist; this demonstrates an indexing limitation, not an
absence of runtime use. Compare
[`strings-xrefs-default.out`](../_fixtures/02-strings-and-data/strings-xrefs-default.out)
and
[`strings-xrefs-used-only.out`](../_fixtures/02-strings-and-data/strings-xrefs-used-only.out).

For automation:

```bash
uv run glaurung strings-xrefs "$DB" --binary "$BIN" \
  --min-len 12 --limit 5 --format json
```

See [`strings-xrefs-json.out`](../_fixtures/02-strings-and-data/strings-xrefs-json.out).

## Label the global storage accurately

The checked-in binary's symbol table places the primary C2 server pointer at
`0x4040`. In the REPL:

```text
label set 0x4040 primary_c2_server void *
y 0x4040 const char *
label
save
```

This models a pointer stored at the global address. It does not claim that a
64-byte character array begins there. The verified writes and listing are
[`repl-label.out`](../_fixtures/02-strings-and-data/repl-label.out),
[`repl-retype.out`](../_fixtures/02-strings-and-data/repl-retype.out), and
[`repl-label-list.out`](../_fixtures/02-strings-and-data/repl-label-list.out).

Verify through the project search surface:

```bash
uv run glaurung find "$DB" primary_c2_server --kind data
uv run glaurung find "$DB" server --kind data
```

See [`find-label.out`](../_fixtures/02-strings-and-data/find-label.out) for the
exact-name query and
[`find-data-prefix.out`](../_fixtures/02-strings-and-data/find-data-prefix.out)
for the prefix query.

## Evidence discipline

- A string's presence does not establish reachability or intent.
- A missing xref can be a recovery gap.
- A manual label or type should describe storage proven by bytes, symbols,
  disassembly, or repeated use—not merely the string's wording.

Continue to [§I — Searching](searching.md).
