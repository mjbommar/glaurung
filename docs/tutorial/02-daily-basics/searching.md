# §I — Searching

Goal: use `find` to produce an address or project object that a more specific
view can inspect.

## Set up

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
DB=demo.glaurung
uv run glaurung kickoff "$BIN" --db "$DB"
```

Current results are under
[`_fixtures/02-searching/`](../_fixtures/02-searching/).

## Search broadly, then narrow by kind

```bash
uv run glaurung find "$DB" main
uv run glaurung find "$DB" main --kind function
```

The default search spans functions, comments, data labels, types, stack
variables, strings, and disassembly. `--kind` avoids unrelated matches and is
preferable in automation. Compare
[`find-substring.out`](../_fixtures/02-searching/find-substring.out) with
[`find-kind-function.out`](../_fixtures/02-searching/find-kind-function.out).

An empty query lists a selected kind:

```bash
uv run glaurung find "$DB" "" --kind function
```

Do not hard-code the resulting count. Function discovery changes as analysis
improves; the checked inventory is
[`find-all-functions.out`](../_fixtures/02-searching/find-all-functions.out).

## Regex and case behavior

```bash
uv run glaurung find "$DB" '^_' --regex --kind function
uv run glaurung find "$DB" MAIN --kind function
uv run glaurung find "$DB" MAIN --kind function --case-sensitive
```

Plain and regex queries are case-insensitive by default. `--case-sensitive`
changes that behavior. See
[`find-regex-funcs.out`](../_fixtures/02-searching/find-regex-funcs.out) and
[`find-case-sensitive-flag.out`](../_fixtures/02-searching/find-case-sensitive-flag.out).

## Search strings and disassembly

```bash
uv run glaurung find "$DB" Hello --kind string
uv run glaurung find "$DB" '^push' --regex --kind disasm --limit 10
```

String locations are file offsets. Disassembly locations are virtual addresses.
Disassembly search can contain duplicate VA/snippet pairs when overlapping
analysis sweeps cover the same instruction, so bound interactive output and
deduplicate explicitly in scripts. See
[`find-strings.out`](../_fixtures/02-searching/find-strings.out) and
[`find-disasm.out`](../_fixtures/02-searching/find-disasm.out).

## Script with JSON

```bash
uv run glaurung find "$DB" main --kind function --format json
```

The current schema is captured in
[`find-json.out`](../_fixtures/02-searching/find-json.out). Treat it as a
pre-1.0 interface and test the exact revision used by automation.

## Pivot to evidence

```bash
uv run glaurung view "$DB" 0x11d0 --binary "$BIN"
uv run glaurung xrefs "$DB" 0x11d0 --binary "$BIN" --direction to
```

The useful loop is `find` → inspect the returned object or VA → follow precise
xrefs. A name match is navigation, not behavioral proof.

Continue to [§J — Bookmarks and journal](bookmarks-and-journal.md).
