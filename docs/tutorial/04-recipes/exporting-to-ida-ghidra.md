# §U — Export a project

Goal: export persisted knowledge as documentation, structured data, or an
import script without confusing export success with successful execution in a
third-party reverse-engineering tool.

## Create a project

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
DB=hello-c.glaurung
uv run glaurung kickoff "$BIN" --db "$DB"
```

## Human-readable and JSON exports

```bash
uv run glaurung export "$DB" --output-format markdown > analysis.md
uv run glaurung export "$DB" --output-format json > analysis.json
```

Markdown summarizes names, types, stack variables, and evidence. JSON includes
a schema version and the full structured sections. Current samples are
[`export-markdown-head.out`](../_fixtures/04-export/export-markdown-head.out)
and
[`export-json-summary.out`](../_fixtures/04-export/export-json-summary.out).
Counts reflect the project at export time.

## Generate tool-import scripts

```bash
uv run glaurung export "$DB" --output-format ida > import_ida.py
uv run glaurung export "$DB" --output-format binja > import_binja.py
uv run glaurung export "$DB" --output-format ghidra > import_ghidra.py
```

The generated script heads are captured for
[IDA](../_fixtures/04-export/export-ida-head.out),
[Binary Ninja](../_fixtures/04-export/export-binja-head.out), and
[Ghidra](../_fixtures/04-export/export-ghidra-head.out).

Review generated code before running it. Verify that the target database is the
same binary and image base, make a project backup, and inspect how name/type
conflicts are handled. Tutorial generation checks do not launch or validate the
scripts inside those proprietary/external applications.

Continue to [§V — Typed locals](typed-locals-from-libc.md).
