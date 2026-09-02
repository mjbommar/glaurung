# §C — CLI tour

> **Kind:** guide · **Status:** maintained

Goal: learn the main command families and when they read a binary directly
versus when they use a persistent `.glaurung` project.

This is an orientation, not a promise that every top-level command fits one
workflow. Use the [CLI cheatsheet](../../reference/cli.md) and
`uv run glaurung <command> --help` for the complete current surface.

## Set up one binary and project

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
DB=tutorial.glaurung
```

The checked output for this chapter is under
[`_fixtures/01-cli-tour/`](../_fixtures/01-cli-tour/).

## Inspect a binary without a project

These commands read the binary and print a result without creating a database:

```bash
uv run glaurung triage "$BIN"
uv run glaurung strings "$BIN" --min-len 6 --raw-limit 10
uv run glaurung symbols "$BIN" --limit 20
uv run glaurung disasm "$BIN" --addr 0x1150 --max-instructions 5
uv run glaurung cfg "$BIN"
uv run glaurung detect-packer "$BIN"
```

Use them for a quick question:

- `triage` identifies the container, architecture, and high-level clues.
- `strings` extracts and classifies printable data.
- `symbols` reports available imports, exports, and symbols.
- `disasm` decodes a bounded instruction window. Addresses use `--addr`.
- `cfg` discovers functions and control-flow edges.
- `detect-packer` reports packer evidence and entropy heuristics.

Representative verified output is available for
[`triage`](../_fixtures/01-cli-tour/triage.out),
[`strings`](../_fixtures/01-cli-tour/strings-head.out),
[`disasm`](../_fixtures/01-cli-tour/disasm-head.out), and
[`cfg`](../_fixtures/01-cli-tour/cfg-head.out).

## Build the persistent project

```bash
uv run glaurung kickoff "$BIN" --db "$DB"
```

`kickoff` is the bridge from stateless inspection to analyst workflow. It
indexes recovered functions, names, types, xrefs, strings, and evidence in the
SQLite project. It is safe to inspect the report for broad orientation, but
exact counts are analyzer outputs rather than compatibility guarantees. See the
current [`kickoff.out`](../_fixtures/01-cli-tour/kickoff.out).

## Search and inspect the project

```bash
uv run glaurung find "$DB" main --kind function
uv run glaurung view "$DB" 0x1150 --binary "$BIN" \
  --hex-window 16 --pseudo-lines 5
uv run glaurung xrefs "$DB" 0x11d0 --binary "$BIN" --direction to
uv run glaurung strings-xrefs "$DB" --binary "$BIN" --limit 5
uv run glaurung frame "$DB" 0x1150 list --binary "$BIN"
```

The database supplies persistent names, types, and history. `--binary` supplies
bytes when a view needs to disassemble or render content that is not stored in
the project itself.

Read xrefs as precise recorded relationships, not as a guarantee that every
indirect call or data use was recovered. The current fixtures show the exact
[`view`](../_fixtures/01-cli-tour/view-main.out) and
[`xrefs`](../_fixtures/01-cli-tour/xrefs-print-sum.out) results.

## Work interactively and preserve history

```bash
uv run glaurung repl "$BIN" --db "$DB"
uv run glaurung undo "$DB" --list
```

The REPL is the normal place to navigate, rename, comment, label data, and edit
stack variables. Analyst writes carry provenance and create undo records. The
next chapter exercises that loop end to end.

For durable notes outside the REPL, inspect the subcommand help before writing:

```bash
uv run glaurung bookmark --help
uv run glaurung journal --help
```

## Decompile, graph, compare, and export

These command families answer larger questions:

```bash
uv run glaurung decompile "$BIN" --func main
uv run glaurung graph "$BIN" callgraph > callgraph.dot
uv run glaurung diff old-binary new-binary
uv run glaurung export "$DB" --output-format markdown
```

`decompile` selects a function with `--func`; the function address is not a
second positional argument. Treat its output as experimental and validate it
against disassembly and xrefs. `graph` emits DOT, `diff` compares recovered
functions, and `export` renders persisted project knowledge for other tools.

## Patch only a copied output

`patch` always takes an input and output path. Start with `--help`, choose a new
output file, and use `--verify` to re-read the result:

```bash
uv run glaurung patch --help
uv run glaurung patch "$BIN" /tmp/hello-patched \
  --va 0x11e0 --nop --verify --force
```

Verification confirms the requested byte-level edit, not that the patched
program is safe or semantically correct. Test patched artifacts in an isolated
environment.

## Format-specific and optional LLM commands

The top-level inventory also includes JVM, Lua, PE/Windows, generated-type, and
cross-binary group workflows. Their inputs and subcommands differ, so begin
with the relevant help or walkthrough rather than applying native-ELF examples
unchanged.

LLM-backed commands require provider credentials. For example, `ask` takes the
binary path first and a question through `-a`:

```bash
uv run glaurung ask "$BIN" --route -a "What behavior should I verify first?"
```

An LLM response is an investigative lead. Retain and check the cited binary
evidence before drawing conclusions.

Continue to [§D — REPL tour](repl-tour.md).
