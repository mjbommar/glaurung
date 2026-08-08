# Glaurung CLI cheatsheet

This page inventories every top-level command currently printed by
`uv run glaurung --help`. It gives safe invocation shapes, not every option.
Always check `uv run glaurung <command> --help` before scripting a pre-1.0
interface.

<!-- Long command forms in the mapping tables are intentionally unwrapped. -->
<!-- markdownlint-disable MD013 -->

Examples assume the repository root and use:

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
DB=analysis.glaurung
```

## Inspect binary inputs

| Command | Minimal shape | Purpose |
| --- | --- | --- |
| `triage` | `uv run glaurung triage "$BIN"` | Identify format, architecture, language clues, strings, and security-relevant metadata. |
| `strings` | `uv run glaurung strings "$BIN"` | Extract strings and related statistics without a project. |
| `symbols` | `uv run glaurung symbols "$BIN"` | List available symbols, imports, exports, or libraries. |
| `disasm` | `uv run glaurung disasm "$BIN" --addr 0x1150` | Decode an instruction window. The address is supplied with `--addr`. |
| `cfg` | `uv run glaurung cfg "$BIN"` | Discover functions and build control-flow graphs. |
| `detect-packer` | `uv run glaurung detect-packer "$BIN"` | Report packer signatures and heuristic evidence. |

## Decompile and explain

| Command | Minimal shape | Purpose |
| --- | --- | --- |
| `decompile` | `uv run glaurung decompile "$BIN" --func main` | Render experimental pseudocode for a selected function; also supports `--all` and `--vas`. |
| `explain` | `uv run glaurung explain "$BIN" --func main` | Rewrite one recovered function in a higher-level style; inspect help for LLM/fidelity behavior. |
| `name-func` | `uv run glaurung name-func "$BIN" --func 0x1150` | Ask the configured LLM to suggest a function name from recovered context. |

Validate decompiler and LLM output against bytes, disassembly, xrefs, and
provenance before relying on it.

## Create and navigate projects

| Command | Minimal shape | Purpose |
| --- | --- | --- |
| `kickoff` | `uv run glaurung kickoff "$BIN" --db "$DB"` | Run the default first-touch analysis and persist a project. |
| `repl` | `uv run glaurung repl "$BIN" --db "$DB"` | Open the interactive, persistent analyst session. |
| `view` | `uv run glaurung view "$DB" 0x1150 --binary "$BIN"` | Align bytes, disassembly, and pseudocode at one VA. |
| `find` | `uv run glaurung find "$DB" main --kind function` | Search persisted functions, comments, labels, types, strings, and disassembly. |
| `xrefs` | `uv run glaurung xrefs "$DB" 0x1150 --binary "$BIN"` | List recorded references to or from a VA. |
| `frame` | `uv run glaurung frame "$DB" 0x1150 list --binary "$BIN"` | List, discover, rename, or retype stack-frame slots. |
| `strings-xrefs` | `uv run glaurung strings-xrefs "$DB" --binary "$BIN"` | Join recovered strings to indexed data-read sites. |
| `bookmark` | `uv run glaurung bookmark "$DB" list` | Add, list, or delete address bookmarks. |
| `journal` | `uv run glaurung journal "$DB" list` | Add, list, or delete dated project notes. |
| `undo` | `uv run glaurung undo "$DB" --list` | Inspect or revert analyst KB writes. |
| `redo` | `uv run glaurung redo "$DB"` | Reapply writes reverted by `undo`. |

`frame`, `bookmark`, and `journal` have action-specific positional arguments;
read their help before issuing a write.

## Compare, graph, patch, verify, and export

| Command | Minimal shape | Purpose |
| --- | --- | --- |
| `graph` | `uv run glaurung graph "$BIN" callgraph` | Export a callgraph, or use `cfg FUNCTION`, as DOT. |
| `diff` | `uv run glaurung diff old.bin new.bin` | Compare recovered functions between two binaries. |
| `patch` | `uv run glaurung patch in.bin out.bin --va 0x1150 --nop --verify` | Write a byte-level patch to a separate output. |
| `verify-recovery` | `uv run glaurung verify-recovery recovered.c` | Compile-check one recovered C/C++ source file; optionally run or compare it. |
| `export` | `uv run glaurung export "$DB" --output-format markdown` | Export a project as JSON, Markdown, C header, or tool-import script. |

Patch verification confirms the requested edit was encoded and re-read. It
does not establish semantic equivalence, exploit safety, or runtime correctness.

## Managed code and format-specific inspection

| Command | Minimal shape | Purpose |
| --- | --- | --- |
| `classfile` | `uv run glaurung classfile path/to/App.class` | Parse Java class or archive metadata. |
| `java` | `uv run glaurung java --help` | Enter the `triage`, `security`, or `recovery` JVM workflows. |
| `java-recovery-report` | `uv run glaurung java-recovery-report app.jar` | Recover a Java archive and produce a ranked report. |
| `luac` | `uv run glaurung luac path/to/chunk.luac` | Recognize Lua/LuaJIT bytecode and report header information. |
| `pe` | `uv run glaurung pe --help` | Enter PE resource, manifest, or version inspection. |
| `windows-risk` | `uv run glaurung windows-risk path/to/driver.sys` | Summarize Windows imports, string xrefs, and risky function shapes. |

Some Java recovery modes invoke external decompilers, build tools, or optional
network resolution. Read their help and output-directory policy before use.

## Windows, type data, and multi-binary analysis

| Command | Minimal shape | Purpose |
| --- | --- | --- |
| `types` | `uv run glaurung types sync --help` | Manage generated type and prototype data. |
| `windows` | `uv run glaurung windows --help` | Enter the larger Windows project-analysis and artifact workflow. |
| `locks` | `uv run glaurung locks --db project.glaurung --function DriverEntry driver.sys` | Inventory lock state for one function. |
| `group` | `uv run glaurung group --member a=a.sys --member b=b.sys` | Analyze shared tags across at least two named binaries. |

The `windows` surface contains many specialized nested commands. Its live help,
not a flattened copy here, is the maintainable source of truth.

## Optional LLM question answering

| Command | Minimal shape | Purpose |
| --- | --- | --- |
| `ask` | `uv run glaurung ask "$BIN" --route -a "What should I verify?"` | Ask a natural-language question with a routed tool subset. |

`ask`, `name-func`, and LLM-dependent modes require configured provider
credentials and can incur cost. See
[runtime configuration](../../development/setup.md#runtime-configuration).

## Benchmark harness

The benchmark runner is a Python module, not a top-level `glaurung` subcommand:

```bash
uv run python -m glaurung.bench --help
```

## Shared flags and notation

The live subcommand help currently exposes common output controls such as
`--format`, `--json`, `--no-color`, `--quiet`, and `--verbose`. Output support
can still vary by command and nested action, so test the exact mode you plan to
automate.

- `<binary>` or `$BIN`: an input file path.
- `<db>` or `$DB`: a `.glaurung` SQLite project.
- `VA`: a virtual address, conventionally written as hexadecimal.
- `NAME|VA`: either a recovered name or a virtual address.

Root-level inventory and version:

```bash
uv run glaurung --help
uv run glaurung --version
```

See also the [REPL keymap](repl-keymap.md), [sample corpus](sample-corpus.md),
and [`set_by` precedence](set-by-precedence.md).
