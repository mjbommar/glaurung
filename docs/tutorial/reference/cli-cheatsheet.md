# Glaurung CLI cheatsheet

One-page reference for every `glaurung` subcommand. Each entry has
the canonical invocation and a one-liner pointing to the tutorial
chapter that goes deep on it.

> Source of truth: this table is regenerated whenever a subcommand
> ships, lands, or changes its arguments. If you find a drift between
> this file and `glaurung --help`, that's a bug — file it.

## Load / triage

| Command | What it does | Tutorial |
|---|---|---|
| `glaurung triage <binary>` | Format / arch / language detection + IOCs | Tier 1 §B |
| `glaurung kickoff <binary> --db tutorial.glaurung` | One-shot first-touch (~300ms): detect-packer + triage + analyze + index + demangle + propagate + recover-structs | Tier 1 §B, Tier 5 §X |
| `glaurung detect-packer <binary>` | Packer fingerprint match (UPX/Themida/VMProtect/...) + entropy fallback | Tier 3 §R |

## Inspect

| Command | What it does | Tutorial |
|---|---|---|
| `glaurung disasm <binary> <va>` | Disassemble a code window starting at a VA | Tier 1 §C |
| `glaurung decompile <binary> <va>` | Pseudocode for one or more functions | Tier 1 §C |
| `glaurung view <db> <va>` | Synchronised hex / disasm / pseudocode tri-pane (#223) | Tier 2 §H |
| `glaurung xrefs <db> <va>` | Cross-references panel: callers / readers / writers (#219) | Tier 2 §F |
| `glaurung frame <db> <fn-va>` | Stack-frame editor: list slots, rename, retype, discover (#221) | Tier 2 §G |
| `glaurung strings-xrefs <db>` | IDA-style strings panel with data_read use sites (#222) | Tier 2 §H |
| `glaurung find <db> <query>` | Substring/regex search across functions, comments, labels, types, stack vars, strings, disasm (#225) | Tier 2 §I |
| `glaurung strings <binary>` | Standalone strings analyzer (no DB, no use sites) | Tier 2 §H |
| `glaurung symbols <binary>` | Symbol table dump (imports / exports / debug) | Tier 1 §C |
| `glaurung cfg <binary>` | Function discovery + bounded CFG | Tier 1 §C |

## Annotate

| Command | What it does | Tutorial |
|---|---|---|
| `glaurung repl <binary> --db tutorial.glaurung` | Interactive REPL with persistent KB; see `repl-keymap.md` | Tier 1 §D |
| `glaurung bookmark <db> add\|list\|delete` | "Come back to this" markers (#226) | Tier 2 §J |
| `glaurung journal <db> add\|list\|delete` | Project-level dated free-form notes (#226) | Tier 2 §J |
| `glaurung undo <db> [-n N] [--list]` | Revert the most recent analyst KB write(s) (#228) | Tier 2 §K |
| `glaurung redo <db> [-n N]` | Re-apply the most recent undone write(s) (#228) | Tier 2 §K |
| `glaurung name-func <binary> <va>` | LLM-suggested function name from decompiled pseudocode | Tier 5 §Y |

## Patch / verify

| Command | What it does | Tutorial |
|---|---|---|
| `glaurung patch in out --va N --bytes "90 90 90"` | Raw byte patch | Tier 2 §L |
| `glaurung patch in out --va N --nop --verify` | NOP-out the instruction (size-preserving), confirm via re-disasm (#224) | Tier 2 §L |
| `glaurung patch in out --va N --jmp <target> --verify` | Replace with `jmp <target>` (size-preserving, NOP-padded) (#224) | Tier 2 §L |
| `glaurung patch in out --va N --force-branch true\|false --verify` | Force conditional branch always-taken / never-taken (#224) | Tier 2 §L |
| `glaurung verify-recovery <recovered-dir>` | Compile-check rewritten source, optionally diff bytes against original | Tier 4 §V |
| `glaurung diff a.elf b.elf` | Function-level binary diff | Tier 4 §T |

## Export / interop

| Command | What it does | Tutorial |
|---|---|---|
| `glaurung export <db> --output-format markdown\|json\|header\|ida\|binja\|ghidra` | Dump a .glaurung as docs / IDAPython / BinaryNinja / Ghidra script | Tier 4 §U |
| `glaurung graph <binary> callgraph` | DOT/GraphViz callgraph | Tier 1 §C |
| `glaurung graph <binary> cfg <fn>` | DOT for one function's CFG | Tier 1 §C |

## Bytecode / managed runtimes

| Command | What it does | Tutorial |
|---|---|---|
| `glaurung classfile <path>` | Java .class / .jar / .war / .ear method+field metadata (#209) | Tier 3 §P |
| `glaurung luac <path>` | Lua bytecode (.luac / LuaJIT) recognizer + source-name extraction (#211) | Tier 3 §P (sibling) |

For .NET PEs: use `glaurung kickoff` — CIL metadata recovery (#210)
runs automatically inside `index_callgraph`. Same for stripped Go
binaries (#212 gopclntab).

## Agent (LLM, optional)

| Command | What it does | Tutorial |
|---|---|---|
| `glaurung ask "<question>"` | Natural-language Q&A; agent has 50+ memory tools and writes to evidence_log | Tier 5 §Y |

## Bench / regression

| Command | What it does | Tutorial |
|---|---|---|
| `python -m glaurung.bench --ci-matrix --output baseline.json` | Score the 10-binary CI matrix; produces JSON + markdown summary | Tier 4 §W |
| `python -m glaurung.bench --packed-matrix --output packed.json` | Score the UPX-packed corpus; surfaces "Packed binaries: N" line (#213) | Tier 4 §W |

## Global flags

Every subcommand accepts:

- `-h` / `--help` — usage + flags for that subcommand
- `--format json` — emit JSON instead of plain text (where applicable)

Top-level:

- `glaurung --version`
- `glaurung --help`

## Argument conventions

- `<binary>` — path to a real binary (ELF / Mach-O / PE / .class / .luac)
- `<db>` — path to a `.glaurung` project file (created by `kickoff` or `repl`)
- `<va>` — virtual address, accepts `0x` hex or decimal
- `<fn-va>` — function entry VA (must match an entry the analyzer discovered)
- `<offset>` — signed stack-frame offset, accepts `-0x10` or `-16`

## See also

- [`repl-keymap.md`](repl-keymap.md) — every REPL keystroke
- [`set-by-precedence.md`](set-by-precedence.md) — the provenance ladder
- [`sample-corpus.md`](sample-corpus.md) — every binary in `samples/binaries/` with the chapter that uses it
