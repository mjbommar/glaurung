# §C — CLI tour

Goal: a 5-minute walkthrough of every shipped subcommand so you
know what's available before going deep on any one of them.

> If you just want the cheatsheet, jump to
> [`reference/cli-cheatsheet.md`](../reference/cli-cheatsheet.md).
> This page narrates the same content in workflow order.

## Setup

We'll continue from §B. If you skipped it:

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug
glaurung kickoff $BIN --db tutorial.glaurung
```

## 1. Triage and load

These commands inspect a binary without writing anything:

```bash
glaurung triage $BIN              # format / arch / language / IOCs
glaurung detect-packer $BIN       # UPX / Themida / VMProtect / entropy fallback
glaurung disasm $BIN 0x11e0       # raw disassembly window
glaurung decompile $BIN 0x11e0    # raw pseudocode for one function
glaurung strings $BIN             # every string + classification
glaurung symbols $BIN             # symbol table dump
glaurung cfg $BIN                 # function discovery + bounded CFG
```

`kickoff` is the one-shot version of triage + analyze + index +
propagate that produces the `.glaurung` project file every other
command reads from. Use it once per binary.

## 2. Navigate the KB

These read `tutorial.glaurung` (the project file `kickoff` wrote):

```bash
glaurung view tutorial.glaurung 0x10d0 --binary $BIN
glaurung xrefs tutorial.glaurung 0x10d0 --binary $BIN
glaurung frame tutorial.glaurung 0x10d0 --binary $BIN
glaurung strings-xrefs tutorial.glaurung --binary $BIN
glaurung find tutorial.glaurung main --kind function
```

Each command has a Tier 2 chapter that goes deep. Try them now to
get a feel for the output shapes.

## 3. Annotate

Writes back to `tutorial.glaurung`:

```bash
# Bookmarks + free-form journal.
glaurung bookmark tutorial.glaurung add 0x1140 "weird branch — investigate"
glaurung journal tutorial.glaurung add "today: tracing parse_packet"

# Mostly done from the REPL — see §D below.
glaurung repl $BIN --db tutorial.glaurung
```

Inside the REPL, single-key shortcuts (`n`, `y`, `c`, `x`, `d`,
`l`...) drive the workflow. See [§D `repl-tour.md`](repl-tour.md) and
[`reference/repl-keymap.md`](../reference/repl-keymap.md).

## 4. Patch

Modify a binary while keeping the original intact:

```bash
# NOP-out an instruction (size-preserving).
glaurung patch in.elf out.elf --va 0x1140 --nop --verify

# Force a conditional always-taken.
glaurung patch in.elf out.elf --va 0x1140 --force-branch true --verify

# Redirect to a different VA.
glaurung patch in.elf out.elf --va 0x1140 --jmp 0x1200 --verify

# Raw bytes (legacy).
glaurung patch in.elf out.elf --va 0x1140 --bytes "90 90 90"
```

The `--verify` flag re-disassembles the patched VA in the output
binary so you can confirm the encoding. See
[§L `patch-and-verify.md`](../02-daily-basics/patch-and-verify.md).

## 5. Undo / redo

Reverse any analyst KB write (rename / retype / comment / data
label / stack var):

```bash
glaurung undo tutorial.glaurung           # revert the last write
glaurung undo tutorial.glaurung -n 5      # revert the last 5 writes
glaurung undo tutorial.glaurung --list    # show history without mutating
glaurung redo tutorial.glaurung           # re-apply
```

Why `auto` / `dwarf` / `propagated` writes don't enter the log: see
[`reference/set-by-precedence.md`](../reference/set-by-precedence.md).

## 6. Diff and export

Compare two binaries or hand off your KB to another tool:

```bash
# Function-level diff (BinDiff-style).
glaurung diff old.elf new.elf

# Export the KB.
glaurung export tutorial.glaurung --output-format json     # round-trippable
glaurung export tutorial.glaurung --output-format markdown # human report
glaurung export tutorial.glaurung --output-format header   # C header
glaurung export tutorial.glaurung --output-format ida      # IDAPython script
glaurung export tutorial.glaurung --output-format binja    # Binary Ninja script
glaurung export tutorial.glaurung --output-format ghidra   # Ghidra script
```

The IDA / BinaryNinja / Ghidra scripts apply your renames, comments,
data labels, and types inside those tools — so Glaurung becomes the
fast-iterate engine and the polished tool gets the result.

## 7. Bytecode / managed runtimes

For non-native binaries, Glaurung has format-specific surfaces:

```bash
# JVM .class / .jar.
glaurung classfile samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class
glaurung classfile samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar

# Lua bytecode.
glaurung luac samples/binaries/platforms/linux/amd64/export/lua/hello-lua5.3.luac

# .NET / Mono PE — no special command; kickoff handles it.
glaurung kickoff samples/binaries/platforms/linux/amd64/export/dotnet/mono/Hello-mono.exe \
  --db dotnet.glaurung
glaurung find dotnet.glaurung Main --kind function
# → Hello::Main  (set_by=cil)

# Stripped Go — also handled by kickoff.
glaurung kickoff samples/binaries/platforms/linux/amd64/export/go/hello-go --db go.glaurung
glaurung find go.glaurung main. --kind function | head
# → main.main  (set_by=gopclntab), main.worker, ...
```

Tier 3 covers each in depth.

## 8. Visualize

```bash
# DOT/GraphViz.
glaurung graph $BIN callgraph         | dot -Tsvg > callgraph.svg
glaurung graph $BIN cfg main          | dot -Tsvg > main-cfg.svg
```

## 9. Bench / regression

```bash
# Score the standard 10-binary CI matrix.
python -m glaurung.bench --ci-matrix --output baseline.json

# Score the UPX-packed corpus (regression coverage for #187).
python -m glaurung.bench --packed-matrix --output packed.json
```

See Tier 4 §W `bench-harness-as-ci.md` for using this in your CI.

## 10. Agent (optional, requires LLM credentials)

```bash
glaurung ask $BIN "what does this binary do?"
glaurung name-func $BIN 0x1140
```

Tier 5 covers the agent workflow. **Tiers 1-4 are 100% deterministic
— no API key needed.**

## Reference

For the complete table sorted by category:
[`reference/cli-cheatsheet.md`](../reference/cli-cheatsheet.md).

## Next: §D `repl-tour.md`

The REPL is where most of the day-to-day annotation work happens —
single keystrokes drive a cursor-based navigation model.

→ [§D `repl-tour.md`](repl-tour.md)
