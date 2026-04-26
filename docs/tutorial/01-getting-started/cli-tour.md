# §C — CLI tour

Goal: a 5-minute walkthrough of every shipped subcommand so you
know what's available before going deep on any one of them.

> If you just want the cheatsheet, jump to
> [`reference/cli-cheatsheet.md`](../reference/cli-cheatsheet.md).
> This page narrates the same content in workflow order.

> **Verified output.** Every block is captured by
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/01-cli-tour/`](../_fixtures/01-cli-tour/).

## Setup

```bash
$ BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
```

(Same binary as §B / §M / §F. Small enough to inspect by hand.)

## 1. Triage and load

These commands inspect a binary without writing anything:

### `triage` — first-touch fingerprint

```bash
$ glaurung triage $BIN
```

```text
path: samples/.../hello-c-clang-debug
size: 17680 bytes (17.3 KiB)
verdicts: 1
format=ELF arch=x86_64 64-bit endianness=Little confidence=0.86
symbols: imports=7 exports=0 libs=1 flags: debug,nx,aslr,relro,pie
strings: ascii=105 utf8=1 u16le=0 u16be=0
languages: (none)
scripts: Latin=4
entropy: overall=1.97
```

(Captured: [`_fixtures/01-cli-tour/triage.out`](../_fixtures/01-cli-tour/triage.out).)

Format / arch / language verdict, symbol counts, strings histogram,
entropy. The "is this binary worth analyzing?" filter.

### `strings` — every printable run

```bash
$ glaurung strings $BIN | head -10
```

```text
path: samples/.../hello-c-clang-debug
size: 17680 bytes (17.3 KiB)
encodings: ascii=105 utf8=1 u16le=0 u16be=0
languages: (none)
scripts: Latin=16
lengths: count=105 min=4 max=44 mean=13.3 median=11.0 p90=27.0 p99=38.0
entropy: count=105 min=1.50 max=4.18 mean=2.97 p90=3.84 p99=4.11
[0x318] ascii    len=  27 3.86 lang=- script=- | /lib64/ld-linux-x86-64.so.2
[0x489] ascii    len=  14 3.18 lang=- script=- | __cxa_finalize
[0x498] ascii    len=  17 3.26 lang=- script=- | __libc_start_main
```

(Captured: [`_fixtures/01-cli-tour/strings-head.out`](../_fixtures/01-cli-tour/strings-head.out).)

Statistics header, then every string with offset / encoding /
length / entropy / language guess. For per-string xrefs (where in
the code each is referenced), see `strings-xrefs` in §H.

### `disasm` — raw disassembly preview

```bash
$ glaurung disasm $BIN --addr 0x1150 --max-instructions 5
```

```text
engine: iced-x86 arch: x86_64
0x1150: 55                   push rbp
0x1151: 4889e5               mov rbp, rsp
0x1154: 4883ec20             sub rsp
0x1158: c745fc00000000       mov rbp:[rbp - 0x4], 0x0
0x115f: 897df8               mov rbp:[rbp - 0x8], edi

note: truncated preview output.
- Read only first 256 bytes of file
- Stopped after 5 instructions
```

(Captured: [`_fixtures/01-cli-tour/disasm-head.out`](../_fixtures/01-cli-tour/disasm-head.out).)

Quick preview at any VA. For function-aware decompile use
`view … --pane disasm` after `kickoff`.

### `cfg` — function discovery + bounded CFG

```bash
$ glaurung cfg $BIN | head -10
```

```text
functions: 9 | callgraph edges: 12
- _start @0x1060 blocks=4 edges=4 size=89
- deregister_tm_clones @0x1090 blocks=4 edges=4 size=41
- register_tm_clones @0x10c0 blocks=4 edges=4 size=57
- __do_global_dtors_aux @0x1100 blocks=5 edges=4 size=57
- frame_dummy @0x1140 blocks=5 edges=5 size=9
- main @0x1150 blocks=4 edges=5 size=127
- print_sum @0x11d0 blocks=1 edges=0 size=34
- static_function @0x1200 blocks=1 edges=0 size=41
- sub_117b @0x117b blocks=4 edges=5 size=84
```

(Captured: [`_fixtures/01-cli-tour/cfg-head.out`](../_fixtures/01-cli-tour/cfg-head.out).)

Function discovery, basic-block counts, callgraph edges. Stateless
— doesn't need a `.glaurung` project.

### Other inspect-only subcommands

- `glaurung detect-packer $BIN` — UPX / Themida / VMProtect / entropy fallback
- `glaurung decompile $BIN <va>` — raw pseudocode for one function (no KB)
- `glaurung symbols $BIN` — symbol table dump

## 2. Kickoff — the one-shot pipeline

`kickoff` is the one-shot version of triage + analyze + index +
propagate that produces the `.glaurung` project file every other
command reads from. Use it once per binary.

```bash
$ glaurung kickoff $BIN --db tutorial.glaurung
```

```markdown
# Kickoff analysis — hello-c-clang-debug

- format: **ELF**, arch: **x86_64**, size: **17680** bytes
- entry: **0x1060**

## Functions
- discovered: **9** (with blocks: 9, named: 8)
- callgraph edges: **5**
- name sources: analyzer=9

## Type system
- stdlib prototypes loaded: **192**
- DWARF types imported: **0**
- stack slots discovered: **36**
- types propagated: **0**
…
```

(Captured: [`_fixtures/01-cli-tour/kickoff.out`](../_fixtures/01-cli-tour/kickoff.out).)

See [§B `first-binary.md`](first-binary.md) for the full kickoff
narrative.

## 3. Navigate the KB

These read the `.glaurung` file kickoff wrote:

### `find` — search across every kind

```bash
$ glaurung find tutorial.glaurung main --kind function
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
function    0x1150          main  (set_by=analyzer)
```

(Captured: [`_fixtures/01-cli-tour/find-main.out`](../_fixtures/01-cli-tour/find-main.out).)

Goes deep in [§I `searching.md`](../02-daily-basics/searching.md).

### `view` — tri-pane (hex / disasm / pseudocode)

```bash
$ glaurung view tutorial.glaurung 0x1150 --binary $BIN \
    --hex-window 16 --pseudo-lines 5
```

```text
── hex @ 0x1150 ──
    0x1148  ff 0f 1f 80 00 00 00 00 55 48 89 e5 48 83 ec 20   |........UH..H.. | ←

── disasm @ 0x1150 ──
    0x1150  55                        push rbp ←
    0x1151  4889e5                    mov rbp, rsp
    0x1154  4883ec20                  sub rsp
    …

── pseudocode (enclosing function) ──
fn main {
    // x86-64 prologue: save rbp, frame 32 bytes
    local_0 = 0;
    local_1 = arg0;
    local_2 = arg1;
…
```

(Captured: [`_fixtures/01-cli-tour/view-main.out`](../_fixtures/01-cli-tour/view-main.out).)

### `xrefs` — every caller / callee

```bash
$ glaurung xrefs tutorial.glaurung 0x11d0 --binary $BIN --direction to
```

```text
dir   src_va       kind          function                         snippet
-------------------------------------------------------------------------
to    0x1150       call          main                             push rbp
to    0x117b       call          sub_117b                         mov rbp:[rbp - 0x18], 0x0
```

(Captured: [`_fixtures/01-cli-tour/xrefs-print-sum.out`](../_fixtures/01-cli-tour/xrefs-print-sum.out).)

Goes deep in [§F `cross-references.md`](../02-daily-basics/cross-references.md).

### `strings-xrefs` — strings panel

```bash
$ glaurung strings-xrefs tutorial.glaurung --binary $BIN --limit 5
```

```text
  offset  enc       len  uses  text  →  used_at
--------------------------------------------------------------------------------
     792  ascii      27     0  /lib64/ld-linux-x86-64.so.2
    1161  ascii      14     0  __cxa_finalize
    1176  ascii      17     0  __libc_start_main
    1194  ascii       6     0  strlen
    1201  ascii       6     0  printf
```

(Captured: [`_fixtures/01-cli-tour/strings-xrefs-head.out`](../_fixtures/01-cli-tour/strings-xrefs-head.out).)

Goes deep in [§H `strings-and-data.md`](../02-daily-basics/strings-and-data.md).

### `frame` — stack-frame editor

```bash
$ glaurung frame tutorial.glaurung 0x1150 list --binary $BIN
```

```text
  offset  name                      type                       size  uses  set_by
---------------------------------------------------------------------------------
-0x018  var_18                    (unknown)                           5  auto
-0x014  var_14                    (unknown)                     4     4  auto
-0x010  var_10                    (unknown)                     4     2  auto
-0x008  var_8                     (unknown)                     8     2  auto
-0x004  var_4                     (unknown)                     4     3  auto
```

(Captured: [`_fixtures/01-cli-tour/frame-list.out`](../_fixtures/01-cli-tour/frame-list.out).)

Goes deep in [§G `stack-frames.md`](../02-daily-basics/stack-frames.md).

## 4. Annotate

Writes back to the `.glaurung` file:

```bash
# Bookmarks + free-form journal.
$ glaurung bookmark tutorial.glaurung add 0x1140 \
    "weird branch — investigate" --binary $BIN
$ glaurung journal tutorial.glaurung add \
    "today: tracing parse_packet" --binary $BIN

# Most analyst writes happen from the REPL — see §D below.
$ glaurung repl $BIN --db tutorial.glaurung
```

Inside the REPL, single-key shortcuts (`n`, `y`, `c`, `x`, `d`,
`l`...) drive the workflow. See [§D `repl-tour.md`](repl-tour.md) and
[`reference/repl-keymap.md`](../reference/repl-keymap.md).

## 5. Patch

```bash
# NOP-out an instruction (size-preserving).
$ glaurung patch in.elf out.elf --va 0x1140 --nop --verify

# Force a conditional always-taken.
$ glaurung patch in.elf out.elf --va 0x1140 --force-branch true --verify
```

Goes deep in [§L `patch-and-verify.md`](../02-daily-basics/patch-and-verify.md).

## 6. Undo / redo

Reverse any analyst KB write:

```bash
$ glaurung undo tutorial.glaurung --list    # show history without mutating
```

```text
(undo log empty)
```

(Captured: [`_fixtures/01-cli-tour/undo-list.out`](../_fixtures/01-cli-tour/undo-list.out).)

Right after a fresh kickoff the log is empty — only `set_by=manual`
writes enter the log. Goes deep in [§K `undo-redo.md`](../02-daily-basics/undo-redo.md).

## 7. Diff and export

```bash
# Function-level diff (BinDiff-style).
$ glaurung diff old.elf new.elf

# Export the KB.
$ glaurung export tutorial.glaurung --output-format json     # round-trippable
$ glaurung export tutorial.glaurung --output-format markdown # human report
$ glaurung export tutorial.glaurung --output-format header   # C header
$ glaurung export tutorial.glaurung --output-format ida      # IDAPython script
$ glaurung export tutorial.glaurung --output-format binja    # Binary Ninja script
$ glaurung export tutorial.glaurung --output-format ghidra   # Ghidra script
```

The IDA / BinaryNinja / Ghidra scripts apply your renames, comments,
data labels, and types inside those tools — so Glaurung becomes the
fast-iterate engine and the polished tool gets the result. See
Tier 4 [§T `diffing-two-binaries.md`](../04-recipes/diffing-two-binaries.md)
and [§U `exporting-to-ida-ghidra.md`](../04-recipes/exporting-to-ida-ghidra.md).

## 8. Bytecode / managed runtimes

For non-native binaries, Glaurung has format-specific surfaces:

```bash
# JVM .class / .jar.
$ glaurung classfile samples/.../HelloWorld.class
$ glaurung classfile samples/.../HelloWorld.jar

# Lua bytecode.
$ glaurung luac samples/.../hello-lua5.3.luac

# .NET / Mono PE — no special command; kickoff handles it.
$ glaurung kickoff samples/.../Hello-mono.exe --db dotnet.glaurung
$ glaurung find dotnet.glaurung Main --kind function

# Stripped Go — also handled by kickoff.
$ glaurung kickoff samples/.../hello-go --db go.glaurung
$ glaurung find go.glaurung main. --kind function | head
```

Tier 3 covers each in depth.

## 9. Visualize

```bash
# DOT/GraphViz.
$ glaurung graph $BIN callgraph         | dot -Tsvg > callgraph.svg
$ glaurung graph $BIN cfg main          | dot -Tsvg > main-cfg.svg
```

## 10. Bench / regression

```bash
# Score the standard 10-binary CI matrix.
$ python -m glaurung.bench --ci-matrix --output baseline.json

# Score the UPX-packed corpus (regression coverage for #187).
$ python -m glaurung.bench --packed-matrix --output packed.json
```

See Tier 4 [§W `bench-harness-as-ci.md`](../04-recipes/bench-harness-as-ci.md).

## 11. Agent (optional, requires LLM credentials)

```bash
$ glaurung ask $BIN "what does this binary do?"
$ glaurung name-func $BIN 0x1140
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
