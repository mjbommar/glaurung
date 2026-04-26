# §B — Your first binary

Goal: load a binary, run the full first-touch pipeline, and end up
with a `.glaurung` project file that every subsequent command in
this tutorial reads from.

## Pick a binary

We'll use the simplest C program in the sample corpus:

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug
file $BIN
```

```
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=..., not stripped, with debug_info
```

This is a tiny `printf("Hello\n")`-style program built with clang at
`-O0 -g`. We picked it because:

- It has full DWARF debug info (all functions named, all types known).
- Its main is short enough to read in one screen.
- It's representative — most binaries you'll triage in real work
  share its structure.

## Run kickoff

```bash
glaurung kickoff $BIN --db tutorial.glaurung
```

Expected output:

```markdown
# Kickoff analysis — hello-clang-debug

- format: **ELF**, arch: **x86_64**, size: **92600** bytes
- entry: **0x11e0**

## Functions
- discovered: **16** (with blocks: 16, named: 16)
- callgraph edges: **10**
- name sources: analyzer=16

## Type system
- stdlib prototypes loaded: **192**
- DWARF types imported: **104**
- stack slots discovered: **492**
- types propagated: **0**
- auto-struct candidates: **16**

## IOCs (from string scan)
- **hostname**: 5
- **java_path**: 1
- **path_posix**: 1
- **ipv4**: 0

_completed in 470 ms_
```

## Read this aloud

Every line is information you'd otherwise have to chase by hand in
IDA / Ghidra. Top to bottom:

- **format / arch / size**: from the file header. Triage already
  knows we're looking at a 64-bit Linux ELF.
- **entry**: the address the loader will jump to (`_start`). Useful
  for "where do I begin?"
- **Functions discovered: 16, named: 16** — every function has a
  symbol-derived name (because `-g` is set). On a stripped binary,
  the named count would be much lower.
- **Type system**:
  - **stdlib prototypes loaded: 192** — `printf`, `malloc`, ~190
    other libc functions are now known to the type system. Glaurung
    will use them to type your stack vars when those functions are
    called (see Tier 4 §V `typed-locals-from-libc.md`).
  - **DWARF types imported: 104** — every struct, enum, and typedef
    the compiler emitted in debug info.
  - **stack slots discovered: 492** — analyzer-inferred local
    variables across all 16 functions.
  - **auto-struct candidates: 16** — heuristic `[reg+offset]` patterns
    that look like struct accesses (#163).
- **IOCs**: any indicators of compromise the string scanner found.
  This binary just has linker paths; on a real malware sample (Tier 3 §S)
  this section is where C2 URLs would land.
- **completed in 470 ms** — the whole pipeline is sub-second on
  small binaries. On a 10MB malware sample expect 2-5 seconds.

## What just happened

Under the hood, `kickoff` ran:

1. **detect-packer** — confirmed the binary isn't packed.
2. **triage** — format / arch / language identification.
3. **analyze-functions** — function discovery + callgraph construction.
4. **index-callgraph** — wrote functions and call edges to the
   `.glaurung` SQLite file.
5. **demangle** — every function name got its display form.
6. **per-function** — stack-slot discovery, type propagation
   (no-op here because there are no libc calls in the user code yet),
   and auto-struct candidates.

Total: ~470ms on this binary. **Every later command reads from the
same `tutorial.glaurung` file** — you don't re-run kickoff per
command.

## Inspect the project file

`tutorial.glaurung` is a SQLite file. You can open it directly:

```bash
sqlite3 tutorial.glaurung "SELECT * FROM function_names LIMIT 5"
```

```
1|4576|frame_dummy|[]|analyzer|...
1|4400|deregister_tm_clones|[]|analyzer|...
1|4304|main|[]|analyzer|...
...
```

Tables include `function_names`, `comments`, `data_labels`,
`stack_frame_vars`, `xrefs`, `types`, `function_prototypes`,
`bookmarks`, `journal`, `evidence_log`, and `undo_log`. Every CLI
surface we'll cover writes to one of these.

## Try a couple of CLI surfaces against the project

We'll go deep on each in Tiers 2-3, but try these now to confirm
your install works end-to-end:

```bash
# What's at the entry point?
glaurung view tutorial.glaurung 0x11e0 \
  --binary $BIN --hex-window 32 --pseudo-lines 6
```

```
── hex @ 0x11e0 ──
    0x11d0  55 48 89 e5 e8 c7 ff ff ff 5d c3 0f 1f 44 00 00   |UH.......]...D..|
    0x11e0  f3 0f 1e fa 31 ed 49 89 d1 5e 48 89 e2 48 83 e4   |....1.I..^H..H..| ←

── disasm @ 0x11e0 ──
    0x11e0  f30f1efa                  Endbr64  ←
    0x11e4  31ed                      xor ebp, ebp
    0x11e6  4989d1                    mov r9, rdx
    0x11e9  5e                        pop rsi
    ...

── pseudocode (enclosing function) ──
fn _start {
    nop;
    arg5 = arg2;
    pop(arg1);
    arg2 = rsp;
    rsp = (rsp & 240);
```

Three synchronized panels: hex bytes, disassembly, decompiled
pseudocode. The `←` markers point at the row containing your
target VA. We'll go deep on this command in [§F](../02-daily-basics/cross-references.md)
and [§H](../02-daily-basics/strings-and-data.md).

```bash
# What strings does it have? (cheap version — no DB needed)
glaurung strings $BIN | head -10
```

```bash
# Find every function in the KB.
glaurung find tutorial.glaurung main --kind function
```

```
kind        location        snippet
----------  --------------  ----------------------------
function    0x10d0          main  (set_by=analyzer)
```

(That `set_by=analyzer` tag is the provenance — see
[`reference/set-by-precedence.md`](../reference/set-by-precedence.md).)

## What's next

Pick one:

- [**§C `cli-tour.md`**](cli-tour.md) — quick survey of all 27
  shipped CLI subcommands so you know what's where.
- [**§D `repl-tour.md`**](repl-tour.md) — the interactive REPL with
  cursor-based navigation and one-keystroke annotation.
- [**Tier 2: Daily basics**](../02-daily-basics/) — go straight to
  the keystroke loops if you're impatient.
- [**Tier 3 §M `01-hello-c-clang.md`**](../03-walkthroughs/01-hello-c-clang.md) —
  full kickoff → annotate walkthrough on this same binary.

→ [§C `cli-tour.md`](cli-tour.md)
