# §M — Walkthrough 1: hello-c-clang (the kickoff → annotate loop)

The simplest walkthrough. We use a tiny C program built with clang
at `-g -O0` so the binary is small enough to read cover-to-cover
in 5-10 minutes. This chapter validates the universal CTF
walkthrough shape — every later walkthrough follows the same six
phases.

## Sample

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
file $BIN
```

```
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, ..., with debug_info, not stripped
```

A 17.6 KB ELF — debug info present, no obfuscation, builds against
glibc.

## Phase 1: Triage

```bash
glaurung triage $BIN
```

What we want from triage: format, arch, language, IOC count. That's
all the information we need to decide "is this worth deeper
analysis?"

For tutorial purposes, skip straight to `kickoff` — it includes
triage plus everything else.

## Phase 2: Load (`kickoff`)

```bash
glaurung kickoff $BIN --db hello.glaurung
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
- auto-struct candidates: **0**

_completed in ~200 ms_
```

Read aloud:

- 9 functions discovered, 8 named (the 9th is a `sub_<hex>` placeholder
  for an analysis stub).
- 5 callgraph edges — small program; tight call structure.
- 192 stdlib prototypes auto-loaded — `printf`, `strlen`, etc. now
  known to the type system.

## Phase 3: Function ID

Where's `main`?

```bash
glaurung find hello.glaurung main --kind function
```

```
function    0x1150          main  (set_by=analyzer)
```

Found it at `0x1150`. The `set_by=analyzer` tag means the name came
from the symbol table (this binary isn't stripped) — see
[`reference/set-by-precedence.md`](../reference/set-by-precedence.md).

What other functions are there?

```bash
glaurung find hello.glaurung "" --kind function | head
```

```
function    0x1030          ?  (set_by=analyzer)
function    0x1060          ?  (set_by=analyzer)
function    0x10d0          frame_dummy  (set_by=analyzer)
function    0x1110          register_tm_clones  (set_by=analyzer)
function    0x1150          main  (set_by=analyzer)
function    0x11d0          print_sum  (set_by=analyzer)
function    0x1210          static_function  (set_by=analyzer)
...
```

Two interesting functions besides `main`: `print_sum` and
`static_function`.

## Phase 4: String/logic trace

What does `main` do?

```bash
glaurung view hello.glaurung 0x1150 --binary $BIN --pane pseudo --pseudo-lines 25
```

```
── pseudocode (enclosing function) ──
fn main {
    // x86-64 prologue: save rbp, frame 32 bytes
    local_0 = 0;
    local_1 = arg0;
    local_2 = arg1;
    printf@plt("Hello, World from C!\n");  // proto: int printf(const char * fmt, ...)
    local_3 = 0;
    local_4 = 0;
    ret = local_5;
    t11 = local_6;
    if ((ret < t11)) {
        print_sum(local_7);
        static_function();
        ret = 0;
        rsp = (rsp + 32);
        pop(rbp);
        return;
    }
    ret = local_2;
    ...
    strlen@plt(*&[ret+arg3*8]);  // proto: size_t strlen(const char * s)
    ...
}
```

Two things to notice:

1. **`printf@plt("Hello, World from C!\n")`** — this is the obvious
   greeting. Hardcoded string in `.rodata`.
2. **`// proto: int printf(const char * fmt, ...)`** — Glaurung
   knows printf's prototype because the libc bundle was auto-loaded
   at kickoff time. The same comment on `strlen` confirms the
   loop body strlens its argv.
3. **`if ((ret < t11)) { print_sum(...); static_function(); ... }`** —
   the structurer recovered an early-exit shape (#192).
4. **`strlen` inside what looks like a loop tail** — the program is
   summing argv string lengths.

What's the loop summing? `print_sum` is the next clue:

```bash
glaurung view hello.glaurung 0x11d0 --binary $BIN --pane pseudo --pseudo-lines 8
```

```
fn print_sum {
    push(rbp);
    rsp = (rsp - 16);
    local_0 = arg0;
    printf@plt("Total argument length: %d\n", local_1);
    // x86-64 epilogue: restore rbp
    return;
}
```

There's the answer: `print_sum(int)` prints "Total argument length: %d".
So `main` strlens every argv element, sums them, calls `print_sum`,
then `static_function`. That's the program in 3 lines.

## Phase 5: Verify (cross-references)

We claimed `main` calls `print_sum` and `static_function`. Verify
via xrefs:

```bash
glaurung xrefs hello.glaurung 0x11d0 --binary $BIN --direction to
```

```
dir   src_va   kind   function   snippet
to    0x118a   call   main       call rip:[rip + ...]
```

`print_sum` has exactly one caller — `main` at 0x118a. ✓

Same for `static_function`:

```bash
glaurung xrefs hello.glaurung 0x1210 --binary $BIN --direction to
```

```
dir   src_va   kind   function   snippet
to    0x118f   call   main       call rip:[rip + ...]
```

Also called once from `main`. ✓ The picture matches the body.

## Phase 6: Annotate (rename for clarity)

The function names already make sense (`main`, `print_sum`,
`static_function`), so there's not much to rename. Let's annotate
the loop instead.

Open the REPL:

```bash
glaurung repl $BIN --db hello.glaurung
```

```
>>> g 0x1150
>>> l            # see the stack slots
  4 vars in fn@0x1150:
    -0x18  argc       (uses=1, by=auto)
    -0x10  argv       (uses=1, by=auto)
    -0x08  saved_rbp  (uses=0, by=auto)
    +0x10  ret        (uses=0, by=auto)

>>> locals rename -0x18 my_argc
  renamed -0x018 -> my_argc

>>> c 0x1186 sum the lengths of all argv strings
  0x1186: sum the lengths of all argv strings

>>> save
>>> q
```

Inspect from outside:

```bash
glaurung find hello.glaurung my_argc --kind stack_var
glaurung find hello.glaurung "sum the lengths" --kind comment
```

Both come back tagged `set_by=manual` — they're analyst-driven and
will survive any re-run of `kickoff`.

If you want to undo:

```bash
glaurung undo hello.glaurung --list
glaurung undo hello.glaurung -n 2
```

## What you've done

Six phases, ~5 minutes:

1. **Triage** confirmed it's a small Linux C binary.
2. **Load (kickoff)** populated a `.glaurung` project file with
   the analysis state.
3. **Function ID** via `glaurung find` got us to `main`.
4. **String / logic trace** via `glaurung view` revealed the
   "hello world + sum argv lengths" logic — including a
   prototype-hinted `printf` and the structured if-then.
5. **Verify** via `glaurung xrefs` confirmed `print_sum` and
   `static_function` each have exactly one caller (`main`),
   matching what the body suggested.
6. **Annotate** via REPL renamed a stack slot and added a
   comment, both undo-able.

This is the full template. Every later walkthrough follows the
same six phases — the difference is the binary's complexity and
the format-specific recoveries Glaurung does along the way.

## What's next

The binary ladder climbs from here:

- [§N `02-stripped-go-binary.md`](02-stripped-go-binary.md) —
  what does the same loop look like on a stripped Go binary?
  (Spoiler: `gopclntab` recovers all the names anyway.)
- [§O `03-managed-dotnet-pe.md`](03-managed-dotnet-pe.md) —
  managed .NET PE; CIL metadata parser.
- [§P `04-jvm-classfile.md`](04-jvm-classfile.md) — JVM bytecode.
- [§Q `05-vulnerable-parser.md`](05-vulnerable-parser.md) — CTF-shape
  vulnerability hunt on a real buffer-overflow target.
- [§R `06-upx-packed-binary.md`](06-upx-packed-binary.md) — UPX-
  packed; detect → punt → re-analyze.
- [§S `07-malware-c2-demo.md`](07-malware-c2-demo.md) — the flagship
  malware-triage demo with IOC scanning, stack-frame retype, and
  the agent.

→ [§N `02-stripped-go-binary.md`](02-stripped-go-binary.md)
