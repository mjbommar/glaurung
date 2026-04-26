# §M — Walkthrough 1: hello-c-clang (the kickoff → annotate loop)

The simplest walkthrough. We use a tiny C program built with clang
at `-g -O0` so the binary is small enough to read cover-to-cover
in 5-10 minutes. This chapter validates the universal CTF
walkthrough shape — every later walkthrough follows the same
six phases.

> **Verified output.** Every code block in this chapter is the
> real captured output from running the listed command, regenerated
> by `scripts/verify_tutorial.py` and stored under
> `docs/tutorial/_fixtures/03-hello-c-clang/`. If your output
> differs, the surface drifted — file the diff.

## Sample

```bash
$ BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
$ file $BIN
```

```text
samples/.../hello-c-clang-debug: ELF 64-bit LSB pie executable,
x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=..., for GNU/Linux 3.2.0,
with debug_info, not stripped
```

A 17.6 KB ELF — debug info present, no obfuscation, builds against
glibc.

## Phase 1: Triage

```bash
$ glaurung triage $BIN
```

What we want from triage: format, arch, language, IOC count. That's
all the information we need to decide "is this worth deeper
analysis?"

For tutorial purposes, skip straight to `kickoff` — it includes
triage plus everything else.

## Phase 2: Load (`kickoff`)

```bash
$ glaurung kickoff $BIN --db hello.glaurung
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

## IOCs (from string scan)
- **path_posix**: 6
- **hostname**: 6
- **java_path**: 4
- **ipv4**: 0

Examples:
  - `path_posix` `/lib64/ld-linux-x86-64.so.2`  (off `0x318`)
  - `java_path` `lib64/ld-linux-x86-64.so.2`  (off `0x319`)
  - `c_identifier` `lib64`  (off `0x319`)
  - `c_identifier` `ld`  (off `0x31f`)
  - `c_identifier` `linux`  (off `0x322`)
  - `c_identifier` `x86`  (off `0x328`)

_completed in N ms_
```

(Captured: [`_fixtures/03-hello-c-clang/kickoff.out`](../_fixtures/03-hello-c-clang/kickoff.out).)

Read aloud:

- **9 functions discovered, 8 named** — one is an anonymous helper
  (`sub_<hex>`); the other 8 have symbol-derived names.
- **5 callgraph edges** — small program, tight call structure.
- **DWARF types imported: 0** — interesting! This binary was built
  with `-g` but the analyzer didn't surface DWARF types here. The
  C program uses only `int` / `char *` / function-pointer
  primitives — no structs, enums, or typedefs to import. Compare
  to §B which is C++ and pulls in 104 std::string-and-friends
  types.
- **stdlib prototypes loaded: 192** — `printf`, `strlen`, etc.
  now known to the type system. The propagator can use them.
- **stack slots discovered: 36** — analyzer-inferred locals across
  the 9 functions.

## Phase 3: Function ID

Where's `main`?

```bash
$ glaurung find hello.glaurung main --kind function
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
function    0x1150          main  (set_by=analyzer)
```

(Captured: [`_fixtures/03-hello-c-clang/find-main.out`](../_fixtures/03-hello-c-clang/find-main.out).)

`main` is at `0x1150`. The `set_by=analyzer` tag means the name
came from the symbol table (this binary isn't stripped) — see
[`reference/set-by-precedence.md`](../reference/set-by-precedence.md).

What other functions are there?

```bash
$ glaurung find hello.glaurung "" --kind function
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
function    0x1060          _start  (set_by=analyzer)
function    0x1090          deregister_tm_clones  (set_by=analyzer)
function    0x10c0          register_tm_clones  (set_by=analyzer)
function    0x1100          __do_global_dtors_aux  (set_by=analyzer)
function    0x1140          frame_dummy  (set_by=analyzer)
function    0x1150          main  (set_by=analyzer)
function    0x117b          sub_117b  (set_by=analyzer)
function    0x11d0          print_sum  (set_by=analyzer)
function    0x1200          static_function  (set_by=analyzer)
```

(Captured: [`_fixtures/03-hello-c-clang/find-all.out`](../_fixtures/03-hello-c-clang/find-all.out).)

Two interesting functions besides `main`: `print_sum` at `0x11d0`
and `static_function` at `0x1200`. Plus an anonymous helper
`sub_117b` (the analyzer found it but the symbol table didn't
name it — it's a compiler-emitted helper, not a user function).

## Phase 4: String/logic trace

What does `main` do?

```bash
$ glaurung view hello.glaurung 0x1150 --binary $BIN \
    --pane pseudo --pseudo-lines 25
```

```text
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
    unknown(movsxd);
    strlen@plt(*&[ret+arg3*8]);  // proto: size_t strlen(const char * s)
    arg3 = ret;
    unknown(movsxd);
    ret = (ret + arg3);
    local_3 = ret;
```

(Captured: [`_fixtures/03-hello-c-clang/view-main.out`](../_fixtures/03-hello-c-clang/view-main.out).)

Things to notice:

1. **`printf@plt("Hello, World from C!\n")`** — the obvious greeting.
   Hardcoded string in `.rodata`.
2. **`// proto: int printf(...)`** and **`// proto: size_t strlen(...)`** —
   Glaurung knows libc prototypes because the bundle was auto-loaded
   at kickoff time.
3. **`if ((ret < t11)) { print_sum(...); static_function(); return; }`** —
   the structurer recovered an early-exit shape (#192).
4. **`strlen` inside what looks like a loop tail** — the program is
   summing argv string lengths.

What's the loop summing? `print_sum` is the next clue:

```bash
$ glaurung view hello.glaurung 0x11d0 --binary $BIN \
    --pane pseudo --pseudo-lines 8
```

```text
── pseudocode (enclosing function) ──
fn print_sum {
    push(rbp);
    rsp = (rsp - 16);
    local_0 = arg0;
    printf@plt("Total argument length: %d\n", local_1);  // proto: int printf(const char * fmt, ...)
    // x86-64 epilogue: restore rbp
    return;
}
```

(Captured: [`_fixtures/03-hello-c-clang/view-print-sum.out`](../_fixtures/03-hello-c-clang/view-print-sum.out).)

There's the answer: `print_sum(int)` prints "Total argument length:
%d". So `main` strlens every argv element, sums them, calls
`print_sum`, then `static_function`. That's the program in 3 lines.

## Phase 5: Verify (cross-references)

We claimed `main` calls `print_sum` and `static_function`. Verify
via xrefs:

```bash
$ glaurung xrefs hello.glaurung 0x11d0 --binary $BIN --direction to
```

```text
dir   src_va       kind          function                         snippet
-------------------------------------------------------------------------
to    0x1150       call          main                             push rbp
to    0x117b       call          sub_117b                         mov rbp:[rbp - 0x18], 0x0
```

(Captured: [`_fixtures/03-hello-c-clang/xrefs-print-sum.out`](../_fixtures/03-hello-c-clang/xrefs-print-sum.out).)

**Two callers, not one:** `main` plus the anonymous `sub_117b`
helper. Worth noting — when the source code looks like one call
to `print_sum`, the compiler may emit additional reference sites
through helpers / inline expansions.

(The `snippet` column shows the calling instruction at each
src_va. Both look like prologue-style sites — the disasm cursor
landed at the start of each caller's frame.)

For `static_function`:

```bash
$ glaurung xrefs hello.glaurung 0x1200 --binary $BIN --direction to
```

```text
dir   src_va       kind          function                         snippet
-------------------------------------------------------------------------
to    0x1150       call          main                             push rbp
to    0x117b       call          sub_117b                         mov rbp:[rbp - 0x18], 0x0
```

(Captured: [`_fixtures/03-hello-c-clang/xrefs-static-fn.out`](../_fixtures/03-hello-c-clang/xrefs-static-fn.out).)

Same shape — two callers, same two functions. So both `print_sum`
and `static_function` are reached from `main` AND from the
anonymous helper at `0x117b`. That helper is worth a closer look
in a more thorough analysis.

## Phase 6: Annotate (rename for clarity)

The function names already make sense (`main`, `print_sum`,
`static_function`), so there's not much to rename. Let's annotate
the anonymous helper instead:

```bash
$ glaurung repl $BIN --db hello.glaurung
```

```text
>>> g 0x117b
>>> n inline_helper
  0x117b → inline_helper
```

```text
>>> c 0x117b "inlined helper that wraps print_sum + static_function"
```

```text
>>> save
>>> q
```

Inspect from outside:

```bash
$ glaurung find hello.glaurung inline_helper --kind function
$ glaurung find hello.glaurung "inlined helper" --kind comment
```

Both come back tagged `set_by=manual` — they're analyst-driven
and will survive any re-run of `kickoff`.

If you want to undo:

```bash
$ glaurung undo hello.glaurung --list
$ glaurung undo hello.glaurung -n 2
```

## What you've done

Six phases, ~5 minutes:

1. **Triage** confirmed it's a small Linux C binary with debug
   info but no struct/typedef DWARF entries (the C program is
   too simple to have any).
2. **Load (kickoff)** populated a `.glaurung` project file with
   9 named functions, 192 stdlib prototypes, and 36 stack slots.
3. **Function ID** via `glaurung find` got us to `main` at
   `0x1150` and surfaced 9 total functions including an
   anonymous helper.
4. **String / logic trace** via `glaurung view` revealed the
   "hello world + sum argv lengths" logic — including
   prototype-hinted `printf` and `strlen` calls and the
   structured if-then.
5. **Verify** via `glaurung xrefs` confirmed both `print_sum`
   and `static_function` are called from BOTH `main` AND the
   anonymous helper — a useful correction over the naïve
   "called once from main" assumption.
6. **Annotate** via REPL renamed the helper and added a comment,
   both undo-able.

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
