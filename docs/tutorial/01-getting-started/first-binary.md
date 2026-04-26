# §B — Your first binary

Goal: load a binary, run the full first-touch pipeline, and end up
with a `.glaurung` project file every later command reads from.

> **Verified output.** Every `$ ` block in this chapter is a real
> captured session against the binary at the listed path, regenerated
> by `scripts/verify_tutorial.py` and stored under
> `docs/tutorial/_fixtures/01-first-binary/`. If your output differs,
> the surface drifted — file the diff.

## Pick a binary

```bash
$ BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug
$ file $BIN
```

```text
samples/.../hello-clang-debug: ELF 64-bit LSB pie executable, x86-64,
version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=..., for GNU/Linux 3.2.0,
with debug_info, not stripped
```

(Captured: [`_fixtures/01-first-binary/file.out`](../_fixtures/01-first-binary/file.out).)

This is a tiny **C++** program built with clang at `-O0 -g`. The
"clang-debug" name is the canonical first-binary in this tutorial
because it has full DWARF info and its `main` is short enough to
read in one screen.

## Run kickoff

```bash
$ glaurung kickoff $BIN --db tutorial.glaurung
```

Real captured output:

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
- **path_posix**: 1
- **java_path**: 1
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

(Captured: [`_fixtures/01-first-binary/kickoff.out`](../_fixtures/01-first-binary/kickoff.out).)

## Read this aloud

Every line is information you'd otherwise have to chase by hand in
IDA / Ghidra:

- **format / arch / size** — from the file header.
- **entry: 0x11e0** — `_start`. Useful for "where do I begin?"
- **discovered: 16 (named: 16)** — every function got a name (the
  binary isn't stripped). On a stripped binary the named count
  would be much lower.
- **DWARF types imported: 104** — every struct / enum / typedef
  the compiler emitted. (This is a big number because the binary
  is C++ and pulls in std::string and friends.)
- **stack slots discovered: 492** — analyzer-inferred locals
  across all 16 functions.
- **auto-struct candidates: 16** — heuristic struct-shaped accesses
  the auto-struct pass (#163) flagged.
- **IOCs** — what triage's string scanner classified. On this
  binary just linker paths; on the malware analog in §S the same
  block surfaces real C2 URLs.

## Inspect the project file directly

The `.glaurung` file is a SQLite database — read it with `sqlite3`
or any other SQLite client:

```bash
$ sqlite3 tutorial.glaurung -cmd ".mode column" \
    "SELECT printf('%#x', entry_va) AS entry_va, canonical, set_by
     FROM function_names ORDER BY entry_va LIMIT 5;"
```

Real captured output:

```text
entry_va  canonical                 set_by
--------  ------------------------  --------
0x11a0    __cxx_global_var_init     analyzer
0x11d0    _GLOBAL__sub_I_hello.cpp  analyzer
0x11e0    _start                    analyzer
0x1210    deregister_tm_clones      analyzer
0x1240    register_tm_clones        analyzer
```

(Captured: [`_fixtures/01-first-binary/sqlite-fnames.out`](../_fixtures/01-first-binary/sqlite-fnames.out).)

Notice `__cxx_global_var_init` and `_GLOBAL__sub_I_hello.cpp` —
these are C++-specific runtime stubs the compiler injected to
initialize globals before `main`. The original source is
`hello.cpp`.

Tables include `function_names`, `comments`, `data_labels`,
`stack_frame_vars`, `xrefs`, `types`, `function_prototypes`,
`bookmarks`, `journal`, `evidence_log`, and `undo_log`. Every CLI
surface we'll cover writes to one of these.

## Try a few CLI surfaces

We'll go deep on each in Tiers 2-3, but try these now to confirm
your install works end-to-end:

### `glaurung view` — synchronized hex / disasm / pseudocode

```bash
$ glaurung view tutorial.glaurung 0x11e0 \
    --binary $BIN --hex-window 32 --pseudo-lines 6
```

Real captured output:

```text
── hex @ 0x11e0 ──
    0x11d0  55 48 89 e5 e8 c7 ff ff ff 5d c3 0f 1f 44 00 00   |UH.......]...D..|
    0x11e0  f3 0f 1e fa 31 ed 49 89 d1 5e 48 89 e2 48 83 e4   |....1.I..^H..H..| ←

── disasm @ 0x11e0 ──
    0x11e0  f30f1efa                  Endbr64  ←
    0x11e4  31ed                      xor ebp, ebp
    0x11e6  4989d1                    mov r9, rdx
    0x11e9  5e                        pop rsi
    0x11ea  4889e2                    mov rdx, rsp
    0x11ed  4883e4f0                  and rsp
    0x11f1  50                        push rax
    0x11f2  54                        push rsp
    0x11f3  4531c0                    xor r8d, r8d
    0x11f6  31c9                      xor ecx, ecx
    0x11f8  488d3dd1000000            lea rdi, rip:[rip + 0x12d0]
    0x11ff  ff15cb4d0000              call rip:[rip + 0x5fd0]

── pseudocode (enclosing function) ──
fn _start {
    nop;
    arg5 = arg2;
    pop(arg1);
    arg2 = rsp;
    rsp = (rsp & 240);
```

(Captured: [`_fixtures/01-first-binary/view.out`](../_fixtures/01-first-binary/view.out).)

Three synchronized panels:

- **hex** — raw bytes, with `←` marking the row containing `0x11e0`.
- **disasm** — instructions starting at `0x11e0`. The first row
  (`Endbr64`) is the entry point.
- **pseudocode** — the enclosing function (`_start`).

The lea at 0x11f8 loads `rip + 0x12d0` (which is `main`'s VA — see
the next subsection) into rdi. That's `__libc_start_main`'s first
arg: a function pointer to `main`. Standard CRT bootstrap.

### `glaurung find` — locate `main`

```bash
$ glaurung find tutorial.glaurung main --kind function
```

Real captured output:

```text
kind        location        snippet
--------------------------------------------------------------------------------
function    0x12d0          main  (set_by=analyzer)
```

(Captured: [`_fixtures/01-first-binary/find-main.out`](../_fixtures/01-first-binary/find-main.out).)

`main` is at `0x12d0` — matching the lea target in `_start`.
`set_by=analyzer` means the name came from the binary's symbol
table (the binary isn't stripped). See
[`reference/set-by-precedence.md`](../reference/set-by-precedence.md).

## What's next

Pick one:

- [**§C `cli-tour.md`**](cli-tour.md) — quick survey of all 27
  shipped CLI subcommands so you know what's where.
- [**§D `repl-tour.md`**](repl-tour.md) — the interactive REPL.
- [**Tier 2: Daily basics**](../02-daily-basics/) — go straight
  to the keystroke loops if you're impatient.
- [**Tier 3 §M `01-hello-c-clang.md`**](../03-walkthroughs/01-hello-c-clang.md) —
  full kickoff → annotate walkthrough on the C-only sibling
  binary `hello-c-clang-debug`.

→ [§C `cli-tour.md`](cli-tour.md)
