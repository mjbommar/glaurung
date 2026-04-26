# §E — Naming and types (`n` / `y` / `c`)

The first keystroke loop. Every analyst's day is mostly: rename
something → look at its body → comment something → rename a
related thing. This chapter shows the muscle-memory shape, plus
why renames are safe (#228 undo) and how renames flow to callers
(#220 auto-rerender).

> **Verified output.** Every transcript is captured by
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/02-naming-and-types/`](../_fixtures/02-naming-and-types/).
> The REPL was driven by piping each block's keystrokes through
> stdin — no synthesized snippets.

## Setup

```bash
$ BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
$ glaurung kickoff $BIN --db demo.glaurung
```

```text
# Kickoff analysis — c2_demo-clang-O0

- format: **ELF**, arch: **x86_64**, size: **16456** bytes
- entry: **0x1070**

## Functions
- discovered: **6** (with blocks: 6, named: 6)
- callgraph edges: **1**
- name sources: analyzer=6

## Type system
- stdlib prototypes loaded: **192**
- DWARF types imported: **0**
- stack slots discovered: **90**
- types propagated: **18**
- auto-struct candidates: **0**

## IOCs (from string scan)
- **path_posix**: 11
- **java_path**: 10
- **hostname**: 10
- **ipv4**: 4
- **domain**: 3
- **url**: 2
- **email**: 1
```

(Captured: [`_fixtures/02-naming-and-types/kickoff.out`](../_fixtures/02-naming-and-types/kickoff.out).)

We use `c2_demo` instead of `hello-c-clang-debug` because it has
something interesting to rename — hardcoded URLs, a global C2
endpoint table, and 18 types already propagated from libc
prototypes.

## Confirm the candidate function

```text
─── stdin (keystrokes piped to glaurung repl) ───
functions
q
─── glaurung repl stdout ───
>   6 functions, showing first 20:
    0x1070  _start  (set_by=analyzer)
    0x10a0  deregister_tm_clones  (set_by=analyzer)
    0x10d0  register_tm_clones  (set_by=analyzer)
    0x1110  __do_global_dtors_aux  (set_by=analyzer)
    0x1150  frame_dummy  (set_by=analyzer)
    0x1160  main  (set_by=analyzer)
>
saving and exiting…
```

(Captured: [`_fixtures/02-naming-and-types/repl-functions.out`](../_fixtures/02-naming-and-types/repl-functions.out).)

`main` is at `0x1160` — the only user-defined function in this
ultra-small binary.

## Rename a function (`n` at cursor)

```text
─── stdin (keystrokes piped to glaurung repl) ───
g 0x1160
n c2_main
save
q
─── glaurung repl stdout ───
>   0x1160  main  (set_by=analyzer)
0x1160>   0x1160 → c2_main
  ── c2_main (post-rename) ──
    fn main {
        // ── locals (from KB) ─────────────────────────────────
        void *var_1b0;  // -0x1b0  set_by=propagated
        void *var_140;  // -0x140  set_by=propagated
        char *var_110;  // -0x110  set_by=propagated
    ... (38 more lines)
0x1160> saved.
0x1160>
saving and exiting…
```

(Captured: [`_fixtures/02-naming-and-types/repl-rename.out`](../_fixtures/02-naming-and-types/repl-rename.out).)

The auto-rerender shows the renamed function's body. Note:

- The rename shows `0x1160 → c2_main` and re-prints the function
  immediately so you can confirm the change took.
- The render also surfaces a "locals (from KB)" block showing
  three propagated types (#172 / #195) — `var_1b0`, `var_140`,
  `var_110` — already typed from libc call-site argument matching.
- Renames flow into other functions' bodies on their next render
  — any caller of `0x1160` will now show `c2_main(...)` (#220).

## Provenance: `set_by`

Verify from outside the REPL:

```bash
$ glaurung find demo.glaurung c2_main --kind function
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
function    0x1160          c2_main  (set_by=manual)
```

(Captured: [`_fixtures/02-naming-and-types/find-renamed.out`](../_fixtures/02-naming-and-types/find-renamed.out).)

`set_by=manual` is the highest tier. **No analyzer pass can clobber
this** — re-running `kickoff` won't revert it. See
[`reference/set-by-precedence.md`](../reference/set-by-precedence.md).

## Add a comment (`c <addr> <text>`)

```text
─── stdin (keystrokes piped to glaurung repl) ───
c 0x1160 entry: stash argc/argv into locals
save
q
─── glaurung repl stdout ───
>   0x1160: entry: stash argc/argv into locals
> saved.
>
saving and exiting…
```

(Captured: [`_fixtures/02-naming-and-types/repl-comment.out`](../_fixtures/02-naming-and-types/repl-comment.out).)

The `c` shorthand requires an explicit VA — the REPL does **not**
default to the cursor for comments (different from `n` which does
use the cursor).

Verify:

```bash
$ glaurung find demo.glaurung "stash argc" --kind comment
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
comment     0x1160          entry: stash argc/argv into locals
```

(Captured: [`_fixtures/02-naming-and-types/find-comment.out`](../_fixtures/02-naming-and-types/find-comment.out).)

## Define a data label (`label set <addr> <name> [<type>]`)

The c2_demo has a global C2-endpoint table at `0x4040`. Label it:

```text
─── stdin (keystrokes piped to glaurung repl) ───
label set 0x4040 g_c2_endpoints char *
save
q
─── glaurung repl stdout ───
>   labelled 0x00004040 -> g_c2_endpoints
> saved.
>
saving and exiting…
```

(Captured: [`_fixtures/02-naming-and-types/repl-label-set.out`](../_fixtures/02-naming-and-types/repl-label-set.out).)

Note the syntax: `label set <addr> <name> <type-tokens-joined-with-spaces>`.
The c-type is everything after the name, so `char *` becomes the
type without quoting.

## Retype a data label (`y <addr> <c-type>`)

`y` retypes an existing label — it will **not** create one. The
two-step `label set` then `y` matches Ghidra's "create then retype"
flow:

```text
─── stdin (keystrokes piped to glaurung repl) ───
y 0x4040 char[64]
save
q
─── glaurung repl stdout ───
>   0x4040 g_c2_endpoints: char[64]
> saved.
>
saving and exiting…
```

(Captured: [`_fixtures/02-naming-and-types/repl-retype.out`](../_fixtures/02-naming-and-types/repl-retype.out).)

Both writes are `set_by=manual`. Verify:

```bash
$ glaurung find demo.glaurung g_c2_endpoints --kind data
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
data        0x4040          g_c2_endpoints: char[64]
```

(Captured: [`_fixtures/02-naming-and-types/find-label.out`](../_fixtures/02-naming-and-types/find-label.out).)

## Stack-var rename (`locals rename`)

`l` (locals) shows the slots in the cursor's enclosing function.
Pick a propagated `void *` slot and give it a meaningful name:

```text
─── stdin (keystrokes piped to glaurung repl) ───
g 0x1160
l
locals rename -0x1b0 url_buffer
save
q
─── glaurung repl stdout ───
>   0x1160  c2_main  (set_by=manual)
0x1160>   15 vars in fn@0x1160:
    -0x1b0  var_1b0: void *  (uses=2, by=propagated)
    -0x180  var_180  (uses=2, by=auto)
    -0x178  var_178  (uses=1, by=auto)
    -0x170  var_170  (uses=1, by=auto)
    -0x168  var_168  (uses=1, by=auto)
    -0x164  var_164  (uses=1, by=auto)
    -0x160  var_160  (uses=1, by=auto)
    -0x158  var_158  (uses=1, by=auto)
    -0x150  var_150  (uses=1, by=auto)
    -0x148  var_148  (uses=1, by=auto)
    -0x140  var_140: void *  (uses=1, by=propagated)
    -0x110  var_110: char *  (uses=2, by=propagated)
    -0x010  var_10  (uses=1, by=auto)
    -0x008  var_8  (uses=1, by=auto)
    -0x004  var_4  (uses=1, by=auto)
0x1160>   renamed -0x1b0 -> url_buffer
0x1160> saved.
0x1160>
saving and exiting…
```

(Captured: [`_fixtures/02-naming-and-types/repl-locals-rename.out`](../_fixtures/02-naming-and-types/repl-locals-rename.out).)

Note the `set_by` column: most slots are `auto` (the analyzer
discovered them), but three are `propagated` — the type
propagator (#172 / #195) walked the libc prototype graph and
wrote `void *` / `char *` types based on call-site arg matching.

## Re-decompile to confirm renames flowed through

```text
─── stdin (keystrokes piped to glaurung repl) ───
g 0x1160
d
q
─── glaurung repl stdout ───
>   0x1160  c2_main  (set_by=manual)
0x1160>   fn main {
      // ── locals (from KB) ─────────────────────────────────
      // -0x1b0  url_buffer  (unknown type, set_by=manual)
      void *var_140;  // -0x140  set_by=propagated
      char *var_110;  // -0x110  set_by=propagated
      // ─────────────────────────────────────────────────

      // x86-64 prologue: save rbp, frame 432 bytes
      local_0 = 0;
      local_1 = arg0;
      local_2 = arg1;
      printf@plt("Connecting to C2 server...\n");  // proto: int printf(const char * fmt, ...)
      snprintf@plt(&var_110, 256, "http://%s:8080%s", *&[var0+0x4050], *&[var0+0x4070]);
      memcpy@plt(&var_140, "https://10.10.10.10:443/malware/update", 39);
      ret = *&[var0+0x2150];
      local_3 = ret;
      ret = *&[var0+0x2158];
      local_4 = ret;
      ret = *&[var0+0x2160];
      local_5 = ret;
      ret = *&[var0+0x2168];
      local_6 = ret;
      printf@plt("Primary: %s\n", *&[var0+0x4040]);  // proto: int printf(const char * fmt, ...)
      printf@plt("Backup: %s\n", *&[var0+0x4048]);  // proto: int printf(const char * fmt, ...)
      printf@plt("Domain: %s\n", *&[var0+0x4050]);  // proto: int printf(const char * fmt, ...)
      printf@plt("URL: %s\n", &var_110);  // proto: int printf(const char * fmt, ...)
      ret = *&[var0+0x2170];
      local_7 = ret;
      ret = *&[var0+0x2178];
      local_8 = ret;
      ret = *&[var0+0x2180];
      local_9 = ret;
      ret = *&[var0+0x2188];
      local_10 = ret;
      ret = *&[var0+0x218c];
      local_11 = ret;
      memcpy@plt(&url_buffer, "/etc/systemd/system/backdoor.service", 37);  // proto: void * memcpy(void * dst, const void * src, size_t n)
      printf@plt("Cron: %s\n", &var_180);  // proto: int printf(const char * fmt, ...)
      printf@plt("Service: %s\n", &url_buffer);  // proto: int printf(const char * fmt, ...)
      ret = 0;
      // x86-64 epilogue: restore rbp
      return;
  }
0x1160>
saving and exiting…
```

(Captured: [`_fixtures/02-naming-and-types/repl-decomp-after.out`](../_fixtures/02-naming-and-types/repl-decomp-after.out).)

Two things to read from this:

1. **Renamed slot flowed through.** `(rbp - 0x1b0)` is now
   rendered as `&url_buffer` at the `memcpy@plt(&url_buffer, …)`
   site and the `printf("Service: %s\n", &url_buffer)` site
   (#196 / #194).
2. **Inline locals block** lists each slot's `set_by` so the
   reader sees what's analyst-driven (`manual`) vs. analyzer-
   derived (`propagated`).

## Verify the writes from outside

The undo subcommand lists every reversible KB write:

```text
#5 stack_frame_vars function_va=0x1160 offset=-0x1b0  name: 'var_1b0' → 'url_buffer'
#4 data_labels va=0x4040  c_type: 'char *' → 'char[64]'
#3 data_labels va=0x4040  name: '<none>' → 'g_c2_endpoints'
#2 comments va=0x1160  body: '<none>' → 'entry: stash argc/argv into locals'
#1 function_names entry_va=0x1160  canonical: 'main' → 'c2_main'
```

(Captured: [`_fixtures/02-naming-and-types/undo-list.out`](../_fixtures/02-naming-and-types/undo-list.out).)

Five rows for five writes — function rename, comment, label
create, label retype, stack-slot rename. All reversible with
`glaurung undo`.

The undo log only captures `set_by=manual` writes. Auto / DWARF /
propagated writes don't enter the log because they re-derive on
the next analysis pass — undoing them would be meaningless.

See [§K `undo-redo.md`](undo-redo.md) for the full undo workflow.

## The full keystroke loop

Real session shape, ~30 seconds per cycle:

1. `g <addr>` — go to a place that looks interesting
2. `d` — read the body
3. `x` — see who calls it (§F)
4. `n <name>` — rename the function (uses cursor)
5. `c <addr> <text>` — comment with explicit VA
6. `label set <addr> <name> [<type>]` — name a global
7. `y <addr> <c-type>` — refine the type
8. `locals rename <off> <name>` — rename a stack slot
9. `g <next addr>` — onward

Repeat until you understand the binary.

## What's next

- [§F `cross-references.md`](cross-references.md) — going deeper on `x`
- [§G `stack-frames.md`](stack-frames.md) — going deeper on `l`
- [§K `undo-redo.md`](undo-redo.md) — the safety-net workflow
- [§S `07-malware-c2-demo.md`](../03-walkthroughs/07-malware-c2-demo.md) —
  the full c2_demo walkthrough using the techniques in this chapter

→ [§F `cross-references.md`](cross-references.md)
