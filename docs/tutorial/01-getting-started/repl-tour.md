# §D — REPL tour

Goal: a 10-minute interactive session that exercises every REPL
keystroke you'll use day-to-day.

> **Verified output.** Every transcript in this chapter is real
> captured input/output from running the listed keystrokes through
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/01-repl-tour/`](../_fixtures/01-repl-tour/). Each block
> shows the exact keystrokes piped to `glaurung repl` followed by
> the REPL's actual stdout — no synthesized snippets.

> Reference: every keystroke documented in
> [`reference/repl-keymap.md`](../reference/repl-keymap.md).
> This page is the narrated walkthrough.

## Sample binary

```bash
$ BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
$ glaurung kickoff $BIN --db tutorial.glaurung
```

The kickoff populates the project file with 9 functions, 192 stdlib
prototypes, and 36 stack slots — exactly the same kickoff used in
§B `first-binary.md` and §M `01-hello-c-clang.md`.

(Captured: [`_fixtures/01-repl-tour/kickoff.out`](../_fixtures/01-repl-tour/kickoff.out).)

## Launch the REPL

```bash
$ glaurung repl $BIN --db tutorial.glaurung
```

You're now at a `>` prompt. The REPL prints a banner showing the
binary and the attached project file:

```text
glaurung repl  binary=.../hello-c-clang-debug
               db=tutorial.glaurung  session='main'
>
```

## `help` — list every keystroke

```text
─── stdin (keystrokes piped to glaurung repl) ───
help
q
─── glaurung repl stdout ───
> glaurung repl commands

  Navigation
    goto <addr> | g <addr>      jump cursor to address
    back | b                    previous history position
    forward | f                 next history position

  Persistence (auto-saved)
    rename <addr> <name>        set canonical function name
    comment <addr> <text>       attach a comment to an address
    struct <n> a:int b:char* …  define a struct
    locals                      list stack-frame slots in current function
    locals discover             auto-discover stack-frame slots from disasm
    locals rename <off> <name>  rename one slot (offset accepts 0x-hex)
    label                       list global data labels
    label set <addr> <name> [<type>]   add or rename a data label
    label remove <addr>         drop a data label
    label import                bootstrap labels from binary symbols
    borrow <donor>              copy names from a debug-build sibling
    proto                       list loaded function prototypes
    proto <name>                show one prototype (e.g. printf)
    proto set <name> <return> [<param>:<type> ...]   analyst override
    propagate                   refine slot types from prototype params
    recover-structs             auto-discover structs from access patterns
    save                        force a save (also automatic on every edit)

  Inspection
    xrefs [<addr>]              calls/refs into and out of address
    decomp [<addr>] | d         show pseudocode for the function at address
    functions [<n>]             list functions (default 20)
    types [<kind>]              list types
    show <type-name>            print one type as C
    strings [<n>]               first N triage strings

  AI
    ask <question>              run the memory agent (51 tools) over the
                                binary; persists results to the KB

  Misc
    help | ? | h                this text
    quit | q | exit             save and exit
>
saving and exiting…
```

(Captured: [`_fixtures/01-repl-tour/repl-help.out`](../_fixtures/01-repl-tour/repl-help.out).)

The REPL splits its commands into **Navigation**, **Persistence**
(every write auto-saves and enters the undo log), **Inspection**
(read-only), and **AI** (the agent — Tier 5).

## The cursor model — `g` / `b` / `f`

Most commands operate on "the current cursor". You move the cursor
with `goto` (or `g`):

```text
─── stdin (keystrokes piped to glaurung repl) ───
g 0x1150
b
f
q
─── glaurung repl stdout ───
>   0x1150  main  (set_by=analyzer)
0x1150> (at oldest history entry)
0x1150> (at newest history entry)
0x1150>
saving and exiting…
```

(Captured: [`_fixtures/01-repl-tour/repl-navigate.out`](../_fixtures/01-repl-tour/repl-navigate.out).)

Things to notice:

- The prompt morphs from `>` to `0x1150>` once the cursor is set.
- `g 0x1150` reports the function at that address with its
  `set_by` tag — `analyzer` here, since the symbol came from the
  binary's symbol table.
- `b` (back) and `f` (forward) walk a history stack like an IDA
  navigation history. With only one position visited there is
  nothing to walk to, so the REPL says so explicitly.

## Inspect the cursor — `x` (xrefs)

`x` shows cross-references into and out of the cursor's enclosing
function:

```text
─── stdin (keystrokes piped to glaurung repl) ───
g 0x1150
x
q
─── glaurung repl stdout ───
>   0x1150  main  (set_by=analyzer)
0x1150>   refs to 0x1150: 0
  refs from 0x1150: 2
    call        → 0x11d0  print_sum                 push rbp
    call        → 0x1200  static_function           push rbp
0x1150>
saving and exiting…
```

(Captured: [`_fixtures/01-repl-tour/repl-inspect.out`](../_fixtures/01-repl-tour/repl-inspect.out).)

`main` has zero callers (it's the entry-equivalent — `_start`
calls `__libc_start_main` which calls it indirectly) and two
outgoing calls: `print_sum` and `static_function`. Each row shows
the kind, target VA, callee name, and the calling instruction's
disasm snippet.

> **Drift check:** §M `01-hello-c-clang.md` Phase 5 shows that
> `print_sum` and `static_function` *also* get called from the
> anonymous helper `sub_117b`. Here we're looking from `main`'s
> perspective; the `xrefs … --direction to` query in §M is
> looking at the callees' callers.

## Inspect locals — `l`

`l` (or `locals`) lists the stack-frame slots discovered for the
enclosing function:

```text
─── stdin (keystrokes piped to glaurung repl) ───
g 0x1150
l
q
─── glaurung repl stdout ───
>   0x1150  main  (set_by=analyzer)
0x1150>   5 vars in fn@0x1150:
    -0x018  var_18  (uses=5, by=auto)
    -0x014  var_14  (uses=4, by=auto)
    -0x010  var_10  (uses=2, by=auto)
    -0x008  var_8  (uses=2, by=auto)
    -0x004  var_4  (uses=3, by=auto)
0x1150>
saving and exiting…
```

(Captured: [`_fixtures/01-repl-tour/repl-locals.out`](../_fixtures/01-repl-tour/repl-locals.out).)

Five auto-discovered slots, each with a usage count. `by=auto`
means the analyzer found them; renaming with `locals rename` flips
that to `by=manual`.

## Decompile the cursor — `d`

```text
─── stdin (keystrokes piped to glaurung repl) ───
g 0x11d0
d
q
─── glaurung repl stdout ───
>   0x11d0  print_sum  (set_by=analyzer)
0x11d0>   fn print_sum {
      push(rbp);
      rsp = (rsp - 16);
      local_0 = arg0;
      printf@plt("Total argument length: %d\n", local_1);  // proto: int printf(const char * fmt, ...)
      // x86-64 epilogue: restore rbp
      return;
  }
0x11d0>
saving and exiting…
```

(Captured: [`_fixtures/01-repl-tour/repl-decomp.out`](../_fixtures/01-repl-tour/repl-decomp.out).)

This is the same body §M Phase 4 surfaces from the CLI
`glaurung view … --pane pseudo`. The `// proto:` annotation
appears because the stdlib prototype bundle was loaded at kickoff
time.

## List functions — `functions [N]`

```text
─── stdin (keystrokes piped to glaurung repl) ───
functions 6
q
─── glaurung repl stdout ───
>   9 functions, showing first 6:
    0x1060  _start  (set_by=analyzer)
    0x1090  deregister_tm_clones  (set_by=analyzer)
    0x10c0  register_tm_clones  (set_by=analyzer)
    0x1100  __do_global_dtors_aux  (set_by=analyzer)
    0x1140  frame_dummy  (set_by=analyzer)
    0x1150  main  (set_by=analyzer)
>
saving and exiting…
```

(Captured: [`_fixtures/01-repl-tour/repl-functions.out`](../_fixtures/01-repl-tour/repl-functions.out).)

The REPL counts the total and trims to the requested limit. Same
data the `glaurung find <db> "" --kind function` CLI returns —
useful when you want to pick a target without leaving the REPL.

## Look up a prototype — `proto`

```text
─── stdin (keystrokes piped to glaurung repl) ───
proto printf
q
─── glaurung repl stdout ───
>   int printf(const char * fmt, ...)  (set_by=stdlib)
>
saving and exiting…
```

(Captured: [`_fixtures/01-repl-tour/repl-proto.out`](../_fixtures/01-repl-tour/repl-proto.out).)

This is the same prototype the decompiler annotates call sites
with. `set_by=stdlib` means it came from the bundled libc/libstdc++
type library — see §H `strings-and-data.md` and §E
`naming-and-types.md` for analyst overrides.

## Annotate — `n` (rename) + `c` (comment)

These writes are `set_by="manual"` and enter the undo log. **You
can always reverse them with `glaurung undo`** outside the REPL.

```text
─── stdin (keystrokes piped to glaurung repl) ───
g 0x1200
n demo_static
c 0x1200 called once from main; flags-only side effect
save
q
─── glaurung repl stdout ───
>   0x1200  static_function  (set_by=analyzer)
0x1200>   0x1200 → demo_static
  ── demo_static (post-rename) ──
    fn static_function {
        push(rbp);
        ret = *&[var0+0x4040];
        ret = (ret + 1);
        &[var0+0x4040] = ret;
    ... (4 more lines)
0x1200>   0x1200: called once from main; flags-only side effect
0x1200> saved.
0x1200>
saving and exiting…
```

(Captured: [`_fixtures/01-repl-tour/repl-annotate.out`](../_fixtures/01-repl-tour/repl-annotate.out).)

Three things happened:

1. `n demo_static` renamed `static_function` → `demo_static` and
   *auto-rerendered* the post-rename function body so you can
   confirm the change took. Note: the body header still says
   `fn static_function` because the rerender header reflects the
   pre-rename name in this REPL build — the canonical name
   stored in the KB is now `demo_static` (verifiable below).
2. `c 0x1200 …` attached a comment to the function entry VA.
3. `save` flushed to disk; `saved.` confirms the commit.

The rename and comment are `set_by="manual"` — the highest
precedence in the [set_by ladder](../reference/set-by-precedence.md),
so they survive any later analyzer pass.

## Rename a stack slot — `locals rename`

```text
─── stdin (keystrokes piped to glaurung repl) ───
g 0x1150
locals rename -0x18 argc_copy
save
q
─── glaurung repl stdout ───
>   0x1150  main  (set_by=analyzer)
0x1150>   renamed -0x018 -> argc_copy
0x1150> saved.
0x1150>
saving and exiting…
```

(Captured: [`_fixtures/01-repl-tour/repl-locals-rename.out`](../_fixtures/01-repl-tour/repl-locals-rename.out).)

We picked `-0x18` because §M's pseudocode showed `local_0 = arg0`
storing the argv pointer there. The slot is now `argc_copy` in the
KB. It will appear as `argc_copy` in every later `view` /
`decomp` rerender for `main`.

## Verify the writes from outside — `glaurung undo --list`

The undo subcommand lists every reversible KB write made this
session, in reverse order:

```text
#3 stack_frame_vars function_va=0x1150 offset=-0x18  name: 'var_18' → 'argc_copy'
#2 comments va=0x1200  body: '<none>' → 'called once from main; flags-only side effect'
#1 function_names entry_va=0x1200  canonical: 'static_function' → 'demo_static'
```

(Captured: [`_fixtures/01-repl-tour/undo-list-after.out`](../_fixtures/01-repl-tour/undo-list-after.out).)

Three rows for three writes, all reversible. See §K
`undo-redo.md` for the full undo/redo workflow.

## Save and exit

`save` commits the KB to disk. It's safe to run periodically; `q`
(or `quit` / `exit`) saves automatically. Every fixture above
ended with the line:

```text
saving and exiting…
```

— that's the REPL's farewell on `q`.

## Keystrokes you've now used

| Keystroke              | Meaning                              | Fixture |
|------------------------|--------------------------------------|---------|
| `help` / `?` / `h`     | List every command                   | `repl-help.out` |
| `g <addr>`             | Move cursor                          | `repl-navigate.out` |
| `b` / `f`              | History back / forward               | `repl-navigate.out` |
| `x` / `xrefs`          | Calls/refs at cursor                 | `repl-inspect.out` |
| `l` / `locals`         | Stack-frame slots                    | `repl-locals.out` |
| `d` / `decomp`         | Pseudocode at cursor                 | `repl-decomp.out` |
| `functions [N]`        | List functions in KB                 | `repl-functions.out` |
| `proto <name>`         | Show one stdlib prototype            | `repl-proto.out` |
| `n <name>`             | Rename function at cursor (manual)   | `repl-annotate.out` |
| `c <addr> <text>`      | Comment at address (manual)          | `repl-annotate.out` |
| `locals rename <off>`  | Rename one stack slot (manual)       | `repl-locals-rename.out` |
| `save` / `q`           | Persist + exit                       | (every fixture) |

The **persistence** group also includes `label set / remove /
import`, `borrow`, `proto set`, `propagate`, and `recover-structs`
— see §E and §H for examples that exercise those.

## Where to go next

You now have the muscle memory for the daily basics. Pick the
chapter that matches what you want to do:

- [**§E `naming-and-types.md`**](../02-daily-basics/naming-and-types.md) — go deep on `n`/`y`/`c`
- [**§F `cross-references.md`**](../02-daily-basics/cross-references.md) — go deep on `x`
- [**§G `stack-frames.md`**](../02-daily-basics/stack-frames.md) — go deep on `l`
- [**§H `strings-and-data.md`**](../02-daily-basics/strings-and-data.md) — strings panel + `label`
- [**§I `searching.md`**](../02-daily-basics/searching.md) — `glaurung find`
- [**§J `bookmarks-and-journal.md`**](../02-daily-basics/bookmarks-and-journal.md) — analyst notes
- [**§K `undo-redo.md`**](../02-daily-basics/undo-redo.md) — the safety net
- [**§L `patch-and-verify.md`**](../02-daily-basics/patch-and-verify.md) — patch shorthands

Or jump to a real walkthrough in [Tier 3](../03-walkthroughs/).
