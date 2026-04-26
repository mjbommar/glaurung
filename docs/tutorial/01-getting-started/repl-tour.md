# §D — REPL tour

Goal: a 10-minute interactive session that exercises every REPL
keystroke you'll use day-to-day.

> Reference: every keystroke documented in
> [`reference/repl-keymap.md`](../reference/repl-keymap.md).
> This page is the narrated walkthrough.

## Launch the REPL

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug
glaurung repl $BIN --db tutorial.glaurung
```

You're now at a `>>> ` prompt with a persistent KB (the
`tutorial.glaurung` you created in §B) attached.

## The cursor model

Most commands operate on "the current cursor". You move the cursor
with `goto` (or `g`):

```
>>> g 0x10d0
0x10d0
```

Step through history:

```
>>> g 0x1140
0x1140
>>> g 0x1180
0x1180
>>> b
0x1140        # back one step
>>> b
0x10d0
>>> f
0x1140        # forward one step
```

This is the same back/forward concept as IDA's history navigation.

## Read the function at the cursor

`d` decompiles the enclosing function with KB-aware rendering
(named locals, prototype hints, signature comment if a prototype
is set):

```
>>> g 0x10d0
>>> d
fn main {
    nop;
    rsp = (rsp - 32);
    *&[rsp + 0x18] = arg0;
    *&[rsp + 0x10] = arg1;
    ...
    return;
}
```

`l` (or `locals`) shows the stack-frame slots:

```
>>> l
  4 vars in fn@0x10d0:
    -0x18  argc          (uses=1, by=auto)
    -0x10  argv          (uses=1, by=auto)
    -0x08  saved_rbp     (uses=0, by=auto)
    +0x10  ret           (uses=0, by=auto)
```

`x` shows cross-references at the cursor:

```
>>> x
  refs to 0x10d0: 1
    call         0x11f8  _start                   call rip:[rip + 0x5fd0]
  refs from 0x10d0: 4
    call       → 0x10b0  printf@plt                call rip:[rip + ...]
    ...
```

## Annotate

These writes are `set_by="manual"` and enter the undo log. **You can
always reverse them with `glaurung undo`** outside the REPL.

```
>>> g 0x10d0
>>> n parse_packet
  0x10d0 → parse_packet
  ── parse_packet (post-rename) ──
    fn parse_packet {
        nop;
        rsp = (rsp - 32);
        ...
```

The auto-rerender shows the renamed function's body so you can
confirm the change took. Renames also propagate: any other
function that calls `0x10d0` will render `parse_packet(...)` on
its next `d`.

```
>>> c 0x10d4 TODO: bounds check this
  0x10d4: TODO: bounds check this
```

```
>>> locals rename -0x18 user_count
  renamed -0x018 -> user_count
```

```
>>> label 0x4000 g_secret_key --type "char[32]"
  0x4000 g_secret_key  (char[32])
```

```
>>> proto parse_packet int "char *,size_t"
  parse_packet  int(char *, size_t)
```

## Search

`functions` lists every named function in the KB:

```
>>> functions
0x1080  printf@plt           (analyzer)
0x10d0  parse_packet         (manual)
0x11e0  _start               (analyzer)
...
```

`types` lists every type:

```
>>> types
struct stat                              (dwarf)
typedef size_t = unsigned long           (stdlib)
...
```

`s` (or `strings`) lists triage-extracted strings.

## Cross-binary borrow

If you have a sibling binary with debug info, you can pull names
from it:

```
>>> borrow other-binary-with-symbols.glaurung
  borrowed 23 names
```

This uses prologue-matching to identify functions in the stripped
binary that match named ones in the donor. `set_by="borrowed"`.

## Run analysis passes from the REPL

```
>>> propagate
  propagated types into 14 stack slots across 4 functions
>>> recover-structs
  found 3 candidate struct types
>>> save
```

`save` commits the KB to disk. It's safe to run periodically;
`q` (or `quit`) saves automatically.

## Ask the agent (optional, requires LLM credentials)

```
>>> ask "what does this binary do?"
  ... (agent's response with citations to evidence_log) ...
```

This reads the same KB the deterministic commands wrote. Every tool
call the agent makes records to evidence_log so its answer can cite
specific findings. See Tier 5 §Y `chat-driven-triage.md`.

## Save and exit

```
>>> save
  saved.
>>> q
```

Or just `quit` / `exit`.

## Undo from outside the REPL

The REPL doesn't have a built-in undo command — `undo` is a CLI
subcommand because most analysts undo across REPL sessions. After
quitting:

```bash
$ glaurung undo tutorial.glaurung
undo #5 function_names {entry_va: 0x10d0}  canonical: 'parse_packet' → 'sub_10d0'
```

See [§K `undo-redo.md`](../02-daily-basics/undo-redo.md) for the full
undo workflow.

## Where to go next

You now have the muscle memory for the daily basics. Pick the chapter
that matches what you want to do:

- [**§E `naming-and-types.md`**](../02-daily-basics/naming-and-types.md) — go deep on `n`/`y`/`c`
- [**§F `cross-references.md`**](../02-daily-basics/cross-references.md) — go deep on `x`
- [**§G `stack-frames.md`**](../02-daily-basics/stack-frames.md) — go deep on `l`
- [**§H `strings-and-data.md`**](../02-daily-basics/strings-and-data.md) — strings panel + `label`
- [**§I `searching.md`**](../02-daily-basics/searching.md) — `glaurung find`
- [**§J `bookmarks-and-journal.md`**](../02-daily-basics/bookmarks-and-journal.md) — analyst notes
- [**§K `undo-redo.md`**](../02-daily-basics/undo-redo.md) — the safety net
- [**§L `patch-and-verify.md`**](../02-daily-basics/patch-and-verify.md) — patch shorthands

Or jump to a real walkthrough in [Tier 3](../03-walkthroughs/).
