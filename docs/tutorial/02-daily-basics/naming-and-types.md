# §E — Naming and types (`n` / `y` / `c`)

The first keystroke loop. Every analyst's day is mostly: rename
something → look at its body → comment something → rename a
related thing. This chapter shows the muscle-memory shape, plus
why renames are safe (#228 undo) and how renames flow to callers
(#220 auto-rerender).

## Setup

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
glaurung kickoff $BIN --db demo.glaurung
glaurung repl $BIN --db demo.glaurung
```

We'll use `c2_demo` instead of `hello-clang-debug` because it has
something interesting to rename — hardcoded URLs, multiple call
sites, real libc usage.

## Rename a function (`n` at cursor)

```
>>> functions
0x1070  __do_global_dtors_aux  (analyzer)
0x10a0  deregister_tm_clones  (analyzer)
0x10d0  register_tm_clones  (analyzer)
0x1110  frame_dummy           (analyzer)
0x1160  main                  (analyzer)
```

Go to `main` and rename it for clarity:

```
>>> g 0x1160
0x1160
>>> n c2_main
  0x1160 → c2_main
  ── c2_main (post-rename) ──
    fn c2_main {
        nop;
        rsp = (rsp - 432);
        ...
```

The auto-rerender shows the renamed function's body. Renames
also flow into other functions' bodies on their next render —
any caller of `0x1160` will now show `c2_main(...)` (#220).

## Provenance: `set_by`

```
>>> functions | grep c2_main
```

Or from the CLI in another shell:

```bash
glaurung find demo.glaurung c2_main --kind function
```

```
kind        location        snippet
----------  --------------  ---------------------------
function    0x1160          c2_main  (set_by=manual)
```

`set_by=manual` is the highest tier. **No analyzer pass can clobber
this** — re-running `kickoff` won't revert it. See
[`reference/set-by-precedence.md`](../reference/set-by-precedence.md).

## Retype a data label (`y`)

The c2_demo has a global `g_secret_key`-shaped buffer. Find it:

```bash
glaurung strings-xrefs demo.glaurung --binary $BIN --used-only --limit 5
```

Pick a string with a use site — say `https://10.10.10.10:443/malware/update`
at file offset `0x2cd0`. Convert to VA (it's in `.rodata`):

```
>>> g 0x4000
0x4000
>>> label 0x4000 g_c2_url --type "char *"
  0x4000 g_c2_url  (char *)
```

Now retype it:

```
>>> y char[64]
  0x4000 g_c2_url: char[64]
```

Both writes are `set_by=manual`.

## Add a comment (`c`)

```
>>> g 0x1170
>>> c 0x1170 entry: stash argc/argv into locals
  0x1170: entry: stash argc/argv into locals
```

Comments are per-VA. They show up inline when you re-render the
function with `d`.

## Stack-var rename (`locals rename`)

```
>>> g 0x1160
>>> l
  4 vars in fn@0x1160:
    -0x1b0  var_1b0       (uses=2, by=auto)
    -0x140  var_140       (uses=3, by=auto)
    -0x10   var_10        (uses=1, by=auto)
    +0x10   ret           (uses=0, by=auto)

>>> locals rename -0x1b0 url_buffer
  renamed -0x1b0 -> url_buffer
```

Look at the function body again:

```
>>> d
fn c2_main {
    // ── locals (from KB) ───────────────────────
    char *url_buffer;       // -0x1b0  set_by=manual
    // ───────────────────────────────────────────
    nop;
    ...
    snprintf@plt(&url_buffer, 256, "http://%s:8080%s", ...);
    ...
}
```

The `(rbp - 0x1b0)` references in the body are now rendered as
`url_buffer` (#196 / #194).

## Save your work

```
>>> save
  saved.
>>> q
```

## Inspect your changes from outside

```bash
glaurung find demo.glaurung c2 --kind function
glaurung find demo.glaurung url_buffer --kind stack_var
glaurung find demo.glaurung "stash argc" --kind comment
```

Each row prints the `set_by=manual` tag — explicit provenance.

## Undo (#228)

If you change your mind:

```bash
glaurung undo demo.glaurung
undo #4 stack_frame_vars {function_va: 0x1160, offset: -0x1b0}  name: 'url_buffer' → 'var_1b0'
```

Each `undo` reverses one analyst write at a time. `--list` shows
history; `redo` re-applies.

The undo log only captures `set_by=manual` writes. Auto / DWARF /
propagated writes don't enter the log because they re-derive on
the next analysis pass — undoing them would be meaningless.

See [§K `undo-redo.md`](undo-redo.md) for the full undo workflow.

## The full keystroke loop

Real session shape, ~30 seconds per cycle:

1. `g <addr>` — go to a place that looks interesting
2. `d` — read the body
3. `x` — see who calls it
4. `n <name>` — rename it
5. `c <text>` — comment what it does
6. `g <next addr>` — onward

Repeat until you understand the binary.

## What's next

- [§F `cross-references.md`](cross-references.md) — going deeper on `x`
- [§G `stack-frames.md`](stack-frames.md) — going deeper on `l`
- [§K `undo-redo.md`](undo-redo.md) — the safety-net workflow
- [§S `07-malware-c2-demo.md`](../03-walkthroughs/07-malware-c2-demo.md) —
  the full c2_demo walkthrough using the techniques in this chapter

→ [§F `cross-references.md`](cross-references.md)
