# §D — REPL tour

Goal: navigate a persistent project, inspect evidence, make provenance-aware
annotations, and confirm that the writes are undoable.

## Create a clean project

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
DB=tutorial.glaurung
uv run glaurung kickoff "$BIN" --db "$DB"
uv run glaurung repl "$BIN" --db "$DB"
```

The prompt's address is the current cursor. Most short commands operate on that
cursor. Type `help` whenever the checked-in keymap and your installed revision
differ; the live REPL is authoritative.

The automated transcript for every sequence below is under
[`_fixtures/01-repl-tour/`](../_fixtures/01-repl-tour/).

## Learn the available commands

At the prompt:

```text
help
```

The output groups navigation, inspection, annotation, persistence, and project
commands. See the verified [`repl-help.out`](../_fixtures/01-repl-tour/repl-help.out)
or the [REPL keymap](../reference/repl-keymap.md).

## Move the cursor

```text
g 0x1150
b
f
```

- `g ADDRESS` jumps to a virtual address.
- `b` moves backward through the current navigation context.
- `f` moves forward.

The cursor is a location, not proof of a function boundary. Confirm the active
function and instructions in the resulting view. The exact sequence is
captured in
[`repl-navigate.out`](../_fixtures/01-repl-tour/repl-navigate.out).

## Inspect xrefs and locals

```text
g 0x1150
x
l
```

`x` shows recorded cross-references around the cursor; `l` shows recovered
stack-frame slots for the current function. Empty xref results are meaningful:
they say no matching relationship is currently indexed, not that runtime use is
impossible. Compare the checked
[`xrefs transcript`](../_fixtures/01-repl-tour/repl-inspect.out) and
[`locals transcript`](../_fixtures/01-repl-tour/repl-locals.out).

## Render pseudocode

```text
g 0x11d0
d
```

`d` renders the current function using the same evolving decompiler pipeline as
the CLI. Names and types from the project can improve readability, but the
result remains a hypothesis. Check suspicious branches, calls, and memory
accesses against disassembly. See
[`repl-decomp.out`](../_fixtures/01-repl-tour/repl-decomp.out).

## List functions and prototypes

```text
functions 6
proto printf
```

`functions [N]` displays persisted functions with an optional row limit.
`proto NAME` looks up a known prototype. The verified results are
[`repl-functions.out`](../_fixtures/01-repl-tour/repl-functions.out) and
[`repl-proto.out`](../_fixtures/01-repl-tour/repl-proto.out).

## Rename and comment

Make two analyst annotations, then persist them:

```text
g 0x1200
n demo_static
c 0x1200 called once from main; flags-only side effect
save
```

The rename and comment are manual claims. Glaurung records their provenance and
history, but it cannot guarantee the text is correct; your evidence must. The
checked write and re-render are in
[`repl-annotate.out`](../_fixtures/01-repl-tour/repl-annotate.out).

## Rename a stack slot

```text
g 0x1150
locals rename -0x18 argc_copy
save
```

Offsets are relative to the recovered frame, so inspect `l` before editing.
The captured command is
[`repl-locals-rename.out`](../_fixtures/01-repl-tour/repl-locals-rename.out).

## Confirm undo history outside the REPL

Exit with `q`, then list the project history:

```bash
uv run glaurung undo "$DB" --list
```

The current transcript records the function rename, comment, and stack-slot
rename in reverse chronological order. See
[`undo-list-after.out`](../_fixtures/01-repl-tour/undo-list-after.out).

Use `uv run glaurung undo "$DB"` to revert the newest write and
`uv run glaurung redo "$DB"` to reapply an undone write. The next daily-basics
chapters cover multi-step history and the other annotation surfaces.

## The core loop

You now have the REPL's basic analyst cycle:

1. Move to evidence with `g`, `b`, or `f`.
2. Inspect xrefs, locals, prototypes, disassembly, and pseudocode.
3. Add a narrowly supported name, type, label, or comment.
4. `save`, then verify the changed view and undo history.

Continue to [§E — Naming and types](../02-daily-basics/naming-and-types.md).
