# §K — Undo / redo

The trust floor. Every analyst KB write — rename, retype, comment,
data label, stack-var — goes through the undo log. A single
`glaurung undo` reverses your last write; `redo` re-applies it.

This is the *reason* you can rename aggressively without fear.

> **Verified output.** Every block is captured by
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/02-undo-redo/`](../_fixtures/02-undo-redo/).

## Setup

```bash
$ BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
$ glaurung kickoff $BIN --db demo.glaurung
```

## A round trip

Make some changes through the REPL:

```text
─── stdin (keystrokes piped to glaurung repl) ───
g 0x1160
n c2_main
c 0x1160 entry: stash argc/argv into locals
label set 0x4040 g_c2_endpoints char *
save
q
─── glaurung repl stdout ───
>   0x1160  main  (set_by=analyzer)
0x1160>   0x1160 → c2_main
  ── c2_main (post-rename) ──
    fn main { … (post-rename body) … }
0x1160>   0x1160: entry: stash argc/argv into locals
0x1160>   labelled 0x00004040 -> g_c2_endpoints
0x1160> saved.
0x1160>
saving and exiting…
```

(Captured: [`_fixtures/02-undo-redo/repl-make-changes.out`](../_fixtures/02-undo-redo/repl-make-changes.out).)

Three writes: rename, comment, label. All `set_by=manual`, all
in the undo log.

## Inspect history (no mutation): `undo --list`

```bash
$ glaurung undo demo.glaurung --list
```

```text
#3 data_labels va=0x4040  name: '<none>' → 'g_c2_endpoints'
#2 comments va=0x1160  body: '<none>' → 'entry: stash argc/argv into locals'
#1 function_names entry_va=0x1160  canonical: 'main' → 'c2_main'
```

(Captured: [`_fixtures/02-undo-redo/undo-list-before.out`](../_fixtures/02-undo-redo/undo-list-before.out).)

Newest first. Each row tells you which table changed, the key,
and the old → new value transition.

## Undo the last write

```bash
$ glaurung undo demo.glaurung
```

```text
undo [undone] #3 data_labels va=0x4040  name: '<none>' → 'g_c2_endpoints'
```

(Captured: [`_fixtures/02-undo-redo/undo-once.out`](../_fixtures/02-undo-redo/undo-once.out).)

The data label is gone. The history list now marks it `[undone]`:

```bash
$ glaurung undo demo.glaurung --list
```

```text
[undone] #3 data_labels va=0x4040  name: '<none>' → 'g_c2_endpoints'
#2 comments va=0x1160  body: '<none>' → 'entry: stash argc/argv into locals'
#1 function_names entry_va=0x1160  canonical: 'main' → 'c2_main'
```

(Captured: [`_fixtures/02-undo-redo/undo-list-after.out`](../_fixtures/02-undo-redo/undo-list-after.out).)

Note the `[undone]` flag — the row stays in history, marked
reversible. A later `redo` re-applies it.

## Redo the last undone write

```bash
$ glaurung redo demo.glaurung
```

```text
redo #3 data_labels va=0x4040  name: '<none>' → 'g_c2_endpoints'
```

(Captured: [`_fixtures/02-undo-redo/redo-once.out`](../_fixtures/02-undo-redo/redo-once.out).)

The label is back. History reverts:

```bash
$ glaurung undo demo.glaurung --list
```

```text
#3 data_labels va=0x4040  name: '<none>' → 'g_c2_endpoints'
#2 comments va=0x1160  body: '<none>' → 'entry: stash argc/argv into locals'
#1 function_names entry_va=0x1160  canonical: 'main' → 'c2_main'
```

(Captured: [`_fixtures/02-undo-redo/undo-list-after-redo.out`](../_fixtures/02-undo-redo/undo-list-after-redo.out).)

The `[undone]` flag is gone — `#3` is live again.

## Multi-step undo: `-n`

```bash
$ glaurung undo demo.glaurung -n 3
```

```text
undo [undone] #3 data_labels va=0x4040  name: '<none>' → 'g_c2_endpoints'
undo [undone] #2 comments va=0x1160  body: '<none>' → 'entry: stash argc/argv into locals'
undo [undone] #1 function_names entry_va=0x1160  canonical: 'main' → 'c2_main'
```

(Captured: [`_fixtures/02-undo-redo/undo-multi.out`](../_fixtures/02-undo-redo/undo-multi.out).)

Three writes reverted in one call. Useful for "throw away the
last few minutes of edits."

```bash
$ glaurung undo demo.glaurung --list
```

```text
[undone] #3 data_labels va=0x4040  name: '<none>' → 'g_c2_endpoints'
[undone] #2 comments va=0x1160  body: '<none>' → 'entry: stash argc/argv into locals'
[undone] #1 function_names entry_va=0x1160  canonical: 'main' → 'c2_main'
```

(Captured: [`_fixtures/02-undo-redo/undo-list-final.out`](../_fixtures/02-undo-redo/undo-list-final.out).)

All three are now `[undone]` — back to the kickoff state. A
`redo -n 3` would put them all back.

## What enters the log

Only `set_by=manual` writes are captured:

- Function rename (`set_function_name` with `set_by="manual"`)
- Stack-var rename / retype (`set_stack_var`)
- Data-label add / retype (`set_data_label`)
- Comment add / replace (`set_comment`)

What does **not** enter the log:

- `set_by=auto` (heuristic struct discovery, default `var_<hex>` slots)
- `set_by=dwarf` (debug-info-derived names + types)
- `set_by=flirt` (signature-matched names)
- `set_by=propagated` (call-site type inference)
- `set_by=cil` / `gopclntab` (managed-runtime metadata recovery)
- `set_by=stdlib` (auto-loaded library bundle types)
- `set_by=borrowed` (cross-binary symbol borrow)

These re-derive on the next analysis pass. Undoing them would be
meaningless — re-running `kickoff` (or its sub-passes) would just
put them back. The undo log is your safety net for **analyst
intent**, not for the analyzer's findings.

## What about patches?

Today, `glaurung patch` produces a new binary file — it doesn't
write to the `.glaurung` KB. That means **patches don't enter the
undo log**, only KB writes do.

[#235 GAP](../../architecture/IDA_GHIDRA_PARITY.md) tracks wiring
patches into the undo log so a single `glaurung undo` reverses
both KB writes and byte-level edits. Until that lands, the
workflow for reverting a patch is "delete the output file and
re-run patch."

## Common patterns

| Need                                    | Command                                        |
|-----------------------------------------|------------------------------------------------|
| Undo the last write                     | `glaurung undo <db>`                           |
| Undo the last 3 writes                  | `glaurung undo <db> -n 3`                      |
| Redo the most recent undo               | `glaurung redo <db>`                           |
| Redo many                               | `glaurung redo <db> -n 5`                      |
| Inspect history (no mutation)           | `glaurung undo <db> --list`                    |
| What changed in this session?           | `glaurung undo <db> --list \| head -20`        |

## Trust safety

The undo log makes aggressive renames safe:

- Wrong name? `undo` it.
- Bad type? `undo` it.
- Want to try a different theory? Bookmark, rename, explore — if
  the theory doesn't pan out, `undo -n N` rewinds.

This is what we mean by "the analyst's safety net" — Glaurung is
designed for fast-iterate workflows where you rename a function
3 times in 5 minutes as your understanding evolves, and the undo
log keeps the history reversible.

## Caveats

- The undo log is per-`.glaurung` file. Backing up the file backs
  up the log too.
- `redo` history is reset by a new `manual` write — if you `undo`,
  then make a new manual change, the redo stack is cleared (just
  like every text editor).
- The log doesn't currently track patches (#235 GAP). Workaround:
  re-run `patch` against the original input.

## What's next

- [§L `patch-and-verify.md`](patch-and-verify.md) — the patch tool;
  note that #235 is the gap for "undo across patch + KB"
- [§S `07-malware-c2-demo.md`](../03-walkthroughs/07-malware-c2-demo.md) —
  full walkthrough showing aggressive renames + undo

→ [§L `patch-and-verify.md`](patch-and-verify.md)
