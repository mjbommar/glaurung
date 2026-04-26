# §K — Undo / redo

The trust floor. Every analyst KB write — rename, retype, comment,
data label, stack-var — goes through the undo log. A single
`glaurung undo` reverses your last write; `redo` re-applies it.

This is the *reason* you can rename aggressively without fear.

## Setup

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
glaurung kickoff $BIN --db demo.glaurung
```

## A round trip

Make some changes:

```bash
glaurung repl $BIN --db demo.glaurung
```

```
>>> g 0x1160
>>> n c2_main
>>> c entry: stash argc/argv into locals
>>> label 0x4040 g_secret_key --type "char[32]"
>>> save
>>> q
```

Inspect history (no mutation):

```bash
glaurung undo demo.glaurung --list
```

```
#3 data_labels va=0x4040  name: '<none>' → 'g_secret_key'
#2 comments va=0x1160  body: '<none>' → 'entry: stash argc/argv into locals'
#1 function_names entry_va=0x1160  canonical: 'main' → 'c2_main'
```

Each row tells you which table changed, which key, and the old →
new value transition.

## Undo

```bash
glaurung undo demo.glaurung
```

```
undo #3 data_labels {va: 0x4040}  name: 'g_secret_key' → '<none>'
```

Just the most recent write. Confirm:

```bash
glaurung find demo.glaurung g_secret_key --kind data
```

```
(no matches for 'g_secret_key')
```

Gone. Now undo again:

```bash
glaurung undo demo.glaurung
```

```
undo #2 comments {va: 0x1160}  body: 'entry: stash argc/argv into locals' → '<none>'
```

The comment is gone. One more:

```bash
glaurung undo demo.glaurung
```

```
undo #1 function_names {entry_va: 0x1160}  canonical: 'c2_main' → 'main'
```

Back to the kickoff state.

## Multi-step undo

```bash
glaurung undo demo.glaurung -n 5
```

Reverts the last 5 writes in one call. Useful for "throw away the
last few minutes of edits."

## Redo

```bash
glaurung redo demo.glaurung
```

```
redo #1 function_names {entry_va: 0x1160}  canonical: 'main' → 'c2_main'
```

`redo` re-applies the most recently undone write. It works in the
same multi-step way: `redo -n 5`.

## What enters the log

Only `set_by=manual` writes are captured. Specifically:

- Function rename (`set_function_name` with `set_by="manual"`)
- Stack-var rename / retype (`set_stack_var`)
- Data-label add / retype (`set_data_label`)
- Comment add / replace (`set_comment`)

What does NOT enter the log:

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

**"I just made a mistake"**

```bash
glaurung undo <db>
```

**"I want to throw away everything since lunch"**

```bash
glaurung undo <db> --list   # find the row from before lunch
glaurung undo <db> -n 12    # rewind that many writes
```

**"I undid too far"**

```bash
glaurung redo <db> -n 3
```

**"What changed in this session?"**

```bash
glaurung undo <db> --list | head -20
```

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
- `redo` history is reset by a new `manual` write. If you `undo`,
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
