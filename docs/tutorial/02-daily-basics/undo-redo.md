# §K — Undo and redo

Goal: inspect the analyst-write history, revert a specific newest change, and
understand what undo does not cover.

## Create a few manual writes

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
DB=demo.glaurung
uv run glaurung kickoff "$BIN" --db "$DB"
uv run glaurung repl "$BIN" --db "$DB"
```

In the REPL:

```text
g 0x1160
n c2_main
c 0x1160 entry: stash argc/argv into locals
label set 0x4040 primary_c2_server void *
save
q
```

The checked transcript is
[`repl-make-changes.out`](../_fixtures/02-undo-redo/repl-make-changes.out).

## Inspect before changing history

```bash
uv run glaurung undo "$DB" --list
```

History is newest-first and records the affected table, key, field, old value,
and new value. Review it before undoing. See
[`undo-list-before.out`](../_fixtures/02-undo-redo/undo-list-before.out).

## Undo and redo one write

```bash
uv run glaurung undo "$DB"
uv run glaurung undo "$DB" --list
uv run glaurung redo "$DB"
uv run glaurung undo "$DB" --list
```

The first command reverts the newest undoable analyst write. `redo` reapplies
the most recently undone write while that redo chain remains valid. Compare
[`undo-once.out`](../_fixtures/02-undo-redo/undo-once.out),
[`undo-list-after.out`](../_fixtures/02-undo-redo/undo-list-after.out), and
[`redo-once.out`](../_fixtures/02-undo-redo/redo-once.out).

## Undo several writes deliberately

```bash
uv run glaurung undo "$DB" -n 3
uv run glaurung undo "$DB" --list
```

`-n` applies to the newest eligible records. Verify the list before and after;
do not use a guessed count on a valuable project. The example results are
[`undo-multi.out`](../_fixtures/02-undo-redo/undo-multi.out) and
[`undo-list-final.out`](../_fixtures/02-undo-redo/undo-list-final.out).

## Scope and safety

Undo covers supported project writes such as renames, comments, labels, and
stack-variable edits. It does not reverse external file patches, exported
scripts, commands executed by another tool, or arbitrary direct SQLite edits.
Keep binary patches in separate output files and use versioned project backups
for high-value work.

Continue to [§L — Patch and verify](patch-and-verify.md).
