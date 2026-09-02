# §E — Naming and types

> **Kind:** guide · **Status:** maintained

Goal: make narrowly supported analyst annotations, see them affect later views,
and retain enough provenance and history to reverse a mistake.

## Set up the project

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
DB=demo.glaurung
uv run glaurung kickoff "$BIN" --db "$DB"
uv run glaurung repl "$BIN" --db "$DB"
```

The sample contains recognizable network and persistence strings. Treat those
as investigation clues; the names below remain analyst claims. Current output
is under
[`_fixtures/02-naming-and-types/`](../_fixtures/02-naming-and-types/).

## Confirm the target before writing

```text
functions
g 0x1160
d
```

The shipped build currently identifies `main` at `0x1160`. Always obtain the
address from your project rather than assuming another build matches. Compare
[`repl-functions.out`](../_fixtures/02-naming-and-types/repl-functions.out).

## Rename and comment the function

```text
g 0x1160
n c2_main
c 0x1160 entry: stash argc/argv into locals
save
```

`n` renames the function at the cursor. `c` requires an explicit address. The
post-rename render is useful feedback, but it does not prove the new name is
correct. See [`repl-rename.out`](../_fixtures/02-naming-and-types/repl-rename.out)
and [`repl-comment.out`](../_fixtures/02-naming-and-types/repl-comment.out).

Verify the persisted provenance outside the REPL:

```bash
uv run glaurung find "$DB" c2_main --kind function
uv run glaurung find "$DB" "stash argc" --kind comment
```

The results are
[`find-renamed.out`](../_fixtures/02-naming-and-types/find-renamed.out) and
[`find-comment.out`](../_fixtures/02-naming-and-types/find-comment.out).

## Label and retype a global

The symbol table for this checked-in sample places `PRIMARY_C2_SERVER` at
`0x4040`. Model it first conservatively, then refine the type:

```text
label set 0x4040 primary_c2_server void *
y 0x4040 const char *
save
```

`label set ADDRESS NAME TYPE` creates or updates a manual data label. `y`
retypes an existing label. A pointer type is appropriate here because the
global stores a pointer; describing the storage itself as `char[64]` would be a
different and incorrect claim.

See [`repl-label-set.out`](../_fixtures/02-naming-and-types/repl-label-set.out),
[`repl-retype.out`](../_fixtures/02-naming-and-types/repl-retype.out), and
[`find-label.out`](../_fixtures/02-naming-and-types/find-label.out).

## Rename a stack slot

Inspect uses before assigning a semantic name:

```text
g 0x1160
l
locals rename -0x1b0 service_path
save
d
```

In this build the slot at `-0x1b0` receives the systemd service path, so
`service_path` is more defensible than a generic or unrelated buffer name. The
verified before/after evidence is in
[`repl-locals-rename.out`](../_fixtures/02-naming-and-types/repl-locals-rename.out)
and
[`repl-decomp-after.out`](../_fixtures/02-naming-and-types/repl-decomp-after.out).

Decompiler output can still be wrong; a better local name improves a
hypothesis, not the underlying proof.

## Audit and undo

```bash
uv run glaurung undo "$DB" --list
```

Manual writes have the highest precedence and are not meant to be silently
overwritten by analyzer passes. That makes analyst discipline and undo history
important. See [`undo-list.out`](../_fixtures/02-naming-and-types/undo-list.out)
and the [`set_by` precedence reference](../../reference/provenance.md).

Continue to [§F — Cross-references](cross-references.md).
