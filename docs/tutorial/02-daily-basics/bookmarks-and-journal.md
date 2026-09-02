# §J — Bookmarks and journal

> **Kind:** guide · **Status:** maintained

Goal: keep address-specific follow-ups separate from project-level notes and
retrieve both deterministically.

## Set up

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
DB=demo.glaurung
uv run glaurung kickoff "$BIN" --db "$DB"
```

## Add address bookmarks

```bash
uv run glaurung bookmark "$DB" add 0x1140 \
  "weird branch — investigate" --binary "$BIN"
uv run glaurung bookmark "$DB" add 0x1160 \
  "main entry" --binary "$BIN"
```

A bookmark records a VA and note. It does not validate that the VA is a
function boundary or that the note is correct. See
[`bookmark-add-1.out`](../_fixtures/02-bookmarks/bookmark-add-1.out).

Multiple bookmarks may refer to the same VA. List all or filter by address:

```bash
uv run glaurung bookmark "$DB" list --binary "$BIN"
uv run glaurung bookmark "$DB" list --va 0x1140 --binary "$BIN"
```

The checked results are
[`bookmark-list.out`](../_fixtures/02-bookmarks/bookmark-list.out) and
[`bookmark-list-filter.out`](../_fixtures/02-bookmarks/bookmark-list-filter.out).

## Keep a project journal

```bash
uv run glaurung journal "$DB" add \
  "today: traced the C2 protocol" --binary "$BIN"
uv run glaurung journal "$DB" list --binary "$BIN"
```

Journal entries are project-level notes rather than address anchors. Include
enough evidence context that another analyst can reproduce the claim. See
[`journal-list.out`](../_fixtures/02-bookmarks/journal-list.out).

## Delete by record ID

List first, then pass the returned bookmark ID:

```bash
uv run glaurung bookmark "$DB" delete 1 --binary "$BIN"
uv run glaurung bookmark "$DB" list --binary "$BIN"
```

The example fixture is a fresh project where ID `1` is known; never assume that
ID in an existing project. See
[`bookmark-delete.out`](../_fixtures/02-bookmarks/bookmark-delete.out) and
[`bookmark-list-after-delete.out`](../_fixtures/02-bookmarks/bookmark-list-after-delete.out).

## JSON output and timestamps

```bash
uv run glaurung bookmark "$DB" list --binary "$BIN" --format json
```

JSON exposes numeric IDs, VAs, provenance, and creation time. The tutorial
normalizes the current epoch value so fixture checks do not drift merely because
the command ran later. See
[`bookmark-list-json.out`](../_fixtures/02-bookmarks/bookmark-list-json.out).

Continue to [§K — Undo and redo](undo-redo.md).
