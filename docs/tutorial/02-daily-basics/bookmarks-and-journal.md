# §J — Bookmarks and journal

Two lightweight ways to capture findings while you explore:

- **Bookmarks** — VA-anchored "I'll come back to this" markers.
  Multiple bookmarks per VA are allowed.
- **Journal** — project-level dated free-form entries that aren't
  tied to a VA. The "today I learned X" log.

Both are distinct from per-VA comments, which are persistent
inline annotations. Comments are about what code *is*; bookmarks
and journal entries are about what *you* are doing.

> **Verified output.** Every block is captured by
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/02-bookmarks/`](../_fixtures/02-bookmarks/).
> Timestamps are normalized to `YYYY-MM-DD HH:MM:SS` for
> reproducibility — yours will show actual wall-clock times.

## Setup

```bash
$ BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
$ glaurung kickoff $BIN --db demo.glaurung
```

## Bookmarks

### Add a bookmark

```bash
$ glaurung bookmark demo.glaurung add 0x1140 \
    "weird branch — investigate" --binary $BIN
```

```text
  bookmark #1  0x1140  weird branch — investigate
```

(Captured: [`_fixtures/02-bookmarks/bookmark-add-1.out`](../_fixtures/02-bookmarks/bookmark-add-1.out).)

```bash
$ glaurung bookmark demo.glaurung add 0x1160 "main entry" --binary $BIN
```

```text
  bookmark #2  0x1160  main entry
```

(Captured: [`_fixtures/02-bookmarks/bookmark-add-2.out`](../_fixtures/02-bookmarks/bookmark-add-2.out).)

Multiple bookmarks per VA are allowed:

```bash
$ glaurung bookmark demo.glaurung add 0x1140 \
    "actually it's a parser" --binary $BIN
```

```text
  bookmark #3  0x1140  actually it's a parser
```

(Captured: [`_fixtures/02-bookmarks/bookmark-add-second-at-1140.out`](../_fixtures/02-bookmarks/bookmark-add-second-at-1140.out).)

This is the "first impression vs second impression" workflow —
useful when your understanding evolves.

### List bookmarks

```bash
$ glaurung bookmark demo.glaurung list --binary $BIN
```

```text
  id  va            when                 note
------------------------------------------------------------
   3  0x1140        YYYY-MM-DD HH:MM:SS  actually it's a parser
   2  0x1160        YYYY-MM-DD HH:MM:SS  main entry
   1  0x1140        YYYY-MM-DD HH:MM:SS  weird branch — investigate
```

(Captured: [`_fixtures/02-bookmarks/bookmark-list.out`](../_fixtures/02-bookmarks/bookmark-list.out).)

Newest first. Note that bookmarks #1 and #3 are both at `0x1140`
— that's the multiple-impressions pattern.

### Filter by VA

```bash
$ glaurung bookmark demo.glaurung list --va 0x1140 --binary $BIN
```

```text
  id  va            when                 note
------------------------------------------------------------
   3  0x1140        YYYY-MM-DD HH:MM:SS  actually it's a parser
   1  0x1140        YYYY-MM-DD HH:MM:SS  weird branch — investigate
```

(Captured: [`_fixtures/02-bookmarks/bookmark-list-filter.out`](../_fixtures/02-bookmarks/bookmark-list-filter.out).)

### Delete a bookmark

```bash
$ glaurung bookmark demo.glaurung delete 1 --binary $BIN
```

```text
  deleted bookmark #1
```

(Captured: [`_fixtures/02-bookmarks/bookmark-delete.out`](../_fixtures/02-bookmarks/bookmark-delete.out).)

Confirm:

```bash
$ glaurung bookmark demo.glaurung list --binary $BIN
```

```text
  id  va            when                 note
------------------------------------------------------------
   3  0x1140        YYYY-MM-DD HH:MM:SS  actually it's a parser
   2  0x1160        YYYY-MM-DD HH:MM:SS  main entry
```

(Captured: [`_fixtures/02-bookmarks/bookmark-list-after-delete.out`](../_fixtures/02-bookmarks/bookmark-list-after-delete.out).)

Two left.

### JSON

```bash
$ glaurung bookmark demo.glaurung list --binary $BIN --format json
```

```json
[
  {"bookmark_id":3,"va":4416,"note":"actually it's a parser",
   "set_by":"manual","created_at":1777210386},
  {"bookmark_id":2,"va":4448,"note":"main entry",
   "set_by":"manual","created_at":1777210385}
]
```

(Captured: [`_fixtures/02-bookmarks/bookmark-list-json.out`](../_fixtures/02-bookmarks/bookmark-list-json.out).)

`va` is decoded decimal — `4416` = `0x1140`. `created_at` is a
Unix timestamp.

## Journal

Journal entries are NOT tied to a VA. They're a project-level
free-form log.

### Add a journal entry

```bash
$ glaurung journal demo.glaurung add \
    "today: traced the C2 protocol" --binary $BIN
```

```text
  journal #1  today: traced the C2 protocol
```

(Captured: [`_fixtures/02-bookmarks/journal-add.out`](../_fixtures/02-bookmarks/journal-add.out).)

### List entries

```bash
$ glaurung journal demo.glaurung list --binary $BIN
```

```text
#1  YYYY-MM-DD HH:MM:SS
  today: traced the C2 protocol
```

(Captured: [`_fixtures/02-bookmarks/journal-list.out`](../_fixtures/02-bookmarks/journal-list.out).)

## When to use which

| Need                                | Tool                                                |
|-------------------------------------|-----------------------------------------------------|
| Mark a VA to come back to           | `bookmark`                                          |
| Multiple impressions of one VA      | `bookmark` (multiple per VA)                        |
| Permanent annotation about code     | `comment` (§E) — persists in re-renders             |
| Date-stamped progress note          | `journal`                                           |
| "Today I learned"                   | `journal`                                           |
| End-of-session summary              | `journal`                                           |

## Workflow integration

A typical session shape:

```bash
$ glaurung kickoff malware.elf --db case.glaurung

# Quick first pass: bookmark every suspicious-looking thing.
$ glaurung bookmark case.glaurung add 0x1140 \
    "this branch looks like an evasion check" --binary malware.elf
$ glaurung bookmark case.glaurung add 0x1180 \
    "huge stack frame — buffer overflow target?" --binary malware.elf

# Triage break — record the day's progress.
$ glaurung journal case.glaurung add \
    "session 1: 4 functions reviewed, 6 bookmarks, no theory yet" \
    --binary malware.elf

# Tomorrow, jump back to the bookmarks.
$ glaurung bookmark case.glaurung list --binary malware.elf
```

## Bookmarks vs evidence_log (#200)

- **Bookmarks** are analyst notes — `set_by=manual`, free-form.
- **evidence_log** is automatic — every memory tool the agent
  invokes records its inputs/outputs there with a `cite_id`. The
  agent uses this for citations. See [§Z `evidence-and-citations.md`](../05-agent-workflows/evidence-and-citations.md).

You generally don't read evidence_log directly during analysis;
the agent does. Bookmarks are for you.

## What's next

- [§K `undo-redo.md`](undo-redo.md) — analyst safety net
- [§S `07-malware-c2-demo.md`](../03-walkthroughs/07-malware-c2-demo.md) —
  end-to-end walkthrough using bookmarks + journal

→ [§K `undo-redo.md`](undo-redo.md)
