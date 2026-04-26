# §J — Bookmarks and journal

Two lightweight ways to capture findings while you explore:

- **Bookmarks** — VA-anchored "I'll come back to this" markers.
  Multiple bookmarks per VA are allowed.
- **Journal** — project-level dated free-form entries that aren't
  tied to a VA. The "today I learned X" log.

Both are distinct from per-VA comments, which are persistent
inline annotations. Comments are about what code *is*; bookmarks
and journal entries are about what *you* are doing.

## Setup

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
glaurung kickoff $BIN --db demo.glaurung
```

## Bookmarks

### Add a bookmark

```bash
glaurung bookmark demo.glaurung add 0x1140 "weird branch — investigate"
```

```
  bookmark #1  0x1140  weird branch — investigate
```

Multiple bookmarks per VA are allowed:

```bash
glaurung bookmark demo.glaurung add 0x1140 "first reading: looks like a parser"
glaurung bookmark demo.glaurung add 0x1140 "actually it's an init routine"
```

Both stick around. This is the "first impression vs second
impression" workflow — useful when your understanding evolves.

### List bookmarks

```bash
glaurung bookmark demo.glaurung list
```

```
  id  va            when                 note
----  ------------  -------------------  ----
   3  0x1140        2026-04-26 18:42:11  actually it's an init routine
   2  0x1140        2026-04-26 18:41:55  first reading: looks like a parser
   1  0x1140        2026-04-26 18:35:02  weird branch — investigate
```

Newest first. Use `--va <addr>` to filter to one address:

```bash
glaurung bookmark demo.glaurung list --va 0x1140
```

### Delete a bookmark

```bash
glaurung bookmark demo.glaurung delete 1
```

```
  deleted bookmark #1
```

### JSON

```bash
glaurung bookmark demo.glaurung list --format json | jq '.[] | .note'
```

## Journal

Journal entries are NOT tied to a VA. They're a project-level
free-form log.

### Add a journal entry

```bash
glaurung journal demo.glaurung add "today: traced the C2 protocol; it's a custom HTTP/JSON RPC"
```

```
  journal #1  today: traced the C2 protocol; it's a custom HTTP/JSON RPC
```

### List entries

```bash
glaurung journal demo.glaurung list
```

```
#3  2026-04-26 19:14:22
  found three exfil URLs — all use https://10.10.10.10:443/
#2  2026-04-26 18:55:01
  the encryption is simple XOR — see strings around 0x4080
#1  2026-04-26 18:42:11
  today: traced the C2 protocol; it's a custom HTTP/JSON RPC
```

### Delete

```bash
glaurung journal demo.glaurung delete 1
```

## When to use which

| Need | Tool |
|---|---|
| Mark a VA to come back to | `bookmark` |
| Multiple impressions of one VA | `bookmark` (multiple per VA) |
| Permanent annotation about code | `comment` (§E) — persists in re-renders |
| Date-stamped progress note | `journal` |
| "Today I learned" | `journal` |
| End-of-session summary | `journal` |

## Workflow integration

A typical session shape:

```bash
$ glaurung kickoff malware.elf --db case.glaurung

# Quick first pass: bookmark every suspicious-looking thing.
$ glaurung repl malware.elf --db case.glaurung
>>> g 0x1140
>>> b "this branch looks like an evasion check"
>>> g 0x1180
>>> b "huge stack frame — buffer overflow target?"
>>> q

# Triage break — record the day's progress.
$ glaurung journal case.glaurung add "session 1: 4 functions reviewed, 6 bookmarks, no comprehensive theory yet"

# Tomorrow, jump back to the bookmarks.
$ glaurung bookmark case.glaurung list
$ glaurung repl malware.elf --db case.glaurung
>>> g 0x1140
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
