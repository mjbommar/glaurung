# §I — Searching (`glaurung find`)

The "I know there's a 'parse_packet' somewhere — where?" command.
A single `glaurung find` searches across functions, comments, data
labels, types, stack vars, strings, and disassembly so you don't
have to remember which API holds what.

## Setup

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
glaurung kickoff $BIN --db demo.glaurung
```

## Basic search

```bash
glaurung find demo.glaurung printf
```

```
kind        location        snippet
----------  --------------  -------------------------------------
function    0x1030          printf  (set_by=analyzer)
disasm      0x117c          call rip:[rip + 0xeeb4]
disasm      0x119c          call rip:[rip + 0xee94]
...
string      file:0x4c2      Hello, %d\n
```

Default mode hits every kind. The query is **substring**, **case-
insensitive**.

## Filter by kind

| `--kind` | Searches |
|---|---|
| `function` | function_names canonical / demangled / aliases |
| `comment` | comments table |
| `data` | data_labels (name + c_type) |
| `type` | type_db (name + kind) |
| `stack_var` | stack_frame_vars (name + c_type) |
| `string` | triage-extracted strings (file_offset + text) |
| `disasm` | per-function disassembly mnemonic + operand text |
| `all` | (default) union of the above |

```bash
glaurung find demo.glaurung c2 --kind function
```

```
function    0x1160          c2_main  (set_by=manual)
```

## Regex

```bash
glaurung find demo.glaurung "^[A-Z]" --regex --kind function
```

Matches function names starting with a capital letter (useful for
finding C++ class names mid-mangling). Regex is Python `re.search`.

## Case-sensitive

```bash
glaurung find demo.glaurung TODO --kind comment --case-sensitive
```

Default is insensitive, which is usually what you want.

## Common queries

**"Find every TODO comment"**

```bash
glaurung find <db> TODO --kind comment
```

**"Find every function I renamed"**

```bash
glaurung find <db> "" --kind function | grep "set_by=manual"
```

**"Find every char-array stack var"**

```bash
glaurung find <db> "char\\[" --regex --kind stack_var
```

**"Find every URL-shaped string"**

```bash
glaurung find <db> "https?://" --regex --kind string
```

**"Find every call to recv across the binary"**

```bash
glaurung find <db> "call.*recv" --regex --kind disasm
```

**"What types do I have for sockets?"**

```bash
glaurung find <db> sockaddr --kind type
```

## JSON for scripting

```bash
glaurung find demo.glaurung "" --kind function --format json \
  | jq -r '.[] | "\(.location)\t\(.snippet)"' \
  | sort
```

Lists every function in the KB, tab-separated, sorted by VA.

## How it composes with the rest of the toolkit

`find` is the entry point that produces a VA you then feed to a
deeper command:

```bash
# 1. Find the function.
$ glaurung find demo.glaurung parse --kind function
function    0x1140          parse_packet  (set_by=manual)

# 2. Drill into its body.
$ glaurung view demo.glaurung 0x1140 --binary $BIN

# 3. See who calls it.
$ glaurung xrefs demo.glaurung 0x1140 --binary $BIN --direction to
```

This is the canonical "find → view → xref" loop.

## Caveats

- The `disasm` kind does a per-function disassembly pass capped at
  500 instructions per function; very large functions may need a
  more targeted search via `glaurung disasm <binary> <va>` directly.
- `find` reads from the KB — strings come from triage at `kickoff`
  time. If you've added new strings (e.g. by patching the binary)
  re-run `kickoff` to refresh.

## What's next

- [§F `cross-references.md`](cross-references.md) — pivot from a
  found VA to its callers
- [§E `naming-and-types.md`](naming-and-types.md) — rename what you found
- [§J `bookmarks-and-journal.md`](bookmarks-and-journal.md) — record
  findings while you explore

→ [§J `bookmarks-and-journal.md`](bookmarks-and-journal.md)
