# §I — Searching (`glaurung find`)

The "I know there's a `parse_packet` somewhere — where?" command.
A single `glaurung find` searches across functions, comments, data
labels, types, stack vars, strings, and disassembly so you don't
have to remember which API holds what.

> **Verified output.** Every block is captured by
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/02-searching/`](../_fixtures/02-searching/).

## Setup

```bash
$ BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
$ glaurung kickoff $BIN --db demo.glaurung
```

(Same `hello-c-clang-debug` we used in §B / §M / §F. 9 functions
discovered, 192 stdlib prototypes loaded.)

## Default search — across every kind

```bash
$ glaurung find demo.glaurung main
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
function    0x1150          main  (set_by=analyzer)
string      file:0x498      __libc_start_main
string      file:0x3322     main
string      file:0x38fa     __libc_start_main@GLIBC_2.34
string      file:0x39c8     main
```

(Captured: [`_fixtures/02-searching/find-substring.out`](../_fixtures/02-searching/find-substring.out).)

Default mode hits every kind — function names AND every string
the triage scanner found. The query is **substring**,
**case-insensitive**.

## Filter by kind: `--kind <name>`

| `--kind` value | Searches                                      |
|----------------|-----------------------------------------------|
| `function`     | function_names canonical / demangled / aliases |
| `comment`      | comments table                                |
| `data`         | data_labels (name + c_type)                   |
| `type`         | type_db (name + kind)                         |
| `stack_var`    | stack_frame_vars (name + c_type)              |
| `string`       | triage-extracted strings (file_offset + text) |
| `disasm`       | per-function disassembly mnemonic + operand text |
| `all`          | (default) union of the above                   |

```bash
$ glaurung find demo.glaurung main --kind function
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
function    0x1150          main  (set_by=analyzer)
```

(Captured: [`_fixtures/02-searching/find-kind-function.out`](../_fixtures/02-searching/find-kind-function.out).)

## List every function (empty query)

The empty string matches everything — useful for "what functions
are there?":

```bash
$ glaurung find demo.glaurung "" --kind function
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
function    0x1060          _start  (set_by=analyzer)
function    0x1090          deregister_tm_clones  (set_by=analyzer)
function    0x10c0          register_tm_clones  (set_by=analyzer)
function    0x1100          __do_global_dtors_aux  (set_by=analyzer)
function    0x1140          frame_dummy  (set_by=analyzer)
function    0x1150          main  (set_by=analyzer)
function    0x117b          sub_117b  (set_by=analyzer)
function    0x11d0          print_sum  (set_by=analyzer)
function    0x1200          static_function  (set_by=analyzer)
```

(Captured: [`_fixtures/02-searching/find-all-functions.out`](../_fixtures/02-searching/find-all-functions.out).)

Same nine functions kickoff reported.

## Regex with `--regex`

```bash
$ glaurung find demo.glaurung "^_" --regex --kind function
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
function    0x1060          _start  (set_by=analyzer)
function    0x1100          __do_global_dtors_aux  (set_by=analyzer)
```

(Captured: [`_fixtures/02-searching/find-regex-funcs.out`](../_fixtures/02-searching/find-regex-funcs.out).)

Two matches: `_start` and `__do_global_dtors_aux`. Regex engine
is Python `re.search`. Default is still case-insensitive.

## Case sensitivity

By default, queries are insensitive:

```bash
$ glaurung find demo.glaurung MAIN --kind function
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
function    0x1150          main  (set_by=analyzer)
```

(Captured: [`_fixtures/02-searching/find-case-sensitive.out`](../_fixtures/02-searching/find-case-sensitive.out).)

`MAIN` matched `main`. Add `--case-sensitive` to require an exact
case match:

```bash
$ glaurung find demo.glaurung MAIN --kind function --case-sensitive
```

```text
(no matches for 'MAIN')
```

(Captured: [`_fixtures/02-searching/find-case-sensitive-flag.out`](../_fixtures/02-searching/find-case-sensitive-flag.out).)

## Search strings

```bash
$ glaurung find demo.glaurung Hello --kind string
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
string      file:0x2004     Hello, World from C!
string      file:0x32dd     /workspace/source/c/hello.c
string      file:0x33a4     /workspace/source/c/hello.c
string      file:0x3887     hello.c
```

(Captured: [`_fixtures/02-searching/find-strings.out`](../_fixtures/02-searching/find-strings.out).)

Note: the substring match catches `hello.c` as well as
`Hello, World` because the search is case-insensitive.

## Search disassembly

```bash
$ glaurung find demo.glaurung "^push" --regex --kind disasm
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
disasm      0x1071          push rax
disasm      0x1072          push rsp
disasm      0x110d          push rbp
disasm      0x1150          push rbp
disasm      0x11d0          push rbp
disasm      0x1200          push rbp
…
```

(Captured: [`_fixtures/02-searching/find-disasm.out`](../_fixtures/02-searching/find-disasm.out).)

The `disasm` kind walks every function's lifted instructions.
Useful for "every site that has a specific instruction shape" —
e.g. `^syscall` to find all syscall sites, `^endbr` for IBT
landing pads.

> **Caveat.** The disasm kind disassembles each function's prologue
> on each lookup, so duplicates appear if the same instruction is
> reachable from multiple analysis sweeps. Use VA + snippet to
> dedupe in scripts.

## JSON for scripting

```bash
$ glaurung find demo.glaurung main --kind function --format json
```

```json
[{"kind":"function","location":"0x1150","snippet":"main  (set_by=analyzer)"}]
```

(Captured: [`_fixtures/02-searching/find-json.out`](../_fixtures/02-searching/find-json.out).)

Use `jq` to drive subsequent commands:

```bash
$ glaurung find demo.glaurung "" --kind function --format json \
    | jq -r '.[] | "\(.location)\t\(.snippet)"' \
    | sort
```

## How it composes with the rest of the toolkit

`find` is the entry point that produces a VA you then feed to a
deeper command:

```bash
# 1. Find the function.
$ glaurung find demo.glaurung print_sum --kind function
function    0x11d0          print_sum  (set_by=analyzer)

# 2. Drill into its body.
$ glaurung view demo.glaurung 0x11d0 --binary $BIN

# 3. See who calls it.
$ glaurung xrefs demo.glaurung 0x11d0 --binary $BIN --direction to
```

This is the canonical "find → view → xref" loop.

## Common queries

| Question                                | Command                                                     |
|-----------------------------------------|-------------------------------------------------------------|
| Find every TODO comment                 | `find <db> TODO --kind comment`                             |
| List every analyst-renamed function     | `find <db> "" --kind function \| grep "set_by=manual"`      |
| Find every char-array stack var         | `find <db> "char\\[" --regex --kind stack_var`              |
| Find every URL-shaped string            | `find <db> "https?://" --regex --kind string`               |
| Find a struct type                      | `find <db> sockaddr --kind type`                            |
| Find every `push rbp` (function entry)  | `find <db> "^push rbp" --regex --kind disasm`               |

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
