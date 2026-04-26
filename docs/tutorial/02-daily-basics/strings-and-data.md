# §H — Strings and data labels (`strings-xrefs` / `label`)

The IDA "Strings" window in CLI form: every string in the binary
plus the call sites that reference it. Plus how to name globals
that aren't strings (counters, function-pointer tables, etc.).

## Setup

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
glaurung kickoff $BIN --db demo.glaurung
```

## The strings panel

```bash
glaurung strings-xrefs demo.glaurung --binary $BIN --limit 8
```

```
  offset  enc      len  uses  text  →  used_at
--------  -----  -----  ----  ----  -------
   0x318  ascii     27     0  /lib64/ld-linux-x86-64.so.2
   0x4a1  ascii     32     0  https://10.10.10.10:443/malware/update
   0x4c2  ascii     12     1  Hello, %d\n  →  c2_main@0x117c
   ...
```

Columns:

- `offset` — file offset of the string.
- `enc` — encoding (ascii / utf8 / utf16le / ...).
- `len` — string length in bytes.
- `uses` — number of `data_read` xrefs pointing at this offset.
- `text` — the string itself (truncated to 80 chars by default).
- `used_at` — the function and src_va of each use site (up to 3,
  with `+N more` if there are more).

## Filter to strings actually referenced

The triage scanner finds every string in the binary, including
runtime / format strings nothing references directly. To filter
to ones the code actually consumes:

```bash
glaurung strings-xrefs demo.glaurung --binary $BIN --used-only --limit 10
```

This is the analyst's typical view — "what literals does the code
consume?"

## Filter by encoding

```bash
glaurung strings-xrefs demo.glaurung --binary $BIN --encoding utf16le
```

Useful for Windows binaries where most strings are UTF-16.

## Filter by minimum length

```bash
glaurung strings-xrefs demo.glaurung --binary $BIN --min-len 12
```

Drops short strings that are mostly garbage like `[].` and
3-character function names.

## CTF tip: scan for IOCs

```bash
glaurung strings-xrefs demo.glaurung --binary $BIN --used-only --min-len 8 \
  | grep -iE "http|@|\.com|\.exe|\\.dll|\\.so"
```

For c2_demo this surfaces `http://%s:8080%s`, `https://10.10.10.10:443/...`,
the C2 domain templates, etc. — the indicators of compromise the
agent's `kickoff` summary called out earlier.

## Set a data label (REPL `label`)

When you find a global that isn't a string — a counter, a
function-pointer table, a struct — name it:

```bash
glaurung repl $BIN --db demo.glaurung
```

```
>>> label 0x4040 g_message_count --type "int"
  0x4040 g_message_count  (int)
```

Now any function that reads `0x4040` will render
`g_message_count` instead of the raw VA:

```
>>> g 0x118f
>>> d
fn c2_main {
    ...
    rax = g_message_count;
    ...
}
```

## Retype a label

If you got the type wrong, retype it:

```
>>> y char[64]
  0x4040 g_message_count: char[64]
```

(`y` works on the cursor; if your cursor is at `0x4040` it retypes
that label.)

## Provenance

```bash
glaurung find demo.glaurung g_message_count --kind data
```

```
kind        location        snippet
----------  --------------  -------------------------------
data        0x4040          g_message_count: int  (set_by=manual)
```

`set_by=manual` means this is yours — `glaurung undo` will reverse
the rename, the retype, or both. See
[§K `undo-redo.md`](undo-redo.md).

## Find every label

```bash
glaurung find demo.glaurung "" --kind data
```

(Empty query plus `--kind data` — lists every label.)

Or just the ones you set:

```bash
glaurung find demo.glaurung g_ --kind data
```

## JSON for scripting

```bash
glaurung strings-xrefs demo.glaurung --binary $BIN --used-only --format json \
  | jq -r '.[] | select(.uses > 1) | "\(.text) — \(.uses) uses"'
```

## Common patterns

**"What strings does it reference?"**
`glaurung strings-xrefs <db> --used-only`

**"Where is this URL referenced?"**
Find the offset → `glaurung xrefs <db> <va_at_that_offset> --kind data_read`

**"Name this global"**
REPL `label <addr> <name> --type <c-type>`

**"What's the global at 0x4040?"**
`glaurung find <db> 0x4040 --kind data`

## Caveats / GAPs

- The strings panel doesn't yet group by section (`.rodata` vs
  `.data`). That's [#240 GAP](../../architecture/IDA_GHIDRA_PARITY.md).
- Wide-character UTF-16 detection sometimes mis-classifies
  alternating-byte ASCII as UTF-16. Check the `enc` column.

## What's next

- [§F `cross-references.md`](cross-references.md) — pivot from a
  string's offset to its caller's body
- [§I `searching.md`](searching.md) — search across every table
  including strings
- [§S `07-malware-c2-demo.md`](../03-walkthroughs/07-malware-c2-demo.md) —
  full IOC-driven malware analysis

→ [§I `searching.md`](searching.md)
