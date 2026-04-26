# §H — Strings and data labels (`strings-xrefs` / `label`)

The IDA "Strings" window in CLI form: every string in the binary
plus the call sites that reference it. Plus how to name globals
that aren't strings (counters, function-pointer tables, etc.).

> **Verified output.** Every block is captured by
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/02-strings-and-data/`](../_fixtures/02-strings-and-data/).

## Setup

```bash
$ BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
$ glaurung kickoff $BIN --db demo.glaurung
```

(Same kickoff as §E and §G — 6 functions, 90 stack slots, 192
stdlib prototypes.)

## The strings panel: `glaurung strings-xrefs`

```bash
$ glaurung strings-xrefs demo.glaurung --binary $BIN --limit 10
```

```text
  offset  enc       len  uses  text  →  used_at
--------------------------------------------------------------------------------
     792  ascii      27     0  /lib64/ld-linux-x86-64.so.2
    1185  ascii      14     0  __cxa_finalize
    1200  ascii      17     0  __libc_start_main
    1218  ascii       8     0  snprintf
    1227  ascii       6     0  memcpy
    1234  ascii       9     0  libc.so.6
    1244  ascii      10     0  GLIBC_2.14
    1255  ascii      11     0  GLIBC_2.2.5
    1267  ascii      10     0  GLIBC_2.34
    1278  ascii      27     0  _ITM_deregisterTMCloneTable
```

(Captured: [`_fixtures/02-strings-and-data/strings-xrefs-default.out`](../_fixtures/02-strings-and-data/strings-xrefs-default.out).)

Columns:

- `offset` — file offset of the string (decimal in this build).
- `enc` — encoding (ascii / utf8 / utf16le / …).
- `len` — string length in bytes.
- `uses` — number of `data_read` xrefs pointing at this offset.
- `text` — the string itself (truncated to 80 chars by default).
- `used_at` — the function and src_va of each use site (up to 3,
  with `+N more` if there are more).

> **Note on `uses` for c2_demo.** Every row shows `uses=0` here
> because c2_demo's kickoff doesn't currently populate the
> data-read xref index (same coverage gap §F documents). Use a
> binary like `hello-c-clang-debug` if you want to see non-zero
> use counts.

## Filter by minimum length

The triage scanner finds every printable run, including short
junk. Drop short strings to surface the IOCs:

```bash
$ glaurung strings-xrefs demo.glaurung --binary $BIN --min-len 12 --limit 10
```

```text
  offset  enc       len  uses  text  →  used_at
--------------------------------------------------------------------------------
     792  ascii      27     0  /lib64/ld-linux-x86-64.so.2
    1185  ascii      14     0  __cxa_finalize
    1200  ascii      17     0  __libc_start_main
    1278  ascii      27     0  _ITM_deregisterTMCloneTable
    1306  ascii      14     0  __gmon_start__
    1321  ascii      25     0  _ITM_registerTMCloneTable
    8196  ascii      14     0  192.168.100.50
    8221  ascii      19     0  malware-c2.evil.com
    8241  ascii      34     0  beacon.command-control.badguys.org
    8276  ascii      22     0  Mozilla/5.0 BotNet/1.0
```

(Captured: [`_fixtures/02-strings-and-data/strings-xrefs-min-len.out`](../_fixtures/02-strings-and-data/strings-xrefs-min-len.out).)

The IOCs jump out: a hardcoded IPv4, two C2 domains, and a fake
user-agent — exactly what the kickoff IOC scan called out.

## `--used-only` (when the xref index has data)

```bash
$ glaurung strings-xrefs demo.glaurung --binary $BIN --used-only --limit 10
```

```text
(no strings matched)
```

(Captured: [`_fixtures/02-strings-and-data/strings-xrefs-used-only.out`](../_fixtures/02-strings-and-data/strings-xrefs-used-only.out).)

For c2_demo the xref index isn't populated, so `--used-only`
returns nothing. This filter is the analyst's typical view —
"only show strings the code actually consumes" — and works on
binaries whose kickoff registers PLT-call xrefs (e.g.
hello-c-clang).

## JSON for scripting

```bash
$ glaurung strings-xrefs demo.glaurung --binary $BIN \
    --min-len 12 --limit 5 --format json
```

```json
[
  {"offset":792,"encoding":"ascii","length":27,"text":"/lib64/ld-linux-x86-64.so.2","uses":0,"used_at":[]},
  {"offset":1185,"encoding":"ascii","length":14,"text":"__cxa_finalize","uses":0,"used_at":[]},
  {"offset":1200,"encoding":"ascii","length":17,"text":"__libc_start_main","uses":0,"used_at":[]},
  {"offset":1278,"encoding":"ascii","length":27,"text":"_ITM_deregisterTMCloneTable","uses":0,"used_at":[]},
  {"offset":1306,"encoding":"ascii","length":14,"text":"__gmon_start__","uses":0,"used_at":[]}
]
```

(Captured: [`_fixtures/02-strings-and-data/strings-xrefs-json.out`](../_fixtures/02-strings-and-data/strings-xrefs-json.out).)

Pipeline-friendly. Use `jq` to filter / count:

```bash
$ glaurung strings-xrefs demo.glaurung --binary $BIN --format json \
    | jq -r '.[] | select(.length >= 12) | .text'
```

## Set a data label (REPL `label set`)

When you find a global that isn't a string — a counter, a
function-pointer table, a struct — name it:

```text
─── stdin (keystrokes piped to glaurung repl) ───
label set 0x4040 g_c2_endpoints char *
save
q
─── glaurung repl stdout ───
>   labelled 0x00004040 -> g_c2_endpoints
> saved.
>
saving and exiting…
```

(Captured: [`_fixtures/02-strings-and-data/repl-label.out`](../_fixtures/02-strings-and-data/repl-label.out).)

The REPL syntax is `label set <addr> <name> [<type>]` — note the
`set` subcommand. `label` alone (no args) lists every label.

## Retype a label (`y <addr> <c-type>`)

```text
─── stdin (keystrokes piped to glaurung repl) ───
y 0x4040 char[64]
save
q
─── glaurung repl stdout ───
>   0x4040 g_c2_endpoints: char[64]
> saved.
>
saving and exiting…
```

(Captured: [`_fixtures/02-strings-and-data/repl-retype.out`](../_fixtures/02-strings-and-data/repl-retype.out).)

`y` requires an existing label — it retypes, not creates. The
two-step `label set` then `y` matches Ghidra's "create then
retype" flow.

## List every label

```text
─── stdin (keystrokes piped to glaurung repl) ───
label
q
─── glaurung repl stdout ───
>   1 data labels:
    0x00004040  g_c2_endpoints: char[64]  (set_by=manual)
>
saving and exiting…
```

(Captured: [`_fixtures/02-strings-and-data/repl-label-list.out`](../_fixtures/02-strings-and-data/repl-label-list.out).)

`set_by=manual` is the highest-precedence tier — survives any
later analyzer pass.

## Provenance from the CLI

```bash
$ glaurung find demo.glaurung g_c2_endpoints --kind data
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
data        0x4040          g_c2_endpoints: char[64]
```

(Captured: [`_fixtures/02-strings-and-data/find-label.out`](../_fixtures/02-strings-and-data/find-label.out).)

Or every analyst-prefixed label:

```bash
$ glaurung find demo.glaurung g_ --kind data
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
data        0x4040          g_c2_endpoints: char[64]
```

(Captured: [`_fixtures/02-strings-and-data/find-data-prefix.out`](../_fixtures/02-strings-and-data/find-data-prefix.out).)

## Common patterns

| Question                               | Command                                                               |
|----------------------------------------|-----------------------------------------------------------------------|
| What strings does it reference?        | `strings-xrefs <db> --binary <bin> --used-only`                       |
| Filter to long strings (drop garbage)  | `strings-xrefs … --min-len 12`                                        |
| Strings as JSON                        | `strings-xrefs … --format json \| jq …`                               |
| Name a global                          | REPL `label set <addr> <name> [<type>]`                               |
| Retype a label                         | REPL `y <addr> <c-type>`                                              |
| List every label                       | REPL `label`                                                          |
| What's the global at 0x4040?           | `find <db> 0x4040 --kind data`                                        |

## Caveats / GAPs

- `--used-only` and the `uses`/`used_at` columns depend on the
  data-read xref index. For c2_demo this index isn't populated
  (same gap as §F). Tracked separately.
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
