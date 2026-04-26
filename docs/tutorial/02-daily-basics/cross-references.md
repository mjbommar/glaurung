# §F — Cross-references (`x` / `glaurung xrefs`)

The single most-pressed button in IDA / Ghidra: "show me everywhere
this function is called from / everywhere this address is read."
Glaurung's xrefs panel does the same in either CLI or REPL form.

> **Verified output.** Every block in this chapter is captured by
> `scripts/verify_tutorial.py` against
> [`hello-c-clang-debug`](../reference/sample-corpus.md#hello-c-clang-debug)
> and stored under
> [`_fixtures/02-cross-references/`](../_fixtures/02-cross-references/).
> Same binary as §B and §M, so addresses match.

## Setup

```bash
$ BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
$ glaurung kickoff $BIN --db demo.glaurung
```

> **Why hello-c-clang here, not c2_demo?** The c2_demo binary's
> kickoff path doesn't currently populate the xref index for PLT
> calls — `glaurung xrefs` returns no rows on it. hello-c-clang
> exercises the full xref index. Tracked as a follow-up against
> kickoff coverage.

## CLI form: `glaurung xrefs <db> <va>`

Find every caller of `print_sum`. First locate it:

```bash
$ glaurung find demo.glaurung print_sum --kind function
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
function    0x11d0          print_sum  (set_by=analyzer)
```

(Captured: [`_fixtures/02-cross-references/find-print-sum.out`](../_fixtures/02-cross-references/find-print-sum.out).)

Now show all callers:

```bash
$ glaurung xrefs demo.glaurung 0x11d0 --binary $BIN --direction to
```

```text
dir   src_va       kind          function                         snippet
-------------------------------------------------------------------------
to    0x1150       call          main                             push rbp
to    0x117b       call          sub_117b                         mov rbp:[rbp - 0x18], 0x0
```

(Captured: [`_fixtures/02-cross-references/xrefs-to-print-sum.out`](../_fixtures/02-cross-references/xrefs-to-print-sum.out).)

Two callers: `main` (0x1150) and the anonymous helper `sub_117b`.
The `snippet` column shows the calling instruction at each
src_va — useful for distinguishing call sites.

> **Cross-check with §M.** This is the same xref result Phase 5
> of [§M `01-hello-c-clang.md`](../03-walkthroughs/01-hello-c-clang.md)
> uses to surface that `print_sum` has *two* callers, not one,
> even though the source code looks like a single call site.

## What the columns mean

- `dir` — `to` (someone calls this VA) or `from` (this VA calls
  someone). With `--direction both` you get both.
- `src_va` — the VA of the calling instruction.
- `kind` — `call`, `jump`, `data_read`, `data_write`,
  `struct_field`. Filter with `--kind`.
- `function` — the function whose body contains `src_va`
  (resolved via `function_names`, so renames flow through).
- `snippet` — one-line disassembly at `src_va`.

## REPL form: `x` at the cursor

```text
─── stdin (keystrokes piped to glaurung repl) ───
g 0x11d0
x
q
─── glaurung repl stdout ───
>   0x11d0  print_sum  (set_by=analyzer)
0x11d0>   refs to 0x11d0: 2
    call        0x1150  main                      push rbp
    call        0x117b  sub_117b                  mov rbp:[rbp - 0x18], 0x0
  refs from 0x11d0: 0
0x11d0>
saving and exiting…
```

(Captured: [`_fixtures/02-cross-references/repl-x.out`](../_fixtures/02-cross-references/repl-x.out).)

The REPL form prints both directions in one block, capped per
direction. `refs from 0x11d0: 0` is correct — `print_sum` calls
`printf@plt` but the PLT entry isn't a registered function in
this kickoff, so the from-edge isn't recorded for the table.

## Walking from a function entry: `--direction from`

```bash
$ glaurung xrefs demo.glaurung 0x1150 --binary $BIN --direction from
```

```text
dir   src_va       kind          function                         snippet
-------------------------------------------------------------------------
from  0x1150       call          main                             push rbp
from  0x1150       call          main                             push rbp
```

(Captured: [`_fixtures/02-cross-references/xrefs-from-main.out`](../_fixtures/02-cross-references/xrefs-from-main.out).)

Two outgoing calls, both rendered with the source function (`main`)
in the function/snippet columns. The table format omits the
target VA — to see where each call goes, switch to JSON:

```bash
$ glaurung xrefs demo.glaurung 0x11d0 --binary $BIN --direction to --format json
```

```json
[
  {"direction":"to","src_va":4432,"dst_va":4560,"kind":"call",
   "src_function_va":4432,"src_function":"main","snippet":"push rbp"},
  {"direction":"to","src_va":4475,"dst_va":4560,"kind":"call",
   "src_function_va":4475,"src_function":"sub_117b",
   "snippet":"mov rbp:[rbp - 0x18], 0x0"}
]
```

(Captured: [`_fixtures/02-cross-references/xrefs-json.out`](../_fixtures/02-cross-references/xrefs-json.out).)

The JSON form has both `src_va` and `dst_va` — necessary for
scripted analysis. `dst_va: 4560` decodes to `0x11d0` (print_sum).

## Filter by kind

```bash
$ glaurung xrefs demo.glaurung 0x1150 --binary $BIN \
    --direction from --kind call
```

```text
dir   src_va       kind          function                         snippet
-------------------------------------------------------------------------
from  0x1150       call          main                             push rbp
from  0x1150       call          main                             push rbp
```

(Captured: [`_fixtures/02-cross-references/xrefs-from-main-call.out`](../_fixtures/02-cross-references/xrefs-from-main-call.out).)

Same shape because every outgoing edge from `main` happens to be
a `call`. `--kind data_read` / `data_write` would filter to data
references; `--kind jump` to control-flow jumps.

## `--direction both`

```bash
$ glaurung xrefs demo.glaurung 0x11d0 --binary $BIN --direction both
```

```text
dir   src_va       kind          function                         snippet
-------------------------------------------------------------------------
to    0x1150       call          main                             push rbp
to    0x117b       call          sub_117b                         mov rbp:[rbp - 0x18], 0x0
```

(Captured: [`_fixtures/02-cross-references/xrefs-both.out`](../_fixtures/02-cross-references/xrefs-both.out).)

`both` = `to` ∪ `from`. Here it matches the `to`-only table
because `print_sum` has no recorded outgoing edges in this
kickoff.

## Pivot from CLI to REPL

The CLI is great for "what does the data look like?" The REPL is
great for "let me explore from here." A typical workflow:

```bash
$ glaurung xrefs demo.glaurung 0x11d0 --binary $BIN --direction to
# (eyes on the output: sub_117b is the surprising caller)

$ glaurung repl $BIN --db demo.glaurung
>>> g 0x117b      # jump to the surprising caller
>>> d             # decompile the enclosing function
```

## JSON for scripting

Pipe to `jq` to count callers per function:

```bash
$ glaurung xrefs demo.glaurung 0x11d0 --binary $BIN --format json \
    | jq -r '.[].src_function' \
    | sort | uniq -c
```

```text
   1 main
   1 sub_117b
```

(Same data, aggregated.)

## Common patterns

| Question                        | Command                                                        |
|---------------------------------|----------------------------------------------------------------|
| What calls this?                | `xrefs <db> <va> --direction to`                               |
| What does this call?            | `xrefs <db> <va> --direction from`                             |
| Every read of this global?      | `xrefs <db> <va> --kind data_read --direction to`              |
| Every callsite as JSON?         | `xrefs <db> <va> --format json`                                |
| Caller histogram?               | `xrefs … --format json \| jq -r '.[].src_function' \| sort -u` |

## What's next

- [§G `stack-frames.md`](stack-frames.md) — when xrefs aren't enough,
  drill into the stack frame
- [§I `searching.md`](searching.md) — the broader `glaurung find`
- [§Q `05-vulnerable-parser.md`](../03-walkthroughs/05-vulnerable-parser.md) —
  full vuln-hunting walkthrough using xrefs

→ [§G `stack-frames.md`](stack-frames.md)
