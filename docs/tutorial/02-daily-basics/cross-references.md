# §F — Cross-references (`x` / `glaurung xrefs`)

The single most-pressed button in IDA / Ghidra: "show me everywhere
this function is called from / everywhere this address is read."
Glaurung's xrefs panel does the same in either CLI or REPL form.

## Setup

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
glaurung kickoff $BIN --db demo.glaurung
```

## CLI form: `glaurung xrefs <db> <va>`

Find every caller of `printf`. First locate it:

```bash
glaurung find demo.glaurung printf --kind function
```

```
function    0x1030          printf  (set_by=analyzer)
```

Now show all callers:

```bash
glaurung xrefs demo.glaurung 0x1030 --binary $BIN --direction to
```

```
dir   src_va        kind          function                          snippet
to    0x119c        call          c2_main                           call rip:[rip + 0xee94]
to    0x11d4        call          c2_main                           call rip:[rip + 0xee5c]
to    0x121e        call          c2_main                           call rip:[rip + 0xee12]
...
```

Six callers, all from `c2_main`. The `snippet` column shows the
calling instruction at each VA — useful for distinguishing the
specific call site.

## What the columns mean

- `dir` — `to` (someone calls this VA) or `from` (this VA calls
  someone). With `--direction both` you get both.
- `src_va` — the VA of the calling instruction.
- `kind` — `call`, `jump`, `data_read`, `data_write`,
  `struct_field`. Filter with `--kind`.
- `function` — the function whose body contains `src_va` (resolved
  via `function_names` so renames flow through).
- `snippet` — one-line disassembly at `src_va`.

## REPL form: `x` at the cursor

```bash
glaurung repl $BIN --db demo.glaurung
```

```
>>> g 0x1030
>>> x
  refs to 0x1030: 6
    call         0x119c  c2_main                  call rip:[rip + 0xee94]
    call         0x11d4  c2_main                  call rip:[rip + 0xee5c]
    ...
  refs from 0x1030: 0
```

Shorter format, capped at 12 rows per direction. The CLI version
(no cap) is better for grep-pipelining.

## Filter by kind

```bash
glaurung xrefs demo.glaurung 0x4040 --binary $BIN \
  --direction to --kind data_read
```

```
dir   src_va        kind          function                          snippet
to    0x118f        data_read     c2_main                           mov rax, rip:[rip + 0xeea0]
to    0x11ad        data_read     c2_main                           mov rax, rip:[rip + 0xee82]
```

Useful for: "every site that reads this global". Use `data_write`
for stores; `call` for function calls; `jump` for tail-calls.

## Pivot from CLI to REPL

The CLI is great for "what does the data look like?" The REPL is
great for "let me explore from here." A typical workflow:

```bash
$ glaurung xrefs demo.glaurung 0x1030 --binary $BIN
# (eyes on the output: the 3rd caller looks suspicious)

$ glaurung repl $BIN --db demo.glaurung
>>> g 0x121e
>>> d           # decompile the enclosing function
```

## Walk callees

```bash
glaurung xrefs demo.glaurung 0x1160 --binary $BIN --direction from
```

```
dir     src_va        kind          function                          snippet
from    0x117c        call          c2_main                           call rip:[rip + ...]   # printf
from    0x119c        call          c2_main                           call rip:[rip + ...]   # printf
from    0x121e        call          c2_main                           call rip:[rip + ...]   # snprintf
...
```

Every call out of `c2_main` (entry 0x1160). Useful for "what does
this function do?" without having to read the whole body.

## JSON for scripting

```bash
glaurung xrefs demo.glaurung 0x1030 --binary $BIN --format json | jq '.[0]'
```

```json
{
  "direction": "to",
  "src_va": 4508,
  "dst_va": 4144,
  "kind": "call",
  "src_function_va": 4448,
  "src_function": "c2_main",
  "snippet": "call rip:[rip + 0xee94]"
}
```

Pipeline-friendly. Use `jq` to count callers per function:

```bash
glaurung xrefs demo.glaurung 0x1030 --binary $BIN --format json \
  | jq -r '.[].src_function' \
  | sort | uniq -c
```

## Prototype hints in the body (#227)

When a function has a known prototype, `glaurung view` /
`render_decompile_with_names` annotates each call line:

```bash
glaurung view demo.glaurung 0x117c --binary $BIN --pane pseudo --pseudo-lines 6
```

```
── pseudocode (enclosing function) ──
fn c2_main {
    nop;
    rsp = (rsp - 432);
    ...
    printf@plt("Connecting to C2 server...\n");  // proto: int printf(const char * fmt, ...)
    ...
}
```

Glaurung knows `printf`'s prototype because `auto_load_stdlib`
populated `function_prototypes` with the libc bundle (#180). The
inline `// proto:` comment is purely advisory; it doesn't change
the analysis.

## Common patterns

**"What calls this?"**
`glaurung xrefs <db> <va> --direction to`

**"What does this call?"**
`glaurung xrefs <db> <va> --direction from`

**"Every read of this global?"**
`glaurung xrefs <db> <va> --kind data_read --direction to`

**"Every libc call site?"**
Find all the `@plt` entries with `glaurung find <db> @plt --kind function`,
then xrefs each.

**"Trace user input flow"**
Start at `read` / `recv`. xrefs --to gets the call site → enter
the calling function → trace where the buffer flows.

## What's next

- [§G `stack-frames.md`](stack-frames.md) — when xrefs aren't enough,
  drill into the stack frame
- [§I `searching.md`](searching.md) — the broader `glaurung find`
- [§Q `05-vulnerable-parser.md`](../03-walkthroughs/05-vulnerable-parser.md) —
  full vuln-hunting walkthrough using xrefs

→ [§G `stack-frames.md`](stack-frames.md)
