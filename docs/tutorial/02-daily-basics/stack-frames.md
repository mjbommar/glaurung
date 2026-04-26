# §G — Stack frames (`l` / `glaurung frame`)

The frame editor — IDA's "Stack frame" window in CLI form. List
every slot a function uses, see provenance for each, rename and
retype inline.

## Setup

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
glaurung kickoff $BIN --db demo.glaurung
```

## CLI form

```bash
glaurung frame demo.glaurung 0x1160 --binary $BIN list
```

The first argument after the action is the function entry VA. (Use
`glaurung find <db> <name> --kind function` to find one.)

## Discover slots

If the slot table is empty (because `kickoff` only does a sample
of functions during the per-function lift), populate it:

```bash
glaurung frame demo.glaurung 0x1160 --binary $BIN discover
```

```
discovered 18 stack-frame slot(s) in fn@0x1160
```

Then list:

```bash
glaurung frame demo.glaurung 0x1160 --binary $BIN list
```

```
  offset  name                      type                       size  uses  set_by
--------  ------------------------  ------------------------  -----  ----  -------
 -0x1b0  var_1b0                   (unknown)                            2  auto
 -0x140  var_140                   (unknown)                  112      3  auto
 -0x010  var_10                    (unknown)                  304      1  auto
 +0x010  ret                       (unknown)                   32      0  auto
```

Columns:

- `offset` — signed offset from the frame pointer (typically rbp on
  x86_64). Negative = local; positive = arg / saved-reg / red-zone.
- `name` — analyzer-assigned (`var_<hex>` for locals, `arg_<hex>` for
  positive offsets) or analyst-renamed.
- `type` — `c_type` if known. `(unknown)` is the default.
- `size` — gap to the next slot (a heuristic — the actual storage
  size depends on how the slot is accessed). See
  [#239 GAP](../../architecture/IDA_GHIDRA_PARITY.md) for tracking
  explicit sizes.
- `uses` — how many times the discoverer saw the slot referenced.
- `set_by` — provenance: `auto`, `manual`, `propagated`, `dwarf`.

## Rename a slot

```bash
glaurung frame demo.glaurung 0x1160 --binary $BIN rename -0x1b0 url_buffer
```

```
  fn@0x1160 -0x1b0 -> url_buffer
```

## Retype a slot

```bash
glaurung frame demo.glaurung 0x1160 --binary $BIN retype -0x1b0 "char[256]"
```

```
  fn@0x1160 -0x1b0 url_buffer: char[256]
```

Both writes are `set_by=manual` and enter the undo log (#228).

## Look at the function with named slots

```bash
glaurung view demo.glaurung 0x1160 --binary $BIN --pane pseudo --pseudo-lines 8
```

```
── pseudocode (enclosing function) ──
fn c2_main {
    // ── locals (from KB) ───────────────────────
    char url_buffer[256];          // -0x1b0  set_by=manual
    // ───────────────────────────────────────────
    nop;
    rsp = (rsp - 432);
    *&[rsp + 0x18] = arg0;
    ...
    snprintf@plt(&url_buffer, 256, "http://%s:8080%s", ...);
    ...
}
```

The slot now appears as a real C declaration in the typed-locals
prelude (#194), and `(rbp - 0x1b0)` references in the body render
as `url_buffer` (#196).

## REPL form

```bash
glaurung repl $BIN --db demo.glaurung
```

```
>>> g 0x1160
>>> l
  18 vars in fn@0x1160:
    -0x1b0  url_buffer    : char[256]  (uses=2, by=manual)
    -0x140  var_140                    (uses=3, by=auto)
    -0x10   var_10                     (uses=1, by=auto)
    ...
>>> locals rename -0x140 cmd_buffer
  renamed -0x140 -> cmd_buffer
```

## Type propagation lights up auto types

When a stack slot flows into a typed function call, the propagation
pass (#172 / #195) infers the type:

```
>>> propagate
  propagated types into 8 stack slots across 1 functions
>>> l
  18 vars in fn@0x1160:
    -0x1b0  url_buffer    : char[256]   (uses=2, by=manual)
    -0x140  cmd_buffer    : char *      (uses=3, by=propagated)
    -0x10   sockfd        : int         (uses=1, by=propagated)
    ...
```

The `set_by=propagated` rows came from the prototype bundle —
e.g. the slot at `-0x10` flowed into `recv(int sockfd, ...)` so
`sockfd` got typed `int`.

`set_by=manual` rows are never overwritten by propagation (manual
always wins — see
[`reference/set-by-precedence.md`](../reference/set-by-precedence.md)).

## JSON for scripting

```bash
glaurung frame demo.glaurung 0x1160 --binary $BIN list --format json | jq '.[0]'
```

```json
{
  "function_va": 4448,
  "offset": -432,
  "name": "url_buffer",
  "c_type": "char[256]",
  "use_count": 2,
  "set_by": "manual"
}
```

## Common patterns

**"What locals does this function have?"**
`glaurung frame <db> <fn-va> list`

**"Auto-discover slots if I haven't yet"**
`glaurung frame <db> <fn-va> discover`

**"Type a slot based on its use site"**
Run `glaurung repl > propagate` instead of typing by hand — the
propagation pass figures out types from typed call sites.

**"Make this slot a struct"**
Define the type with `glaurung repl > struct ...` then retype:
`glaurung frame <db> <fn-va> retype <offset> "MyStruct"`.

## What's next

- [§E `naming-and-types.md`](naming-and-types.md) — function-level
  rename + retype
- [§F `cross-references.md`](cross-references.md) — caller analysis
- [§S `07-malware-c2-demo.md`](../03-walkthroughs/07-malware-c2-demo.md) —
  full c2_demo walkthrough including stack-frame retype

→ [§H `strings-and-data.md`](strings-and-data.md)
