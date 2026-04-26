# §G — Stack frames (`l` / `glaurung frame`)

The frame editor — IDA's "Stack frame" window in CLI form. List
every slot a function uses, see provenance for each, rename and
retype inline.

> **Verified output.** Every block is captured by
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/02-stack-frames/`](../_fixtures/02-stack-frames/).

## Setup

```bash
$ BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
$ glaurung kickoff $BIN --db demo.glaurung
```

```text
# Kickoff analysis — c2_demo-clang-O0
- format: **ELF**, arch: **x86_64**, size: **16456** bytes
- entry: **0x1070**
- discovered: **6** functions
- stack slots discovered: **90**
- types propagated: **18**
- stdlib prototypes loaded: **192**
```

(Captured: [`_fixtures/02-stack-frames/kickoff.out`](../_fixtures/02-stack-frames/kickoff.out).)

90 slots across 6 functions, 18 already typed by the propagation
pass.

## CLI form: `glaurung frame <db> <fn-va> list`

```bash
$ glaurung frame demo.glaurung 0x1160 list --binary $BIN
```

```text
  offset  name                      type                       size  uses  set_by
---------------------------------------------------------------------------------
-0x1b0  var_1b0                   void *                              2  propagated
-0x180  var_180                   (unknown)                    48     2  auto
-0x178  var_178                   (unknown)                     8     1  auto
-0x170  var_170                   (unknown)                     8     1  auto
-0x168  var_168                   (unknown)                     8     1  auto
-0x164  var_164                   (unknown)                     4     1  auto
-0x160  var_160                   (unknown)                     4     1  auto
-0x158  var_158                   (unknown)                     8     1  auto
-0x150  var_150                   (unknown)                     8     1  auto
-0x148  var_148                   (unknown)                     8     1  auto
-0x140  var_140                   void *                        8     1  propagated
-0x110  var_110                   char *                       48     2  propagated
-0x010  var_10                    (unknown)                   256     1  auto
-0x008  var_8                     (unknown)                     8     1  auto
-0x004  var_4                     (unknown)                     4     1  auto
```

(Captured: [`_fixtures/02-stack-frames/frame-list-before.out`](../_fixtures/02-stack-frames/frame-list-before.out).)

15 slots already populated by the kickoff lift. Three are typed
`set_by=propagated` — the propagation pass walked the libc
prototype graph and inferred `void *` / `char *` from how each
slot flows into call sites like `snprintf` / `memcpy`.

Columns:

- `offset` — signed offset from the frame pointer (rbp on x86_64).
  Negative = local; positive = arg / saved-reg / red-zone.
- `name` — analyzer-assigned (`var_<hex>`) or analyst-renamed.
- `type` — `c_type` if known. `(unknown)` is the default.
- `size` — gap to the next slot (heuristic — actual storage size
  depends on access width). Tracked as
  [#239 GAP](../../architecture/IDA_GHIDRA_PARITY.md).
- `uses` — how many times the discoverer saw the slot referenced.
- `set_by` — provenance: `auto`, `manual`, `propagated`, `dwarf`.

## `discover` — re-run the slot finder

If the slot table is empty (or you want to re-run discovery
explicitly), use `discover`:

```bash
$ glaurung frame demo.glaurung 0x1160 discover --binary $BIN
```

```text
discovered 15 stack-frame slot(s) in fn@0x1160
```

(Captured: [`_fixtures/02-stack-frames/frame-discover.out`](../_fixtures/02-stack-frames/frame-discover.out).)

Now list:

```bash
$ glaurung frame demo.glaurung 0x1160 list --binary $BIN
```

```text
  offset  name                      type                       size  uses  set_by
---------------------------------------------------------------------------------
-0x1b0  var_1b0                   (unknown)                           2  auto
-0x180  var_180                   (unknown)                    48     2  auto
-0x178  var_178                   (unknown)                     8     1  auto
-0x170  var_170                   (unknown)                     8     1  auto
-0x168  var_168                   (unknown)                     8     1  auto
-0x164  var_164                   (unknown)                     4     1  auto
-0x160  var_160                   (unknown)                     4     1  auto
-0x158  var_158                   (unknown)                     8     1  auto
-0x150  var_150                   (unknown)                     8     1  auto
-0x148  var_148                   (unknown)                     8     1  auto
-0x140  var_140                   (unknown)                     8     1  auto
-0x110  var_110                   (unknown)                    48     2  auto
-0x010  var_10                    (unknown)                   256     1  auto
-0x008  var_8                     (unknown)                     8     1  auto
-0x004  var_4                     (unknown)                     4     1  auto
```

(Captured: [`_fixtures/02-stack-frames/frame-list-after.out`](../_fixtures/02-stack-frames/frame-list-after.out).)

> **Behavior to know.** `discover` rebuilds the slot table from
> the lifted disasm — and that rebuild *resets* `set_by=propagated`
> types back to `auto`. The propagation pass needs a separate
> re-run (REPL `propagate`) to re-infer them. **Manual writes
> survive** discover (they're highest precedence) but propagated
> types do not.

## `rename` and `retype`

```bash
$ glaurung frame demo.glaurung 0x1160 rename -0x1b0 url_buffer --binary $BIN
```

```text
  fn@0x1160 -0x1b0 -> url_buffer
```

(Captured: [`_fixtures/02-stack-frames/frame-rename.out`](../_fixtures/02-stack-frames/frame-rename.out).)

```bash
$ glaurung frame demo.glaurung 0x1160 retype -0x1b0 "char[256]" --binary $BIN
```

```text
  fn@0x1160 -0x1b0 url_buffer: char[256]
```

(Captured: [`_fixtures/02-stack-frames/frame-retype.out`](../_fixtures/02-stack-frames/frame-retype.out).)

Both writes are `set_by=manual` and enter the undo log (#228).
Confirm:

```bash
$ glaurung frame demo.glaurung 0x1160 list --binary $BIN
```

```text
  offset  name                      type                       size  uses  set_by
---------------------------------------------------------------------------------
-0x1b0  url_buffer                char[256]                           2  manual
-0x180  var_180                   (unknown)                    48     2  auto
…
```

(Captured: [`_fixtures/02-stack-frames/frame-list-final.out`](../_fixtures/02-stack-frames/frame-list-final.out).)

The first row now reads `url_buffer : char[256]  set_by=manual`.

## JSON for scripting

```bash
$ glaurung frame demo.glaurung 0x1160 list --binary $BIN --format json | jq '.[0]'
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

(Captured: [`_fixtures/02-stack-frames/frame-list-json.out`](../_fixtures/02-stack-frames/frame-list-json.out)
— full array of 15 slot objects.)

`function_va` and `offset` are byte-encoded ints; convert with
`printf "%#x" 4448` (= `0x1160`) or in jq with
`(.function_va / 16 | floor)` etc.

## REPL form

The `l` / `locals` keystroke shows the slots for the cursor's
enclosing function. See §D `repl-tour.md` "Inspect locals — `l`"
and §E `naming-and-types.md` "Stack-var rename" for live REPL
captures.

## Type propagation lights up auto types

After a manual rename, run the propagator to re-derive types
elsewhere in the function:

```text
>>> propagate
  propagated types into N stack slots across M functions
```

The `set_by=propagated` rows come from the prototype bundle —
e.g. a slot that flows into `recv(int sockfd, …)` gets typed
`int`. `set_by=manual` rows are never overwritten by propagation
(manual always wins — see
[`reference/set-by-precedence.md`](../reference/set-by-precedence.md)).

## Common patterns

| Question                                | Command                                                      |
|-----------------------------------------|--------------------------------------------------------------|
| What locals does this function have?    | `glaurung frame <db> <fn-va> list --binary <bin>`            |
| Re-discover slots                       | `glaurung frame <db> <fn-va> discover --binary <bin>`        |
| Name a slot                             | `glaurung frame <db> <fn-va> rename <off> <name> --binary <bin>` |
| Type a slot                             | `glaurung frame <db> <fn-va> retype <off> <c-type> --binary <bin>` |
| Type many slots automatically           | REPL `propagate`                                             |

## What's next

- [§E `naming-and-types.md`](naming-and-types.md) — function-level
  rename + retype
- [§F `cross-references.md`](cross-references.md) — caller analysis
- [§S `07-malware-c2-demo.md`](../03-walkthroughs/07-malware-c2-demo.md) —
  full c2_demo walkthrough including stack-frame retype

→ [§H `strings-and-data.md`](strings-and-data.md)
