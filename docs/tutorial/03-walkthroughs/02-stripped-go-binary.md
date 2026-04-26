# §N — Walkthrough 2: stripped Go binary

The "Glaurung does what IDA can't out of the box" walkthrough. We
load a stripped Go binary and use the `gopclntab` walker (#212) to
recover **1801 fully-qualified function names** that the symbol
table doesn't expose.

If you've ever opened a stripped Go binary in IDA Pro and seen
nothing but `sub_<hex>` everywhere, this is the chapter that shows
you what's possible without an external plugin.

## Sample

```bash
BIN=samples/binaries/platforms/linux/amd64/export/go/hello-go
file $BIN
```

```
ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
statically linked, Go BuildID=..., stripped
```

Key callouts:

- **statically linked** — the entire Go runtime is embedded.
- **stripped** — no regular symbol table.
- **Go BuildID** — the Go toolchain stamps this; how `file` even
  knows it's Go.

The binary is a 1.4 MB stripped Go program. Out of IDA's box, you'd
see hundreds of `sub_<hex>` functions and no clue how to navigate.

## Phase 1: Triage

```bash
glaurung triage $BIN | head -10
```

The triage layer recognises Go from imports / runtime markers but
doesn't yet recover names — that's `kickoff`'s job.

## Phase 2: Load (`kickoff`)

```bash
glaurung kickoff $BIN --db go.glaurung
```

```markdown
# Kickoff analysis — hello-go

- format: **ELF**, arch: **x86_64**, size: **1425560** bytes
- entry: **0x46d1e0**

## Functions
- discovered: **16** (with blocks: 16, named: 0)
- callgraph edges: **0**
- name sources: gopclntab=1801

## Type system
- stdlib prototypes loaded: **192**
- DWARF types imported: **0**
- stack slots discovered: **160**
- types propagated: **0**
- auto-struct candidates: **32**

_completed in 5261 ms_
```

The line that matters: **`name sources: gopclntab=1801`**.

The CFG analyzer found 16 functions in the .text it walked
(reachable from the entry), but the gopclntab walker scanned the
runtime's `pclntab` section and recovered names for **all 1801
functions** the binary contains — every user function (`main.*`),
every Go runtime function (`runtime.*`), every standard library
function (`internal/abi.*`, `bytes.*`, etc).

## Phase 3: Function ID

Where's `main.main`? In Go, the user's `main` package is
namespaced.

```bash
glaurung find go.glaurung "main.main$" --regex --kind function
```

```
function    0x4934e0        main.main  (set_by=gopclntab)
```

The `set_by=gopclntab` tag means the name came from the runtime's
function table — not from a symbol table (there isn't one) and not
from the analyst.

What other `main.*` functions are there?

```bash
glaurung find go.glaurung "main\." --regex --kind function | head
```

```
function    0x493180        main.(*Application).String     (set_by=gopclntab)
function    0x493220        main.worker                     (set_by=gopclntab)
function    0x493380        main.riskyOperation             (set_by=gopclntab)
function    0x493440        main.riskyOperation.func1       (set_by=gopclntab)
function    0x4934e0        main.main                       (set_by=gopclntab)
function    0x493b60        main.main.func1                 (set_by=gopclntab)
function    0x493ba0        main.main.gowrap1               (set_by=gopclntab)
function    0x493c00        main.main.func2                 (set_by=gopclntab)
function    0x493c20        main.mapSlice[go.shape.int,go.shape.int]  (set_by=gopclntab)
...
```

This is what the binary actually contains — not just `main.main`,
but the goroutine wrappers (`gowrap1`), defer-statement wrappers
(`deferwrap1`), closures (`func1` / `func2`), and a generic
function (`mapSlice[go.shape.int,go.shape.int]`) that the Go
toolchain emitted.

This is rich detail. None of it is visible without a Go-specific
parser.

## Phase 4: String/logic trace

What does the program do? Look at `main.main`:

```bash
glaurung view go.glaurung 0x4934e0 --binary $BIN --pane pseudo --pseudo-lines 30
```

The body is large because Go inlines a lot of runtime calls. Skim
for:

- **Calls into the user's package**: `main.worker`,
  `main.riskyOperation` — those are the analyst's targets.
- **Goroutine launches**: any call to `runtime.newproc` is `go ...`
  in source.
- **Defer statements**: `runtime.deferproc` calls.

For now, just confirm we can navigate:

```bash
glaurung view go.glaurung 0x493220 --binary $BIN --pane pseudo --pseudo-lines 8
```

This is `main.worker`. With KB-aware rendering enabled, calls into
other recovered names show up by name instead of by VA.

## Phase 5: Verify

Confirm the recovered namespace makes sense — `runtime.gopanic`
should exist (every Go binary has it) and so should the standard
library:

```bash
glaurung find go.glaurung "runtime.gopanic$" --regex --kind function
```

```
function    0x464b80        runtime.gopanic  (set_by=gopclntab)
```

```bash
glaurung find go.glaurung "internal/abi.Kind.String" --kind function
```

```
function    0x401000        internal/abi.Kind.String  (set_by=gopclntab)
```

Both present. The recovery is comprehensive — every Go function
the runtime needs at panic / reflection / scheduler time is named.

## Phase 6: Annotate

The Go-recovered names are fully qualified — `main.main`,
`main.worker.deferwrap1` — so there's not much to rename for clarity.
What's worth annotating:

1. **Bookmark the user's package entries** for fast navigation:

```bash
glaurung bookmark go.glaurung add 0x4934e0 "main.main entry"
glaurung bookmark go.glaurung add 0x493220 "main.worker — goroutine body"
glaurung bookmark go.glaurung add 0x493380 "main.riskyOperation — investigate"
```

2. **Comment a `runtime.deferproc` call site** with the
   user-visible defer it represents:

```bash
glaurung repl $BIN --db go.glaurung
>>> g 0x493440
>>> c "deferred recovery in main.riskyOperation"
```

3. **If you rename a function**, the manual rename wins over
   gopclntab:

```
>>> g 0x493220
>>> n process_request    # take precedence over main.worker
  0x493220 → process_request
```

`set_by=manual` always beats `set_by=gopclntab` (see
[`reference/set-by-precedence.md`](../reference/set-by-precedence.md)).
A subsequent `kickoff` re-run won't restore the gopclntab name — but
`glaurung undo` will.

## What you've done

1. **Triage** confirmed: stripped Go binary.
2. **Load (kickoff)** ran the Go-specific recovery: 1801 names
   from the runtime's pclntab.
3. **Function ID** via `glaurung find` distinguished user package
   (`main.*`) from runtime (`runtime.*`) and stdlib
   (`internal/abi.*`, `bytes.*`).
4. **String/logic trace** via `glaurung view` walked the recovered
   names, with cross-function calls rendering by recovered name.
5. **Verify** confirmed canonical Go runtime names like
   `runtime.gopanic` are present — comprehensive recovery, not just
   a sample.
6. **Annotate** demonstrated bookmarks + the manual-overrides-gopclntab
   precedence rule.

## What's different from §M

§M (hello-c-clang) had **debug info** — every name came from the
symbol table. §N (this chapter) has **no debug info** — every name
came from the runtime's own metadata, parsed by Glaurung.

This is the core Glaurung edge: format-specific recovery passes
plug into the same `function_names` table the daily-basics floor
reads from. `glaurung xrefs`, `glaurung view`, `glaurung find`,
the REPL `n` rename — all work the same on a stripped Go binary
as on a debug-info C binary.

## Caveats

- Older Go versions (pre-1.18) used a different pclntab format —
  Glaurung supports 1.18+ today (the 0xfffffff0 / 0xfffffff1
  magics covering ~99% of binaries built in the last few years).
  Older pclntab is filed for v1.
- LuaJIT / Go-arm64 / Go-Mach-O have minor format variants we
  haven't tested exhaustively. File samples to the parity tracker
  if you find one that doesn't recover cleanly.

## What's next

- [§O `03-managed-dotnet-pe.md`](03-managed-dotnet-pe.md) — same
  story for .NET / Mono PEs, but via ECMA-335 metadata tables.
- [§P `04-jvm-classfile.md`](04-jvm-classfile.md) — JVM bytecode
  triage; same managed-runtime philosophy.
- [§S `07-malware-c2-demo.md`](07-malware-c2-demo.md) — flagship
  malware analysis, which uses gopclntab recovery on Go-built
  malware.

→ [§O `03-managed-dotnet-pe.md`](03-managed-dotnet-pe.md)
