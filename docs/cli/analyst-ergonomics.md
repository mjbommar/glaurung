# Analyst-ergonomics CLI (PDB naming, KB disasm, locks, module groups)

These commands remove per-session re-derivation of things glaurung already
owns (symbols, disasm, lock primitives) and make every analysis declare what
it did *not* model. Origin + rationale: `docs/campaigns/analyst-ergonomics-2026-06-DIFF.md`.

A cross-cutting rule: each analysis here ends with a **coverage footer**
(`glaurung.llm.coverage.CoverageFooter`) listing the facts it established and
the caveats/limits it hit (unresolved indirect calls, primitives not modeled,
intraprocedural scope, ...). Partial coverage must read as partial -- a tool
that models only part of the problem and stays silent about it produces
confidently-wrong findings.

## PDB symbolization is on by default (`kickoff`)

`kickoff` resolves a GUID-matching Microsoft PDB and writes its public symbol
names into `function_names` (provenance `pdb`) automatically -- no flag needed.
A stripped Windows driver should never come back all `sub_XXXX` when a PDB is
resolvable.

```
glaurung kickoff driver.sys --db driver.glaurung
```

- Cache dir resolution: `$GLAURUNG_PDB_CACHE` -> a local `_NT_SYMBOL_PATH`
  directory -> `~/.cache/glaurung/symbols`. Override with `--pdb-cache DIR`.
- `--no-fetch-pdb` uses only what is already cached (no symbol-server fetch).
- `--no-pdb` disables symbolization entirely.
- `--pdb-struct NAME` (repeatable) imports that struct's layout into the type
  DB. Note: Microsoft *public* PDBs carry function publics but generally NOT
  private struct layouts, so internal driver structs usually report as missing
  (reconstruct them with the struct-recovery passes instead).

## KB-aware disassembly (`disasm --db --function`)

Disassemble one function from a `.glaurung` project with call targets and
RIP-relative references symbol-resolved, bounds taken from the discovered
function set.

```
glaurung disasm driver.sys --db driver.glaurung --function VidSchiCheckPendingDeviceCommand
glaurung disasm driver.sys --db driver.glaurung --function 0x140013f24 --json
```

Annotations: direct `call`/`jmp` targets -> `function_names`; `call [rip+slot]`
-> IAT import name; RIP-relative data -> `data_labels`. Intra-function jumps are
not treated as unresolved. The footer reports resolved/unresolved counts.

## Lock / synchronization-state (`locks`)

Primitive-complete, CFG-aware lock inventory for one function.

```
glaurung locks driver.sys --db driver.glaurung --function VidSchSignalSyncObjectsFromCpu
```

- Models BOTH raw kernel APIs (`Ke*`/`Ex*AcquireXxx`/`ReleaseXxx`) AND C++ RAII
  wrappers (`Acquire@AcquireSpinLock`, `DXGPUSHLOCK`, `DXGFASTMUTEX`, ...). A
  tracer that sees only the raw imports silently misses wrapper-acquired locks.
- Resolves the lock OBJECT for each op (through the RAII guard indirection and
  by byte-decoding `add rcx, imm` offsets the renderer drops).
- **CFG-aware held-lock dataflow** over glaurung's own basic-block graph:
  reports both `must` (held on every path == provably protected) and `may`
  (held on some path) at each call site, flagging `[PATH-DISCREPANCY: may>must]`.
- Coverage footer lists modeled primitives, unresolved indirect calls, and any
  call target that LOOKS lock-like but was not classified (a modeling gap).
- Scope is intraprocedural (a lock acquired by a caller is not modeled) -- this
  is stated in the footer.

## Cross-binary module groups (`group`)

Driver families share pools; an out-of-bounds write in one module can corrupt
an allocation owned by another. `group` reports the pool TAGS shared across
members (the cross-module corruption surface).

```
glaurung group --member dxgmms2=dxgmms2.sys --member dxgmms1=dxgmms1.sys
```

Tags are the `Tag` argument to `ExAllocatePoolWithTag` / `ExAllocatePool2`.
A shared tag implies a shared pool surface, NOT a proven overflow path -- the
footer says so, and notes that lookaside lists / segment-heap buckets are not
modeled.

## `diff` relocation-only flag

`glaurung diff --json` now tags each `changed` row with `relocation_only`:
true when every block matched structurally (`similarity >= 0.999`), i.e. the
delta is relocation / block-reordering noise rather than a real instruction
change. Pure relocations already collapse to status `same` (the structural
fingerprint masks call/branch/global targets); this flag names the residual
noise so patch-diff consumers can drop it instead of re-deriving the judgment.
The relocation-aware comparison itself is `structural_fingerprint` -- not a
per-consumer reimplementation.

## Known disassembler limitation (affects offset/constant analysis)

The disassembler currently drops standalone immediate operands for some ALU
instructions (`add rcx, 0x7c0` renders as `add rcx`; the raw bytes survive).
Memory-operand displacements and `mov reg, imm` immediates are unaffected.
Analyses that need those immediates (lock offsets here) byte-decode them as a
workaround; the proper fix is in the operand formatter. See Finding A in the
campaign DIFF.
