# Glaurung analyst-ergonomics campaign (2026-06)

Source: dxgmms2 VidSch sync-point crash investigation (agentic-security-bot,
2026-06-01). Friction + two near-miss false findings during that session
motivated these changes. Branch: `glaurung-analyst-ergonomics-2026-06`.

The recurring theme: analyses (and the analyst) keep re-deriving things glaurung
already owns (symbols, disasm, lock primitives), and tools emit confident output
without flagging what they did NOT model -- which produced a false "wrong-lock
double-free" lead this session. Fixes below either remove re-derivation or make
coverage limits explicit.

## Items + status

| # | Item | Status |
|---|------|--------|
| 1 | PDB symbolization on by default in kickoff -> function_names | DONE + tested |
| 2 | KB-aware `glaurung disasm --db --function <name\|va>` w/ symbol annotation | DONE + tested |
| C1| Coverage/assumptions footer helper (`glaurung.llm.coverage`), wired into #2/#3/#5 | DONE + tested |
| 3 | `glaurung locks` -- primitive-complete (raw Ke*/Ex* + RAII wrappers) + **CFG-aware must/may held-lock dataflow** over glaurung's own basic-block graph + lock-object resolution + coverage footer (incl. unmodeled lock-like targets) | DONE + tested |
| 4 | PDB struct-layout import wired into kickoff (`--pdb-struct`) | DONE -- honest missing-layout note (Finding B: public PDBs lack layouts) |
| 5 | `glaurung group` -- cross-binary shared-pool-tag reasoning for driver families | DONE + tested |
| C2| Patch diff-explain (ASB): drop layout-shift FPs (`--no-layout-filter` to disable) + mark lifted-C UNVERIFIED | DONE + tested (in agentic-security-bot) |

All seven items implemented and tested (16 glaurung tests + 3 ASB tests).
#3 CFG-awareness uses glaurung's authoritative `basic_blocks` successor/
predecessor edges (NOT a reconstruction); it reports BOTH must-held
(intersection over paths == provably held everywhere) and may-held (union ==
held on some path), flagging `[PATH-DISCREPANCY: may>must]`. Verified: on
`VidSchSignalSyncObjectsFromCpu` the free-reaching inner call is
`must={+0x7c0}` -- the exact proof the session's wrapper-blind tracer failed to
produce.

### What landed (files)

- `python/glaurung/pdb_fetch.py`: `default_cache_dir()` ($GLAURUNG_PDB_CACHE / a
  local _NT_SYMBOL_PATH dir / ~/.cache/glaurung/symbols).
- `python/glaurung/llm/kb/kickoff.py` + `cli/commands/kickoff.py`: PDB naming ON
  by default (`pdb=True`, `fetch_pdb=True`), `--no-pdb` / `--no-fetch-pdb`,
  `--pdb-struct NAME` (repeatable). Verified: dxgmms2 kickoff now names 2302
  functions by default (was 0/`sub_XXXX`), incl. the symbols hand-bridged in the
  motivating session.
- `python/glaurung/llm/coverage.py`: `CoverageFooter` (C1).
- `python/glaurung/llm/kb/function_disasm.py` + `cli/commands/disasm.py`:
  `disasm --db --function`; direct/indirect call + IAT + data-label annotation;
  CFG-bounded; coverage footer.
- `python/glaurung/llm/kb/lock_state.py` + `cli/commands/locks.py`: `locks`
  command. Models raw `Ke*`/`Ex*` AND RAII wrappers (`?Acquire@AcquireSpinLock`),
  resolves the lock object through the guard indirection (+ byte-decoded `add
  rcx,imm` since the renderer drops immediates -- Finding A), per-lock balance.
- Tests: `test_kickoff_pdb_naming.py` (rewritten for default-on),
  `test_coverage_footer.py`, `test_function_disasm.py`, `test_lock_state.py`.

## Discovered glaurung defects (need their own fixes)

### Finding A -- disasm renderer DROPS immediate operands (HIGH)
`disassemble_window_at` returns instructions whose `.operands` AND
`.disassembly()` omit standalone immediates: `48 81 c1 c0 07 00 00` renders as
`add rcx` (the `0x7c0` is gone); `66 83 65 47 00` renders as `and [rbp+0x47]`
(imm `0` gone). The raw bytes ARE present and memory-operand displacements
survive -- only the standalone immediate is dropped. This silently corrupts ANY
analysis that needs constants/offsets (lock-object offsets, struct field
constants, size checks). `lock_state.py` works around it by decoding the
`add rcx, imm` immediate from the instruction bytes, but the real fix is in the
Rust iced/operand-formatting layer (`src/disasm/` / `src/python_bindings/`).
Until fixed, no operand-text analysis can trust immediates.

### Finding B -- Microsoft PUBLIC PDBs carry publics, not private struct layouts (MED)
`import_pe_pdb_types` on the dxgmms2 public PDB returns 2302 function publics but
`imported_struct=0`; `_VIDSCH_SYNC_POINT` / `_KSPIN_LOCK` come back under
`missing_layouts`. So #4's premise ("the PDB had the type") is FALSE for MS public
symbols -- internal struct layouts must be RECONSTRUCTED (glaurung's
`discover_struct_candidates` / type propagation), not imported. The kickoff
`--pdb-struct` wiring is correct and still helps when a TYPED PDB is available
(own builds, full symbol packages), and now surfaces missing layouts as a note
instead of silently importing nothing. The strategic investment for driver
structs is the recovery passes, not PDB type import.

## #5 + C2 -- as-built

### #5 Cross-binary / module-group reasoning (DONE)
`python/glaurung/llm/kb/module_group.py` + `cli/commands/group.py`. Extracts the
pool TAGS each module allocates with (the `Tag` arg to `ExAllocatePoolWithTag` /
`ExAllocatePool2`, read from the rendered `mov r8d, imm`) and reports tags SHARED
across group members -- the concrete cross-module corruption surface. Verified on
the motivating hypothesis: `dxgmms1` and `dxgmms2` share pool tags (`TrAG`, `Vi09`),
so an OOB write in one CAN land in the other's pool block. Coverage footer hedges:
shared tag != proven overflow path; lookaside/segment-heap buckets not modeled.
`glaurung group --member dxgmms2=...dxgmms2.sys --member dxgmms1=...dxgmms1.sys`.
Future extension: cross-module callee-VA resolution + per-tag site cross-ref.

### C2 Patch diff-explain (DONE, in agentic-security-bot)
`tools/windows/diff_explain.py`:
- `filter_layout_shifts()` / `_norm_signature()`: drops same-size pairs whose
  relocation-normalized instruction signature is identical pre/post (only
  control-flow targets + RIP-relative addresses masked, so a real logic change
  still differs -- conservative, never drops a real edit). Wired into the
  orchestration after `select_changed_pairs`; writes `layout_shift_dropped.json`;
  `--no-layout-filter` to disable.
- `render_pair_markdown()` now prefixes the Evidence block with an **UNVERIFIED
  (lifted-C, not disasm-confirmed)** banner pointing at `glaurung disasm --db
  --function` (#2) for ground-truth confirmation.
Tests: `tests/unit/test_windows_diff_explain_layout_filter.py`.

## Root observations (from the session)

- kickoff already writes PDB public-symbol names into `function_names`
  (`set_by="pdb"`), and `import_pe_pdb_types` exists -- but BOTH are gated on
  `--pdb-cache`/`$GLAURUNG_PDB_CACHE`. The dxgmms2 DB was built without it, so
  every function was `sub_XXXX` despite an exact-GUID PDB in the cache.
- `disasm` command disassembles a raw file window; it is NOT KB/symbol-aware
  (no name/va resolution from a `.glaurung`, no call-target annotation).
- The session's lock tracer modeled only raw `Ke*SpinLock` imports and silently
  ignored the `AcquireSpinLock::Acquire/Release` RAII wrapper -> a confident
  false race finding. Coverage-footer discipline (C1) + primitive-complete lock
  modeling (#3) are the direct countermeasures.
