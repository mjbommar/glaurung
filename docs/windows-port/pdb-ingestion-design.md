# #179 -- PDB ingestion design

> The Microsoft Program Database (PDB) is the missing leg of
> Glaurung's typed-symbol coverage. This doc plans the
> ingestion path: where it lives, what crate it uses, how it
> maps onto Glaurung's existing type model, and how the asb
> campaign supplies test fixtures and build-tagging discipline.

Roadmap status: `docs/architecture/IDA_GHIDRA_PARITY.md` row
"#179 PDB ingestion (Microsoft Program Database)".

## Implementation status (2026-05-17)

The type-ingestion path has landed for the comparison-02 contract:

- `src/symbols/pdb.rs` provides native PDB loading through the
  Rust `pdb` crate, struct/class/union layout lookup, field-list
  walking, best-effort field type-name mapping, bitfield metadata,
  function-prototype type records, and PE/PDB build provenance.
- The PE path parses CodeView RSDS metadata and resolves cached
  PDBs from the Microsoft symbol-cache layout or the flat fixture
  layout.
- `glaurung.debug.analyze_pe_pdb_cache_path()` exposes the PE/PDB
  cache analysis to Python.
- `type_db.import_pe_pdb_types()` persists PDB-derived structs,
  unions, and `function_proto` type records into `.glaurung` with
  `set_by="pdb"` and provenance.
- `type_db.import_pe_pdb_public_names()` persists PE/PDB public
  function symbols into the persistent `function_names` table with
  `set_by="pdb"` while preserving manual names.
- The `ntoskrnl.exe` / `ntkrnlmp.pdb` fixture imports the 20
  fielded canonical structs/unions needed by comparison 02 and
  keeps `_KSPIN_LOCK` explicit as a scalar-alias/non-UDT
  `missing_layouts` entry.
- The same fixture imports 27,238 PDB public function names, including
  `KeReleaseSpinLock`, `FsRtlPrivateLock`, and
  `IoInitSystemPreDrivers`.

Remaining work under the broader #179 umbrella:

- Add a narrow alias/type-summary API only if a later consumer needs
  scalar typedefs such as `_KSPIN_LOCK` represented as typed rows.

## What exists today

`src/symbols/pe.rs:549` already scans for a CodeView RSDS record
in the PE debug directory and returns the embedded PDB path
string (`<binary-stem>.pdb`) plus the GUID + age. From
`src/symbols/analysis/pe_env.rs` that path becomes the
`pdb_path` field in the analysis result.

What's missing is the next step: open the .pdb file at that
path, parse its types + symbols, and emit type-DB rows
matching the gimli DWARF ingestion's output (issue #178).

## Crate choice: Rust `pdb` vs `llvm-pdbutil`

### Primary path: `pdb` crate

`https://crates.io/crates/pdb`. Maintained, pure-Rust, used by
`goblin`'s consumers. Covers all the table kinds Glaurung
needs:

- `TypeIndex` resolution (TPI stream)
- `SymbolTable` enumeration (DBI stream, per-module)
- `ItemInfo` (IPI stream) for inline functions
- `LineProgram` for source-line mapping (low priority for
  initial cut)

### Fallback / cross-validation: `llvm-pdbutil dump --json`

Bundled with LLVM, output is JSON, semantically equivalent for
the dimensions we care about. Heavier (subprocess), but proven
against newer MSVC PDB formats where the `pdb` crate has had
historical gaps (e.g. `LF_FUNC_ID` records that postdate the
crate's coverage).

asb workstream 02 sec "Risks and mitigations" calls out the
gap risk; the resolution is the bridge layer accepts either
path. Concretely:

```rust
// src/symbols/pdb.rs
pub enum PdbBackend {
    Native,           // pdb crate
    LlvmPdbutil,      // shells out to `llvm-pdbutil dump --json`
}

pub struct PdbIngestor {
    backend: PdbBackend,
    cache_dir: PathBuf,
}

impl PdbIngestor {
    pub fn from_codeview_record(
        record: &CodeViewRsds,
        cache_dir: &Path,
        backend: PdbBackend,
    ) -> Result<Self> { ... }

    pub fn types(&mut self) -> Result<TypeIterator<'_>> { ... }
    pub fn symbols(&mut self) -> Result<SymbolIterator<'_>> { ... }
}
```

The `PdbBackend` choice is per-call, defaulting to `Native`.
A Cargo feature flag `pdb-llvm-fallback` enables the
subprocess path; we do not require LLVM at build time for the
default install.

## Mapping into Glaurung's internal type model

Glaurung's DWARF path (issue #178, shipped) lands types in:

| table | DWARF source | PDB source (planned) |
|-------|--------------|----------------------|
| `types` (struct, union, enum, typedef, function_proto) | `DW_TAG_structure_type` etc. | `TypeIndex` records: `Class`, `Structure`, `Union`, `Enum`, `Procedure`, `MFunction` |
| `type_fields` (field bodies) | `DW_TAG_member` | `FieldList` -> `Member`, `BClass`, `OneMethod` |
| `function_prototypes` (return type + arg types) | `DW_AT_type` chains | `Procedure.return_type` + `arglist` |
| `function_names` (symbol -> VA) | `DW_TAG_subprogram` `DW_AT_low_pc` | `PublicSymbol` (S_PUB32) + `ProcedureSymbol` (S_GPROC32/S_LPROC32) |

The mapping layer lives at
`src/symbols/analysis/pdb_types.rs`, mirroring
`dwarf_types.rs`. Each PDB type kind has one `From<&pdb::Type<'_>>
for InternalType` impl. The downstream `type_db` consumer cannot
tell which path produced a given row except via the `set_by`
column (asb's persistent-KB ADR), which becomes `set_by="pdb"`
for PDB-sourced rows (matching the existing `set_by="dwarf"`).

### Tricky bits the implementation will hit

1. **Forward references.** PDB uses `LF_CLASS` forward references
   for circular types (`struct Foo { struct Foo* next; }`). The
   mapper has to delay struct-body emission until the
   forward reference resolves. The `pdb` crate exposes
   `TypeFinder::find` for this; mirror gimli's two-pass behaviour.
2. **Compiler-generated synthetics.** PDB encodes
   `<unnamed-tag>` and `<lambda_0>` types. Map them with a
   stable name derived from `(parent_fn, lexical_block_va)`
   so the type-DB key stays deterministic across re-ingest.
3. **Inline functions.** `LF_FUNC_ID` plus `S_INLINESITE`
   records describe inline-call sites. For the initial cut,
   record the outer function only; expose inline-site
   resolution as a follow-up (issue out-of-scope here).
4. **Multi-stream PDBs.** Modern MSVC emits PDBs with multiple
   `DBI` modules (one per .obj file). The mapper iterates all
   modules; symbols can appear in multiple modules with the
   same name (template instantiations). Use the
   `(symbol_kind, va)` tuple as the dedup key.

## Wiring into `src/symbols/pe.rs`

```rust
// src/symbols/pe.rs (sketch)
pub fn analyze_pe_symbols(
    bytes: &[u8],
    opts: &PeAnalysisOpts,
) -> Result<PeSymbols> {
    let mut out = PeSymbols::default();

    // existing path: import table, export table, IAT
    out.imports = scan_imports(bytes)?;
    out.exports = scan_exports(bytes)?;

    // existing path: CodeView RSDS detect
    if let Some(cv) = find_codeview_rsds(bytes) {
        out.codeview = Some(cv.clone());

        // NEW (#179): if local PDB cache hit, ingest types + symbols
        if let Some(pdb_path) = resolve_pdb_cache(&cv, opts.pdb_cache.as_deref()) {
            let mut ing = PdbIngestor::from_codeview_record(
                &cv,
                &pdb_path,
                opts.pdb_backend.unwrap_or(PdbBackend::Native),
            )?;
            out.pdb_types = ing.types()?.collect::<Result<Vec<_>>>()?;
            out.pdb_symbols = ing.symbols()?.collect::<Result<Vec<_>>>()?;
        }
    }
    Ok(out)
}
```

The `opts.pdb_cache` defaults to
`/nas4/data/symbol-cache/microsoft/` per asb workstream 00; the
CLI `glaurung symbols --pdb-cache <DIR>` flag overrides.

## Build-tagging: every kg-pe row carries `(binary_sha256, pdb_guid_age)`

asb workstream 03 sec "PDB structs change between builds; rules
must be build-tagged" makes this non-negotiable. A struct field
offset rule that fires on `KTHREAD->StackBase` at offset 0x38 in
26100.1 may need offset 0x40 in 26100.5; the same rule must not
silently match the wrong layout.

Implementation:

- Every type-DB row emitted by `pdb_types.rs` includes a
  `provenance` column populated as:

  ```json
  {
    "set_by": "pdb",
    "binary_sha256": "<hex>",
    "pdb_guid": "<hex>",
    "pdb_age": 1
  }
  ```

- The kg-pe bridge (asb-side `tools/kg-pe/bridge.py`) joins on
  `(binary_sha256, pdb_guid, pdb_age)` so cross-binary queries
  do not blur builds.

- Rules consume the build-tag via the `classify_attacker_for_pe_fn`
  tool's output, which echoes the provenance back to the agent.

This is the structural difference from the Linux side: kernel
source has stable struct layouts (modulo `__randomize_layout`);
PDB layouts change every release. Build-tag-or-die.

## Test fixtures

The #197 fixtures (`tests/fixtures/msvc-pdb/`) feed two test
layers:

1. **`tests/test_pdb_ingest.py`** -- per-fixture smoke: load
   PDB, count types + symbols, assert >0 of each, assert
   sentinel types resolve (e.g. `KTHREAD` for ntoskrnl,
   `VS_VERSIONINFO` for any executable with a manifest).
2. **`tests/test_pdb_type_mapping.py`** -- per-type-kind
   assertions: load a known struct from a known fixture, assert
   the field list matches the expected names + offsets +
   types. Use `mspaint.exe` here for layout stability across
   Win10/11.

Source of truth for "expected" values: dump the same PDB with
`llvm-pdbutil dump --types` and capture the JSON. Tests
compare Glaurung's output against the dump, not against
hand-typed expectations. This way the fallback backend
doubles as a test oracle.

## Win11 24H2 sanity check

`virtio-win/issue-1100` is referenced in asb workstream 02 as a
known Win11 24H2 driver-signing nicety; not a PDB-format
gotcha per se, but worth a one-paragraph check during fixture
selection that we get a clean PDB out of a 24H2 build. If the
24H2 PDB stream layout differs in any way that breaks `pdb`
crate, that's the trigger to flip to the llvm-pdbutil fallback
for that fixture.

## Effort breakdown

| step | pomodoros |
|------|-----------|
| `src/symbols/pdb.rs` scaffold + `PdbIngestor` API | 1 |
| `pdb_types.rs` mapper (struct/union/enum/typedef) | 1.5 |
| `pdb_types.rs` mapper (function_proto + inline-site stubs) | 1 |
| Wire into `src/symbols/pe.rs` + cache-hit resolution | 0.5 |
| Build-tag provenance threading through type-DB writes | 1 |
| `tests/test_pdb_ingest.py` + `test_pdb_type_mapping.py` | 1 |
| **total** | **6** |

Matches asb workstream 02's 4-6 pomodoro estimate at the upper
bound.

## Exit signal (matches roadmap.md)

```
glaurung symbols \
  tests/fixtures/msvc-pdb/ntoskrnl-26100.1.exe \
  --pdb-cache tests/fixtures/msvc-pdb/
```

shows:

- >95% function-name symbolization vs the PDB's `S_PUB32`
  symbol count
- the top-10 named structs (`KTHREAD`, `EPROCESS`,
  `FILE_OBJECT`, `IRP`, `KDPC`, `IO_STACK_LOCATION`,
  `KAPC_STATE`, `KEVENT`, `KMUTEX`, `ETHREAD`) resolve to
  type-DB rows with non-empty field lists
- the type-DB rows carry populated `provenance.binary_sha256`,
  `provenance.pdb_guid`, `provenance.pdb_age`

## Cross-refs

- Existing CodeView RSDS detection:
  `src/symbols/pe.rs:549-580`,
  `src/symbols/analysis/pe_env.rs:18-26`
- DWARF mapper to mirror:
  `src/symbols/analysis/dwarf_types.rs` (path from issue
  #178; check the actual symbol table when starting work)
- Persistent type DB schema:
  `docs/architecture/PERSISTENT_PROJECT.md` -- the `types`
  + `type_fields` + `function_prototypes` tables this work
  populates
- Roadmap board entry:
  `docs/architecture/IDA_GHIDRA_PARITY.md` row for #179
- asb campaign-side use case:
  `projects/windows-port/workstreams/02-kg-pe-substrate.md`
  sec "#179 -- PDB ingestion"
- asb build-tagging policy:
  `projects/windows-port/workstreams/03-rules-and-master-data.md`
  sec "PDB structs change between builds; rules must be build-tagged"
- Fixture cache asb provides:
  `/nas4/data/symbol-cache/microsoft/`
- Corpus the cache is keyed against:
  `/nas4/data/binary-analysis/glaurung/windows-{8,10,11}-x64/`
