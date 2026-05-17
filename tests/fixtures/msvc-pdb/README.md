# tests/fixtures/msvc-pdb/

Fixtures for **#179 -- PDB ingestion** (blocked-by-#197 in
`docs/architecture/IDA_GHIDRA_PARITY.md`).

8 (PE, PDB) pairs from a single Win11 23H2 corpus snapshot,
spanning kernel / driver / userland / system-service diversity:

| binary | role | PE size | notes |
|---|---|---|---|
| `ntoskrnl.exe` | kernel | 12 MB | large, complex; tests kernel-type extraction (`KTHREAD`, `EPROCESS`, ...) |
| `ntdll.dll` | userland baseline | 2.1 MB | small, layout-stable across Win10/11; type-mapping anchor |
| `tcpip.sys` | WDF driver, NDIS | 3.2 MB | net-stack types (`TCB`, `IRP`, ...) |
| `dxgkrnl.sys` | graphics kernel | 4.6 MB | indirect-dispatch heavy; function-pointer ingest |
| `win32k.sys` | graphics kernel | 676 KB | smaller kernel binary; fast-path test |
| `lsass.exe` | SYSTEM service | 82 KB | tiny userland; manifest + imports edge cases |
| `kernel32.dll` | Win32 API surface | 796 KB | well-known prototype catalogue (`CreateFileW`, ...) |
| `spoolsv.exe` | SYSTEM service | 908 KB | SCM-launched, with UAC manifest |

All x64. No ARM64 fixture in v1 -- the asb-side corpus is x64-only.

## Why no committed bytes

The PE + PDB bytes total ~78 MB. Glaurung already vendors some
PE binaries via git LFS (`.gitattributes` covers
`samples/binaries/platforms/**/*.{exe,dll,sys,...}`) so LFS is
technically available, but for this fixture set we ship the
fetch script + provenance manifest instead:

1. **Reproducibility.** `MANIFEST.json` carries sha256 +
   msdl.microsoft.com URLs. Anyone can re-run `fetch.sh` and
   land bit-identical fixtures, even years from now (PDBs are
   immutable per `(name, GUID, age)`).
2. **License posture.** Microsoft public release binaries are
   redistributable under MS Software License Terms for
   development testing, but the binding is more comfortable
   when bytes flow through the official symbol server rather
   than a third-party mirror.
3. **CI footprint.** A 78 MB checkout is unnecessary for the
   ~95% of contributors who never touch PDB-ingestion code.
   Test invocations call `fetch.sh` first; CI caches the
   fetched dir between runs.

If a future revision opts to vendor via git LFS, MANIFEST.json
remains the authoritative provenance record and `fetch.sh`
becomes the "verify or repair" tool.

## Usage

```bash
# Populate the fixture dir (first time, ~70 sec on a warm
# network; idempotent on re-runs)
./tests/fixtures/msvc-pdb/fetch.sh
```

`fetch.sh` verifies each PE by the CodeView `(pdb_guid, pdb_age)`
embedded in the binary, NOT by sha256. msdl.microsoft.com
re-signs binaries from time to time; the PDB GUID stays
constant (debug info is unchanged) but the PE sha drifts. The
manifest's `sha256` field is the corpus-snapshot value
(informational only).

PDBs are content-addressed by their URL -- `(pdb_name, pdb_guid,
pdb_age)` uniquely identifies the file -- so PDBs always
download bit-identical.

In tests, gate on presence so the suite degrades gracefully
when the fixture dir hasn't been populated:

```python
# python/tests/test_pdb_ingest.py (illustrative)
FIXTURES = Path(__file__).parent.parent.parent / "tests/fixtures/msvc-pdb"
NTOSKRNL = FIXTURES / "ntoskrnl.exe"

@pytest.mark.skipif(not NTOSKRNL.exists(),
                    reason="run tests/fixtures/msvc-pdb/fetch.sh first")
def test_pdb_ingest_ntoskrnl():
    ...
```

```rust
// tests/pdb_ingest_integration.rs (illustrative)
fn fixture(name: &str) -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/msvc-pdb")
        .join(name);
    if p.exists() { Some(p) } else { None }
}

#[test]
fn pdb_ingest_ntoskrnl() {
    let Some(pe) = fixture("ntoskrnl.exe") else {
        eprintln!("skip: run tests/fixtures/msvc-pdb/fetch.sh first");
        return;
    };
    // ...
}
```

## Diversity rationale (test plan layers)

Per `docs/windows-port/pdb-ingestion-design.md` sec "Test
fixtures", this set feeds two layers:

1. **`test_pdb_ingest.py`** -- per-fixture smoke: load PDB,
   count types + symbols, assert sentinel types resolve. The
   four kernel fixtures (ntoskrnl/tcpip/dxgkrnl/win32k) plus
   ntdll cover the type categories Glaurung's existing DWARF
   test suite exercises.
2. **`test_pdb_type_mapping.py`** -- per-type-kind assertions:
   load a known struct from a known fixture. Use **ntdll.dll**
   (smallest binary with layout-stable types) as the canonical
   anchor; the kernel fixtures supply the more complex cases.

Per the new resource test plan
(`docs/parsers/pe-coff/WINDOWS_RESOURCES_CAPABILITIES_TEST_PLAN.md`),
the fixture set also exercises the resource paths just landed:

- `lsass.exe`, `spoolsv.exe` -- VS_VERSIONINFO + UAC manifest
- `ntoskrnl.exe` -- a kernel binary with MESSAGETABLE and
  WEVT_TEMPLATE resources
- `dxgkrnl.sys` -- driver with vendor-defined resource types

## Provenance + license

See `MANIFEST.json`. Every fixture row carries:

- `pdb_name`, `pdb_guid`, `pdb_age` -- the **authoritative**
  build identifier (used by fetch.sh for verification)
- `sha256` of the PE -- corpus snapshot, informational only;
  see "Authoritative identifier" in the manifest top-matter
- `version` string (from PE version info)
- `windows_versions` (which Win release shipped this build,
  from m417z/winbindex)
- `msdl_pe_url`, `msdl_pdb_url` -- direct Microsoft public
  symbol server URLs
- `license_note`

## Updating to a newer Win build

When the asb campaign rebases onto a newer Win11 build:

1. Run asb's `tools/windows/win11-fuzz/scripts/winbindex-query.py
   fetch-latest <binary> --win 11-24H2` per fixture
2. Recompute sha256 and PDB id via asb's
   `extract_pdb_id.py`
3. Regenerate `MANIFEST.json`
4. Re-run `fetch.sh` to validate the new URLs resolve
5. Commit; bump `produced_by` field
