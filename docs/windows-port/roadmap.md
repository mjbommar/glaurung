# Roadmap: Glaurung Windows-port items

> Four Glaurung GitHub issues the `agentic-security-bot` (asb)
> windows-port campaign drives upstream. Each section: scope,
> motivation, design sketch, dependencies, effort, exit signal.

The campaign-side rationale lives at
`projects/windows-port/workstreams/02-kg-pe-substrate.md` (asb
repo); the headings below cite the relevant section numbers.

---

## #197 -- MSVC + .pdb sample fixtures

`docs/architecture/IDA_GHIDRA_PARITY.md` lists this as the
blocker for #179. Without committed, license-clean MSVC samples
the PDB ingestion code has no red tests to drive.

### Scope

Add a `tests/fixtures/msvc-pdb/` directory containing 6-10
PE binaries plus matching PDBs, each with a SHA + Microsoft
public-symbol-server provenance line in `MANIFEST.json`. asb has
a 19,287-binary Windows corpus at
`/nas4/data/binary-analysis/glaurung/windows-{8,10,11}-x64/`
and a PDB cache at `/nas4/data/symbol-cache/microsoft/` that
feeds the selection.

### Motivation (from asb workstream 02 sec "Outputs" + sec
"#197 -- MSVC sample fixtures")

The campaign's Windows-side rule-encoding work assumes Glaurung
can resolve PDB-attached function names and struct field
offsets. #179 is the work; #197 is the test bed. asb commits
to picking the fixtures so the choice reflects real driver /
kernel / userland diversity:

- `ntoskrnl-26100.1.exe` + `.pdb` -- kernel, large, complex
- `mspaint.exe` + `.pdb` -- small userland baseline
- `tcpip-26100.1.sys` + `.pdb` -- WDF driver with NDIS
- `dxgkrnl-26100.1.sys` + `.pdb` -- indirect-dispatch heavy
- one x64, one ARM64

### Design sketch

```
tests/fixtures/msvc-pdb/
  MANIFEST.json            # {sha256, build, pdb_guid, pdb_age,
                           #  source: "https://msdl.microsoft.com/.../",
                           #  license_note: "..."}
  ntoskrnl-26100.1.exe
  ntoskrnl-26100.1.pdb
  mspaint.exe
  mspaint.pdb
  ...
tests/test_pdb_ingest.py   # skeleton; red until #179 lands
```

`MANIFEST.json` is the load-bearing artifact. Without it the
fixtures look like arbitrary blobs; with it any reviewer can
re-fetch them from the public symbol server.

### Dependencies

- asb workstream 00 (PDB cache) must be live; it already is.
- License review: Microsoft's public symbol server terms permit
  redistribution-with-attribution for the .pdb files; the .exe
  files are bound by the Windows EULA. Resolution: ship a
  fetch script (`scripts/fetch_msvc_fixtures.sh`) that hydrates
  the directory from the user's local Windows install plus the
  symbol server, rather than committing the .exe bytes.
  `MANIFEST.json` still ships, with SHAs to verify what got
  fetched.

### Effort

2 pomodoros (fixture selection + manifest + fetch script + red
test skeleton).

### Exit signal

`cd tests/fixtures/msvc-pdb && bash fetch.sh && python
-c 'import json; assert all((Path(r["filename"]).exists() and
hashlib.sha256(Path(r["filename"]).read_bytes()).hexdigest() ==
r["sha256"]) for r in json.load(open("MANIFEST.json")))'`
exits 0.

---

## #179 -- PDB ingestion

The symmetric counterpart of the gimli-based DWARF path. PDB is
the missing leg of Glaurung's typed-symbol coverage; until #179
lands, PE binaries fall back to symbol-name-only data and lose
all struct-field-offset knowledge.

### Scope

Add `src/symbols/pdb.rs` (parse) and
`src/symbols/analysis/pdb_types.rs` (map into Glaurung's
internal type model). Wire from `src/symbols/pe.rs` when the
CodeView RSDS PDB path resolves to a local cache hit.

### Motivation (from asb workstream 02 sec "#179 -- PDB
ingestion")

Every kg-pe rule asb plans to encode (workstream 03) needs
either PDB-derived function names (so the rule can say
"this fn calls `KeAcquireSpinLock`") or PDB-derived struct
layouts (so the rule can say "this offset is
`KTHREAD->StackBase`"). Glaurung's existing CodeView RSDS
detector (`src/symbols/pe.rs:549`) already finds the PDB
path; #179 turns that path into a loaded type table.

### Design sketch

The dedicated doc is `pdb-ingestion-design.md`; one-paragraph
summary:

- Primary: Rust `pdb` crate (https://crates.io/crates/pdb).
  Mature, used by `radare2`, `goblin` consumers.
- Fallback / cross-validation: `llvm-pdbutil dump --types` JSON
  output. Heavier, but bundled with LLVM and proven against
  newer MSVC PDB formats.
- Both flow into a `pdb_types.rs` mapper that emits the same
  `struct/enum/typedef/function_proto` rows the DWARF path
  emits in `dwarf_types.rs` (issue #178, shipped). Downstream
  type-DB consumers do not learn whether the source was DWARF
  or PDB.

### Dependencies

- #197 fixtures must exist before tests can drive the code.
- No new system deps beyond the `pdb` crate; llvm-pdbutil is
  an opt-in alternate path behind a Cargo feature flag.

### Effort

4-6 pomodoros (asb workstream 02 estimate). Bulk of the work
is the type-mapper; the `pdb` crate's parse path is one-liner
chains.

### Exit signal

`glaurung symbols ntoskrnl.exe --pdb-cache
/nas4/data/symbol-cache/microsoft/` shows >95% function-name
symbolization, with type-DB rows present for the top-10 named
structs (`KTHREAD`, `EPROCESS`, `FILE_OBJECT`, etc.).

---

## #199 -- PE format hardening

Four PE directory entries Glaurung currently does not read.
Each gates a class of analysis the campaign needs.

### Scope

In `src/symbols/pe.rs` (or split into a per-directory module
under `src/formats/pe/directories/`):

| directory | constant | added artifact |
|-----------|----------|----------------|
| Delay imports     | `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` (13) | per-DLL delay-import table |
| Resource          | `IMAGE_DIRECTORY_ENTRY_RESOURCE` (2)      | manifest extraction (UAC level, DPI awareness, longPathAware) |
| Version info      | (sub-resource of RESOURCE)                | `VS_VERSIONINFO` block: file/product version, company |
| TLS callbacks     | `IMAGE_DIRECTORY_ENTRY_TLS` (9)           | TLS callback VA list |

Today `pe_env.rs` reads TLS only as a count; the rest are
absent.

### Motivation (from asb workstream 02 sec "#199 -- PE format
hardening" + asb `reference/bug-class-invariants.md`)

- Delay imports: lazy-loaded driver helpers can hide attacker
  reachability paths a tier-1 rule would otherwise flag.
- Manifest: gates the threat-model AV/PR (UAC level reveals
  whether the binary requires elevation; informs whether
  `windows-low-il` reaches it).
- Version info: gives the build-tag asb's kg-pe bridge needs
  to disambiguate `ntoskrnl-26100.1` vs `ntoskrnl-26100.5`
  in Patch Tuesday diffs. asb workstream 01 has this as an
  "open question" today; #199 closes it.
- TLS callbacks: a real pre-DriverEntry execution surface.
  Several CVE classes (driver init-time UAF, TLS-callback
  hidden code) require the callback VA list.

### Design sketch (per directory)

```
src/formats/pe/directories/
  delay_import.rs    # IMAGE_DELAYLOAD_DESCRIPTOR walker
  resource.rs        # tree walker: TYPE -> NAME -> LANG -> data
                     # specialized extractors: MANIFEST, VS_VERSIONINFO
  manifest.rs        # parse the XML manifest extracted by resource.rs
  version_info.rs    # parse the VS_VERSIONINFO binary block
  tls.rs             # walk IMAGE_TLS_DIRECTORY64 + callback VAs
```

Each module emits into `src/symbols/analysis/pe_env.rs`'s
existing return type (extended with new fields). The
`pe_env::analyze` call signature stays stable.

Per-directory CVE rationale lives in `pe-hardening-design.md`.

### Dependencies

- No new crate deps; `goblin` exposes everything needed for
  delay-imports + TLS. Manifest XML can be parsed with
  `quick-xml` (already in Glaurung's tree via JVM parser).
- Should not interact with #179 PDB work; the two are
  parallelizable.

### Effort

3-4 pomodoros (asb workstream 02 estimate).

### Exit signal

```
glaurung pe-env dxgkrnl-26100.1.sys --json | jq \
  '.tls_callbacks | length, .manifest.uac_level,
   .delay_imports | length, .version_info.product_version'
```
returns four populated values; `pe_env::analyze` for
`mspaint.exe` returns manifest with `uac_level=asInvoker`,
version info with `company="Microsoft Corporation"`.

---

## #186 -- BSim-equivalent function similarity

Ghidra ships BSim; Glaurung ships `glaurung diff` today but
it operates at function-name granularity (same/changed/added/
removed). Patch Tuesday cross-build diff is the campaign's
n-day analysis loop and needs body-level similarity.

### Scope

Add a similarity index that, given a function in
`ntoskrnl-26100.1` and a candidate set in `ntoskrnl-26100.5`,
returns ranked matches scored as "same modulo refactor",
"changed (and how much)", "removed", or "new".

### Motivation (from asb workstream 02 sec "#186" + sec
"Calibration plan")

Without #186, asb cannot rank the ~30 functions touched by a
typical Patch Tuesday from the ~6000 in `ntoskrnl.exe`. The
campaign's n-day work loop is: pick a Patch Tuesday, diff the
pre/post `ntoskrnl.exe`, narrow to the 30 changed fns, then
walk each through the bug-class invariants. Step 2 is the
bottleneck `glaurung diff` solves shallowly and #186 solves
properly.

### Design sketch (three options)

The dedicated doc is `bsim-similarity-design.md`. Headline:

- **4-gram opcode hashing + LSH** -- closest to Ghidra's BSim.
  Cheap, deterministic, ships fast. Limit: misses semantic
  refactors that change the instruction stream.
- **CodeT5+ embeddings over decompiled pseudocode** -- highest
  semantic recall. Limit: model dependency, GPU-warm path.
- **Hybrid: opcode-LSH as recall filter -> embedding rerank
  on top-K** -- best per-call recall/precision trade; ships
  second.

asb is fine landing whichever lands fastest; the campaign's
calibration says even the 4-gram-LSH baseline ranks the right
30 fns in the top-100 for ~80% of Patch Tuesdays.

### Dependencies

- No formal blocker on #197/#179/#199. asb does want the
  similarity index keyed by build-tag (so the schema knows
  which two ntoskrnls it is comparing); #199 supplies the
  build-tag via VS_VERSIONINFO.
- `glaurung diff` is the integration surface; #186 lands as
  a new ranking column inside the existing CLI output.

### Effort

4-8 pomodoros depending on chosen approach. asb explicitly
agrees to land "first cut, iterate" rather than waiting for
hybrid.

### Exit signal

```
glaurung diff ntoskrnl-26100.1.exe ntoskrnl-26100.5.exe \
  --similarity bsim --top 50
```
identifies >=80% of the ~30 functions a published June 2026
Patch Tuesday touches (validated against MSRC CSAF for the
same month).

---

## Effort summary

| issue | pomodoros | gating |
|-------|-----------|--------|
| #197  | 2         | none |
| #179  | 4-6       | #197 |
| #199  | 3-4       | none (parallel with #179) |
| #186  | 4-8       | wants #199 build-tag but not blocked |
| **total** | **13-20** | -- |

(The 12-15 Windows-specific atomic tools are out of scope for
this roadmap doc; see `atomic-tools.md`.)

## Reading order if you are picking one to start

1. #199 has the lowest design risk; ship first if you want
   immediate visible wins.
2. #197 unblocks #179, which is the highest-value item; pick
   this pair if you have the appetite for a 6-8 pomodoro arc.
3. #186 lands after at least one of the above; the
   build-tag dependency makes it natural last.

## Cross-refs

- `pdb-ingestion-design.md` -- #179 design
- `pe-hardening-design.md` -- #199 design + per-directory CVE
  rationale
- `bsim-similarity-design.md` -- #186 three-option analysis
- `atomic-tools.md` -- the 12-15 tools that consume #179/#199
- `co-investment-policy.md` -- how PRs flow from asb upstream
