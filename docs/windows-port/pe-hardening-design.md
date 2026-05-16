# #199 -- PE format hardening design

> Four PE data-directory entries Glaurung does not currently
> parse. Each gates a class of analysis (or rule encoding) the
> `agentic-security-bot` (asb) windows-port campaign needs.

Roadmap status: `docs/architecture/IDA_GHIDRA_PARITY.md` row
"#199 PE format hardening (delay imports, manifest, version
info, TLS callbacks)" -- "Pre-req for grounded malware triage
claims."

## What exists today

`src/formats/pe/types.rs` defines every `IMAGE_DIRECTORY_ENTRY_*`
constant including the four targeted here:

```
IMAGE_DIRECTORY_ENTRY_RESOURCE      = 2
IMAGE_DIRECTORY_ENTRY_TLS           = 9
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT  = 13
```

(Manifest is a sub-resource of RESOURCE; no separate directory
slot.)

`src/symbols/analysis/pe_env.rs` reads a TLS callback **count**
(integer), nothing else. `src/formats/pe/directories/` has
parsers for `export.rs` and `import.rs` but no delay-import,
resource, or TLS module. `src/formats/pe/types.rs:524` has a
comment "TLS directory" with the struct definition but no
walker.

## Per-directory: source struct, what we extract, CVE classes

### 1. Delay imports (`IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`)

**Microsoft source struct.**

```c
typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
    union {
        DWORD AllAttributes;
        struct {
            DWORD RvaBased : 1;
            DWORD ReservedAttributes : 31;
        };
    } Attributes;
    DWORD DllNameRVA;
    DWORD ModuleHandleRVA;
    DWORD ImportAddressTableRVA;
    DWORD ImportNameTableRVA;
    DWORD BoundImportAddressTableRVA;
    DWORD UnloadInformationTableRVA;
    DWORD TimeDateStamp;
} IMAGE_DELAYLOAD_DESCRIPTOR, *PIMAGE_DELAYLOAD_DESCRIPTOR;
```

**Extraction.** Walk descriptor array until a zeroed terminator.
For each descriptor: resolve `DllNameRVA` to the lazily-loaded
DLL name, resolve `ImportNameTableRVA` to the list of imported
function names, expose as `Vec<DelayImport>` mirroring the
shape of regular imports.

**Why it matters for asb.**

- A driver lazy-loads a helper DLL via `LoadLibraryEx`-style
  resolution; the regular import table does not list the
  helper. asb's `find_*` tools see only "function foo is
  defined", miss the resolution edge to `helper!bar`, and a
  reachability rule under-reports.
- Several malware families hide their real surface in delay
  imports specifically because traditional triage tools miss
  the resolution.

**CVE classes touched.**

- Any rule that depends on full import enumeration to bound
  the function-call surface (tier-1 #6 win32k callbacks
  occasionally cross into delay-loaded user32 helpers).
- Malware-triage claims as called out in
  `docs/architecture/IDA_GHIDRA_PARITY.md`.

**Test fixture suggestion.** `mspaint.exe` uses delay imports
for `gdiplus.dll`; any of the user32-dependent Win11 24H2
binaries do similarly.

### 2. Manifest (`IMAGE_DIRECTORY_ENTRY_RESOURCE` -> `RT_MANIFEST`)

**Microsoft resource type.** Resource type 24 (`RT_MANIFEST`).
Content is XML (`<assembly>` root) describing UAC requirements,
DPI awareness, longPathAware, supported OS, etc.

**Extraction.** Walk the resource tree (3 levels: type -> name
-> language), filter to `RT_MANIFEST`, extract the raw bytes,
parse as XML via `quick-xml` (already a Glaurung dep via the
JVM parser). Surface as:

```rust
pub struct PeManifest {
    pub uac_level: UacLevel,           // asInvoker | highestAvailable | requireAdministrator
    pub ui_access: bool,                // true if requestedExecutionLevel.uiAccess="true"
    pub dpi_aware: Option<String>,      // "true" | "system" | "permonitor"
    pub long_path_aware: bool,
    pub supported_os: Vec<String>,      // GUIDs from <supportedOS Id="...">
    pub raw_xml: String,                // for downstream rules that want the source
}
```

**Why it matters for asb.**

- UAC level pins the AV/PR threat-model fields. A binary
  declaring `requireAdministrator` is reachable only from
  medium IL+ (so AV=Local, PR=High). asb's
  `classify_attacker_for_pe_fn` tool feeds this into the
  Gate-4 CVSS rationale.
- `uiAccess=true` plus auto-elevation is a documented EoP
  primitive (UIPI bypass). asb bug-class #22 (`com-auto-elevation-icmluautil`)
  cares about manifest contents.

**CVE classes touched.**

- COM elevation (#22), UAC bypasses generally, any rule that
  needs the threat-model integrity level to disambiguate
  attacker class.

**Test fixture suggestion.** `mspaint.exe` (asInvoker, dpi
aware), `taskmgr.exe` (highestAvailable), `regedit.exe`
(asInvoker but uiAccess).

### 3. Version info (`VS_VERSIONINFO` sub-resource)

**Microsoft resource type.** Resource type 16 (`RT_VERSION`)
under the RESOURCE directory. Binary-encoded
`VS_VERSIONINFO` block: a header, a `VS_FIXEDFILEINFO`
struct, then a `StringFileInfo` block with localized
key-value strings (`CompanyName`, `FileDescription`,
`FileVersion`, `InternalName`, `LegalCopyright`,
`OriginalFilename`, `ProductName`, `ProductVersion`).

**Extraction.**

```rust
pub struct PeVersionInfo {
    pub fixed: VsFixedFileInfo,         // FileVersionMS/LS, ProductVersionMS/LS, FileFlags, FileType, FileSubtype
    pub strings: BTreeMap<String, String>, // CompanyName, ProductName, ProductVersion, etc.
}
```

**Why it matters for asb.**

- This is the **build-tag** asb workstream 01 listed as an
  open question. `ntoskrnl-26100.1.exe` and
  `ntoskrnl-26100.5.exe` are byte-different but the resource
  string `ProductVersion="10.0.26100.5"` is the canonical
  human-readable build identifier.
- The PDB GUID + age (already extracted from CodeView, see
  `pdb-ingestion-design.md` sec "Build-tagging") and the
  `VS_FIXEDFILEINFO.FileVersion` form a 1:1 pair for any
  Microsoft-shipped binary. Joining the two confirms a PDB
  matches a binary.

**CVE classes touched.**

- Indirectly: Patch Tuesday diff (#186) needs the build-tag
  to know what it is diffing. Without #199 the diff falls
  back to filename-as-identifier, which is wrong for the
  many cases where Microsoft ships the same filename across
  builds.

**Test fixture suggestion.** Any Microsoft binary; `ntoskrnl.exe`
has the richest version info.

### 4. TLS callbacks (`IMAGE_DIRECTORY_ENTRY_TLS`)

**Microsoft source struct.**

```c
typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG StartAddressOfRawData;
    ULONGLONG EndAddressOfRawData;
    ULONGLONG AddressOfIndex;
    ULONGLONG AddressOfCallBacks;   // pointer to NULL-terminated array of PIMAGE_TLS_CALLBACK
    DWORD SizeOfZeroFill;
    union {
        DWORD Characteristics;
        struct {
            DWORD Reserved0 : 20;
            DWORD Alignment : 4;
            DWORD Reserved1 : 8;
        };
    };
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;
```

`AddressOfCallBacks` points at a NULL-terminated array of
function-pointer VAs; each callback runs **before**
`DriverEntry` / `main`.

**Extraction.** Walk the directory, resolve
`AddressOfCallBacks` to a VA, walk the VA array until NULL,
expose `Vec<TlsCallbackVa>`. Each VA gets fed into
Glaurung's existing function-discovery pass so the disassembler
covers the callbacks like any other entry point.

```rust
pub struct PeTlsInfo {
    pub raw_data_start: u64,
    pub raw_data_end: u64,
    pub index_va: u64,
    pub callback_vas: Vec<u64>,   // resolved + dedup'd
    pub characteristics_alignment: u32,
}
```

**Why it matters for asb.**

- TLS callbacks are a real pre-`DriverEntry` execution surface.
  asb bug-class catalogue has no explicit "TLS-callback UAF"
  entry today, but historical Windows kernel CVEs include
  init-time bugs in TLS callbacks; the surface is unguarded
  unless the analyzer walks them.
- Malware loves TLS callbacks for early-execution hiding;
  every triage tool that misses them under-reports.

**CVE classes touched.**

- Driver init-time UAF / use-before-init (a generalization of
  asb bug-class #3 IRP-completion-then-use applied to the
  init path).
- Malware persistence + early-execution patterns; not asb's
  primary focus but a real Glaurung use case.

**Test fixture suggestion.** `dxgkrnl-26100.1.sys` has TLS
callbacks; pick another driver as a second sample so the test
matrix isn't single-binary.

## Implementation layout

```
src/formats/pe/directories/
  delay_import.rs    # NEW: IMAGE_DELAYLOAD_DESCRIPTOR walker
  resource.rs        # NEW: 3-level tree walker
  manifest.rs        # NEW: parse RT_MANIFEST XML via quick-xml
  version_info.rs    # NEW: parse RT_VERSION VS_VERSIONINFO binary block
  tls.rs             # NEW: walk IMAGE_TLS_DIRECTORY64 + dereference callback VAs
  export.rs          # existing
  import.rs          # existing
  mod.rs             # existing, extend pub mod list

src/formats/pe/mod.rs                   # extend top-level PE struct with new fields
src/symbols/analysis/pe_env.rs          # extend PeEnv struct + analyze() to populate new fields
```

The new modules each export one parse function plus their
output struct; `pe_env::analyze` becomes the orchestrator. No
public-API surface changes for callers that only consumed the
existing fields.

## Output schema (CLI JSON)

```
glaurung pe-env <binary> --json
```

after #199 returns:

```json
{
  "pdb_path": "...",
  "tls_callbacks": [4307304448, 4307304512],
  "delay_imports": [
    {"dll": "gdiplus.dll", "functions": ["GdipCreateBitmapFromStream", ...]},
    ...
  ],
  "manifest": {
    "uac_level": "asInvoker",
    "ui_access": false,
    "dpi_aware": "permonitor",
    "long_path_aware": true,
    "supported_os": ["{e2011457-1546-43c5-a5fe-008deee3d3f0}", ...]
  },
  "version_info": {
    "fixed": {
      "file_version": "10.0.26100.1",
      "product_version": "10.0.26100.1",
      "file_flags": 0,
      "file_type": "Driver",
      "file_subtype": "DriverSystem"
    },
    "strings": {
      "CompanyName": "Microsoft Corporation",
      "FileDescription": "NT Kernel & System",
      "ProductName": "Microsoft Windows Operating System",
      "ProductVersion": "10.0.26100.1"
    }
  }
}
```

## Test plan

For each directory, one fixture-based test plus one
adversarial test:

| directory | fixture test | adversarial test |
|-----------|--------------|------------------|
| Delay imports | `mspaint.exe` returns >=1 delay-import (gdiplus.dll) | malformed `DllNameRVA` past end-of-image: parser returns empty list, no panic |
| Manifest | `mspaint.exe` returns `uac_level=asInvoker` | XML with no `<assembly>` root: parser returns empty PeManifest, no panic |
| Version info | `ntoskrnl.exe` returns `ProductName="Microsoft Windows Operating System"` | resource with non-VS_VERSIONINFO bytes in RT_VERSION: parser returns None |
| TLS callbacks | `dxgkrnl.sys` returns >=1 callback VA | `AddressOfCallBacks` -> 0: parser returns empty Vec |

The adversarial tier wires into Glaurung's existing
adversarial-tree regression (#214); the 3-second-per-call
budget applies.

## Effort breakdown

| step | pomodoros |
|------|-----------|
| Delay-import walker + test | 0.5 |
| Resource tree walker + test | 0.5 |
| Manifest XML parser + test | 0.5 |
| VS_VERSIONINFO binary parser + test | 0.75 |
| TLS callback walker + test | 0.5 |
| Wire all four into `pe_env::analyze` + JSON output | 0.5 |
| Adversarial cases (one per directory) | 0.5 |
| **total** | **3.75** |

Matches asb workstream 02's 3-4 pomodoro estimate.

## Exit signal (matches roadmap.md)

```
glaurung pe-env tests/fixtures/msvc-pdb/dxgkrnl-26100.1.sys --json | jq \
  '.tls_callbacks | length, .manifest.uac_level,
   .delay_imports | length, .version_info.fixed.product_version'
```

returns four populated values (`>0`, a known UAC string,
`>=0`, `"10.0.26100.1"`).

For `mspaint.exe`:

```
glaurung pe-env tests/fixtures/msvc-pdb/mspaint.exe --json | jq \
  '.manifest.uac_level, .version_info.strings.CompanyName'
```

returns `"asInvoker"`, `"Microsoft Corporation"`.

## Cross-refs

- Existing PE directory infrastructure:
  `src/formats/pe/directories/{export,import,mod}.rs`,
  `src/formats/pe/types.rs:13-27` (directory entry constants),
  `src/formats/pe/types.rs:524` (TLS struct definition comment)
- Existing `pe_env::analyze`:
  `src/symbols/analysis/pe_env.rs`
- Roadmap board entry:
  `docs/architecture/IDA_GHIDRA_PARITY.md` row for #199
- asb campaign use case:
  `projects/windows-port/workstreams/02-kg-pe-substrate.md`
  sec "#199 -- PE format hardening"
- asb bug-class mapping (esp. tier-2 #22 COM elevation needs
  manifest):
  `projects/windows-port/reference/bug-class-invariants.md`
- Microsoft official references:
  PE Format spec at learn.microsoft.com/en-us/windows/win32/debug/pe-format
  (offline copy not in the repo; consult the live page when
  picking up the work)
