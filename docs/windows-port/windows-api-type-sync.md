# Windows API Type Sync

Glaurung ships an offline Windows API prototype bundle at
`data/types/stdlib-winapi-protos.json`. It is generated, not
hand-maintained.

Regenerate it with:

```bash
glaurung types sync
```

The command downloads only the pinned NuGet packages listed in
`data/types/windows-api-sources.lock.json`:

- `Microsoft.Windows.SDK.Win32Metadata`
- `Microsoft.Windows.WDK.Win32Metadata`

The Rust native extension parses the extracted `.winmd` files with the
`windows-metadata` crate. Python handles NuGet download, cache layout,
overlay merging, and manifest writing.

Normal analysis never reaches out to the network. It only reads the checked-in
bundle. To prove the cache path is sufficient:

```bash
glaurung types sync --offline
```

Local SDK/WDK headers can be used as an explicit fallback or augmentation
source:

```bash
glaurung types sync --offline \
  --header /path/to/ntddk.h \
  --clang-arg -I/path/to/sdk/include \
  --clang-arg -D_AMD64_=1
```

Header prototypes are parsed from Clang AST JSON, assigned lower confidence,
and recorded under `header_results` in the manifest with the header SHA256 and
Clang arguments.

The provenance manifest is:

```text
data/types/generated/MANIFEST.json
```

Curated overlays live in:

```text
data/types/overlays/windows-api-semantics.json
```

Keep overlays limited to facts not carried cleanly by WinMD: CRT prototypes,
kernel allocator/probe prototypes, buffer/source/length roles, allocator/free
relationships, and risk tags.

When a bundle is imported into a `.glaurung` project through
`glaurung.llm.kb.xref_db.import_stdlib_prototypes`, the persistent
`function_prototypes` table keeps the generated metadata, not just the
C-ish signature. Stored fields include module, calling convention, source
package/version, confidence, provenance JSON, semantic provenance JSON,
semantic risk tags, and parameter roles. Older project databases are migrated
forward with nullable columns on open.

Fresh projects opened with `auto_load_stdlib=True` load standard bundles by
container format. PE binaries get `stdlib-winapi` / `stdlib-winapi-protos`
alongside the libc/CRT bundles; ELF and Mach-O projects load only the libc
baseline. The loaded bundle names and per-bundle summaries are recorded in
the project database's `stdlib_bundle_loads` table and exposed through
`PersistentKnowledgeBase.list_stdlib_bundle_loads`.

Import-oriented tools consume the same prototype catalogue. `map_pe_iat`
attaches module, prototype, source, confidence, semantic tags, and parameter
roles to PE import rows, and falls back to symbol imports when the native IAT
map is empty. `list_suspicious_imports` combines its capability buckets with
semantic risk tags from overlays, so an API such as `DeviceIoControl` can be
surfaced as an IOCTL boundary even when it does not match a simple string
bucket.

Lower-confidence sources such as local WDK headers, PDB symbol-server data,
phnt/System Informer, ReactOS, Wine, and Ghidra/GDT archives are recorded in
the source lock and manifest as supplemental or per-binary sources. They should
only be promoted into the bundle with explicit provenance and confidence.
