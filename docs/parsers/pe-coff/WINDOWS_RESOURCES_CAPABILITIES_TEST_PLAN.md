# Windows PE Resources Capability And Test Plan

## Purpose

This plan turns the Windows PE resource survey into concrete Glaurung
capabilities and tests. It focuses on safe static analysis of PE resource,
certificate, and related metadata surfaces across executables, DLLs, drivers,
resource-only localization files, managed PE files, and large vendor packages.

The goal is not just to parse `.rsrc`. The goal is to make Windows binaries
daily-drivable in Glaurung: a user should be able to ask what a PE contains,
which resources matter, whether metadata and signatures are coherent, what
strings/configuration are hidden in resources, and which findings are worth
agent attention.

## Ground Rules

- Do not execute corpus binaries.
- Do not recursively unpack untrusted containers unless an explicit bounded
  extraction tool is requested.
- Keep parser APIs budgeted by resource count, resource depth, byte count, and
  wall-clock timeout.
- Vendor only small, redistributable, generated, or source-built fixtures.
- Keep large OS, vendor-driver, update-package, and malware corpora as local or
  CI-optional smoke targets.
- Report partial results with stop reasons instead of failing the whole parse
  when a resource, certificate, or directory is malformed.
- Store enough offsets, RVAs, section names, sizes, hashes, and parser warnings
  for agents to cite evidence without embedding large raw blobs in prompts.

## Corpus Classes

Use these dataset classes for smoke and regression coverage without baking
machine-specific locations into tests or docs.

- Generated fixture PE files built during tests from C, RC, and manifest source.
- Small vendorable PE samples with permissive redistribution terms.
- Windows OS resource libraries with icons, bitmaps, PNG, WAVE, MUI, and version
  metadata.
- Windows Update and vendor-driver packages with DLL, SYS, EXE, MUI, and CPL
  files.
- Driver packages with WEVT_TEMPLATE and MESSAGETABLE resources.
- Managed .NET PE files with CLR metadata and optional embedded managed
  resources.
- Signed and unsigned PE files with normal, missing, malformed, or suspicious
  certificate tables.
- Malware and packed samples as opt-in local smoke targets only.

## Capability Roadmap

### 1. Bounded PE Resource Directory Enumeration

Implement a first-class Rust resource directory parser under the PE parser
module.

Required output:

- Resource tree totals: type count, entry count, leaf count, max depth.
- Per-leaf metadata: type ID/name, resource ID/name, language ID, codepage,
  RVA, file offset, size, section, entropy, SHA-256, magic classification, and
  first-byte preview.
- Type normalization for common resource IDs: CURSOR, BITMAP, ICON, MENU,
  DIALOG, STRINGTABLE, FONTDIR, FONT, ACCELERATOR, RCDATA, MESSAGETABLE,
  GROUP_CURSOR, GROUP_ICON, VERSIONINFO, DLGINCLUDE, PLUGPLAY, VXD,
  ANICURSOR, ANIICON, HTML, MANIFEST, and MUI.
- Custom type preservation: named resources such as WEVT_TEMPLATE, REGISTRY,
  TYPELIB, MODEL_FILES, IMAGE, PNG, WAVE, and vendor-defined names.
- Directory warnings: invalid offsets, invalid UTF-16 names, duplicate
  type/name/language triplets, overlapping data ranges, data outside mapped
  sections, excessive depth, excessive entries, and truncated data.
- Sorting and filtering by type, name, language, size, entropy, magic, and
  section.

Tests:

- Unit tests for resource directory header parsing, named entries, ID entries,
  directory-to-data traversal, UTF-16 resource names, and RVA-to-offset mapping.
- Golden tests against generated fixtures with one resource of each major
  common type.
- Budget tests for max depth, max entries, max resource bytes, and timeout stop
  reasons.
- Malformed tests for cycles, bad offsets, oversized counts, truncated names,
  duplicate leaves, and data entries outside sections.
- Differential smoke tests comparing totals and common type names against
  `llvm-readobj --coff-resources` when LLVM tools are present.
- CLI tests that ensure resource listing can emit stable JSON and compact human
  output.

### 2. Typed Resource Decoders

Layer typed decoders on top of enumeration. Decoders should be independent:
failure in one decoder must not suppress enumeration or other decoders.

Initial decoder set:

- VERSIONINFO: fixed file info, product version, file version, flags, OS/type,
  string tables, language/codepage pairs, company/product/file descriptions,
  original filename, internal name, copyright, and translation records.
- MANIFEST: XML extraction, requested execution level, UI access, DPI awareness,
  common-controls dependency, assembly identity, trustInfo, compatibility GUIDs,
  and dependency names.
- MUI: language tag, resource checksum or identity fields when present, and
  relationship between neutral and localized resource files.
- STRINGTABLE: block ID, string ID, language, decoded string, and empty-string
  handling.
- MESSAGETABLE: message ID, severity/facility/customer flags, language, text,
  and insertion placeholders.
- WEVT_TEMPLATE: provider GUIDs, template names, channels, levels, opcodes,
  keywords, event IDs, maps, and text table references when recoverable.
- ICON/GROUP_ICON and CURSOR/GROUP_CURSOR: image count, sizes, bit depth,
  format, language, and leaf resource linkage.
- BITMAP, PNG, WAVE, HTML, RCDATA, REGISTRY, TYPELIB, and MODEL_FILES: magic,
  entropy, likely format, stable hash, and safe preview metadata.

Tests:

- One generated or vendorable fixture per typed decoder.
- Round-trip style checks for VERSIONINFO and MANIFEST fields generated from RC
  source.
- Multi-language tests for STRINGTABLE, MESSAGETABLE, VERSIONINFO, and MUI.
- Parser-error tests for invalid UTF-16, malformed XML, truncated fixed
  structures, and unknown resource type names.
- Differential tests against `llvm-readobj`, `wrestool`, `rcedit`, or `lief`
  only when available, always optional and skipped cleanly when absent.
- Snapshot tests for compact CLI summaries so output remains useful and stable.

### 3. Resource Extraction And Embedded Content Correlation

Add safe extraction and correlation without making the resource parser a blob
dumping tool.

Required behavior:

- Extract a single resource by type/name/language to a caller-selected output
  directory.
- Refuse unsafe output paths and report skipped writes.
- Add resource-origin metadata to extracted blobs: parent file hash, resource
  triplet, RVA, offset, size, type, language, and hash.
- Integrate resource payloads with existing embedded-content tools for images,
  XML, JSON, compressed data, PEM/cert-like blobs, and nested executables.
- Correlate resource strings with binary strings and import behavior. Examples:
  manifest privileges with UAC-related imports, event provider resources with
  ETW imports, model files with ML/GPU imports, and message tables with driver
  logging APIs.
- Detect resource anomalies: hidden PE/ELF/Mach-O/class/JAR payloads,
  high-entropy custom resources, compressed archives under custom names,
  extension/magic mismatch, enormous resource-to-file-size ratio, and resource
  data outside `.rsrc`.

Tests:

- Extraction tests that verify filenames are deterministic and safe.
- No-write tests for path traversal and symlink-sensitive output targets.
- Embedded-content integration tests using generated resources containing PNG,
  XML manifest, gzip, ZIP, and nested PE magic.
- Correlation tests where known imports and resources should produce a
  combined finding.
- Negative tests proving normal icons, PNGs, and compressed assets are not
  over-labeled as suspicious without additional evidence.

### 4. Certificate Table And Authenticode Summary

Implement static certificate table parsing before full trust validation.

Required output:

- Certificate table presence, file offset, size, entry count, and alignment.
- WIN_CERTIFICATE fields: length, revision, certificate type, payload size,
  payload hash, and parser warnings.
- PKCS#7/CMS structural summary when parsable: signer count, certificate
  subjects/issuers, serials, validity dates, digest algorithms, signing time,
  timestamp countersignature presence, and chain depth.
- PE checksum value and calculated checksum status.
- Authenticode digest coverage status: whether the certificate table is
  excluded from hashing and whether overlay bytes are inside or outside the
  signed region.
- Trust policy label: structural_only, chain_unverified, trusted_by_platform,
  invalid_signature, malformed_certificate_table, unsigned, or ambiguous.

Tests:

- Generated unsigned fixture.
- Signed fixture from a redistributable source or test-generated certificate.
- Fixture with certificate table alignment padding.
- Fixture with malformed length, truncated certificate payload, and multiple
  certificate entries.
- Tests that distinguish certificate table from arbitrary PKCS#7-like overlay
  bytes.
- Optional platform validation tests gated behind environment variables because
  local certificate stores differ.

### 5. Section-Aware Triage For Large PE Files

The current triage path can miss import/resource evidence when a large PE is
analyzed through an early byte window. Add PE-directory-aware reads so summary
features are collected from data directories under budget.

Required behavior:

- Read DOS, NT, optional headers, section table, and selected data directories
  directly by offset.
- For large files, load only the sections and directory ranges needed for
  imports, exports, resources, debug/PDB, TLS, load config, certificate table,
  and CLR metadata.
- Separate whole-file entropy from section entropy and resource entropy.
- Surface stop reasons clearly: max bytes, max resources, max imports,
  truncated directory, unmapped RVA, and unsupported directory.
- Prefer structured PE evidence over generic byte-window strings when filling
  triage symbols, signing, resources, and container summaries.

Tests:

- Regression test where a large driver imports kernel APIs and has resource
  data beyond the initial read budget.
- Large synthetic PE fixture with imports/resources placed after a large
  padding section.
- Tests that triage summary imports match `symbols` command imports for normal
  PE files within configured budgets.
- Tests that resource summaries are present even when full string scanning is
  capped.
- Performance tests with bounded wall-clock expectations for large resource
  libraries.

### 6. Python Tools, CLI, And Agent Integration

Expose PE resource and certificate capabilities to Python memory tools and
agent flows.

Proposed tools:

- `pe_list_resources`: enumerate resource metadata with filters and budgets.
- `pe_view_resource`: decode or preview one resource by type/name/language.
- `pe_extract_resource`: extract one resource safely with origin metadata.
- `pe_decode_version_info`: return normalized VERSIONINFO records.
- `pe_view_manifest`: return manifest XML plus structured security and
  compatibility fields.
- `pe_list_message_table`: decode message table entries under budget.
- `pe_list_event_templates`: summarize WEVT_TEMPLATE providers and event IDs.
- `pe_summarize_certificates`: summarize certificate table and Authenticode
  structure.
- `pe_resource_risk_report`: correlate resources, imports, sections, signing,
  entropy, and embedded-content findings into ranked findings.

CLI expectations:

- `glaurung pe resources <file>` for compact and JSON resource listings.
- `glaurung pe resource <file> --type ... --name ... --language ...` for a
  single resource preview.
- `glaurung pe manifest <file>` for manifest-focused output.
- `glaurung pe version <file>` for version metadata.
- `glaurung pe certs <file>` for certificate summary.
- Existing `triage`, `symbols`, `kickoff`, and agent workflows should consume
  these summaries without requiring the user to know every specialized command.

Agent expectations:

- Agent context should include top resource types, decoded manifest, decoded
  version info, certificate summary, and resource anomalies.
- Agent prompts should receive compact evidence, not raw resource blobs.
- Suspicious findings should include source anchors: resource triplet, section,
  offset, RVA, hash, and related imports or strings.
- Benign resource-heavy binaries should be labeled as resource-heavy, not
  suspicious, unless there is correlation with risky behavior.

Tests:

- Python tool unit tests for each input model, validation path, and bounded
  output model.
- CLI JSON tests with generated fixtures.
- CLI human-output snapshot tests for daily-use readability.
- KB tests proving resource, certificate, manifest, and version nodes are added
  with stable IDs and evidence edges.
- Agent toolset tests proving PE agents can access resource tools without
  receiving raw large blobs.
- Live LLM tests should remain gated and should assert that resource evidence is
  summarized, cited, and not over-expanded.

### 7. Robustness, Fuzzing, And Corpus Smoke Runs

Treat PE resources as adversarial input. Resource directories are tree-shaped,
offset-rich, and easy to weaponize against parsers.

Required behavior:

- Parser never panics on malformed resource directories.
- Parser returns partial results with warnings.
- Parser enforces independent budgets for resource traversal, resource data
  reads, typed decoding, and extraction.
- Parser handles resource-only files, signed files, drivers, managed PE files,
  and empty or placeholder files.
- Corpus smoke runner records coverage metrics without storing proprietary
  payload bytes in repo.

Tests:

- Rust fuzz targets for resource directory traversal and VERSIONINFO decoding.
- Mutation tests for counts, offsets, directory/data high bits, name offsets,
  language IDs, and data sizes.
- Property tests for monotonic budget behavior: lowering a budget can truncate
  results, but must not increase reported counts or hide warnings incorrectly.
- Corpus smoke tests gated by environment variables:
  - OS resource library smoke.
  - Windows Update driver package smoke.
  - Resource-only MUI smoke.
  - Managed PE smoke.
  - Signed PE smoke.
  - Malware/packed PE smoke.
- Smoke outputs should include totals, warning counts, top resource types,
  parse failure examples, and median/percentile runtime.

## Data Model Additions

Recommended Rust and Python output concepts:

```text
PeResourceSummary
  type_id, type_name
  name_id, name
  language_id, language_name
  codepage
  rva, file_offset, section_name
  size, entropy, sha256, magic
  decoded_kind, decoded_summary
  warnings

PeResourceDirectorySummary
  total_types, total_named_entries, total_id_entries
  total_leaves, max_depth
  resource_bytes_total
  resources_by_type
  warnings, stop_reasons

PeVersionInfo
  fixed_file_info
  string_tables
  translations
  normalized_product_version
  normalized_file_version
  warnings

PeManifestSummary
  assembly_identity
  requested_execution_level
  ui_access
  dpi_awareness
  compatibility_guids
  dependencies
  warnings

PeCertificateSummary
  certificate_table_present
  table_offset, table_size
  entries
  checksum_status
  authenticode_structure_status
  trust_policy_label
  warnings
```

## Milestones

### Milestone 1: Enumerate And Preview

- Add Rust resource traversal.
- Add `pe_list_resources` Python tool.
- Add CLI JSON and human output for resource listings.
- Test generated fixtures, malformed fixtures, and one optional resource-heavy
  smoke corpus.

Acceptance:

- Resource-heavy binaries list top resource types and counts without dumping raw
  bytes.
- Resource-only files parse cleanly.
- Malformed directories return warnings, not panics.

### Milestone 2: Decode Common Metadata

- Decode VERSIONINFO, MANIFEST, STRINGTABLE, MESSAGETABLE, MUI, and basic image
  resources.
- Add manifest/version/message CLI commands.
- Add typed KB nodes and evidence edges.

Acceptance:

- Version and manifest summaries are stable enough for triage and agent context.
- Message/event resources are visible in driver packages.
- Normal resource-heavy binaries are not mislabeled as packed solely because of
  large compressed image or icon resources.

### Milestone 3: Certificates And Signing

- Parse certificate table entries.
- Summarize PKCS#7/CMS structure where possible.
- Distinguish unsigned, structurally signed, malformed, and ambiguous cases.

Acceptance:

- Signed PE summaries include certificate table and signer metadata.
- Malformed certificate tables do not crash parsing.
- Triage signing output uses structured certificate evidence.

### Milestone 4: Triage And Agent Integration

- Make triage section-aware for large PE files.
- Add PE resource risk report.
- Prime PE-focused agents with compact resource, manifest, version, certificate,
  and anomaly evidence.

Acceptance:

- Large drivers retain import/resource evidence under normal triage budgets.
- Agent reports cite resource triplets and offsets.
- Daily-use CLI output is compact but actionable.

### Milestone 5: Corpus Confidence

- Add optional corpus smoke runner.
- Track parse success, warnings, median runtime, top resource types, and
  representative failures.
- Use smoke failures to drive parser hardening and decoder expansion.

Acceptance:

- Generated fixtures remain the source of deterministic CI truth.
- Local corpora provide broad confidence without entering public git.
- Failures produce actionable samples, not unbounded logs.

## Next Ten Implementation Items

1. Add generated PE resource fixture build support with RC, manifest, icon,
   string table, message table, version info, and custom RCDATA.
2. Implement Rust resource directory traversal with budgets and warnings.
3. Add Rust tests for resource traversal, malformed directories, and budget
   behavior.
4. Expose `pe_list_resources` as a Python memory tool with KB nodes.
5. Add `glaurung pe resources` JSON and human output.
6. Decode VERSIONINFO and MANIFEST with generated fixture tests.
7. Add STRINGTABLE and MESSAGETABLE decoding for driver/user-mode resources.
8. Add certificate table structural parsing and unsigned/signed fixture tests.
9. Make triage use section-aware PE directory reads for imports and resources.
10. Add optional corpus smoke tests and a concise smoke report format.
