# Audit: docs/parsers/, docs/formats/, docs/syscalls/, docs/triage/

## Executive summary (read this first)

1. This is the best-maintained corner of the docs tree seen so far: nearly every file in scope
   already carries an accurate `> **Status: ...**` self-classification banner, added in commit
   `0ec35a2e` (2026-08-07, "docs: overhaul documentation and examples"). I verified dozens of
   concrete claims (CLI flags, exit codes, function names, config field names/defaults, test
   file paths, spec-file paths) against source and they check out.
2. **Ground truth on parsers:** `src/formats/` only owns ELF, PE, Android APK/AXML/DEX, and
   SELinux sepolicy (`src/formats/{elf,pe,apk,axml,dex,sepolicy}`). There is **no**
   `src/formats/macho`, `dotnet`, `wasm`, `python`, `archive`, or `java`. Mach-O, .NET/CIL, Lua,
   Go, Java classfiles, and archive/compression handling live as narrower helpers in
   `src/analysis/`, `src/symbols/`, `src/triage/`, or the Python package. WASM and CPython
   bytecode have **zero** dedicated parser modules anywhere — only magic/signature detection in
   `src/triage/`.
3. The nine `elf-*`/`macho-*`/`pe-*` "consolidation-plan" / "migration-guide" / "technical-design"
   docs plus the nine parser-family `README.md` files (android, archive, dotnet, elf, macho,
   pe-coff, python, wasm) are almost all correctly labeled `historical design record` /
   `design-proposal`, and the labels are accurate: ELF and PE consolidation actually happened
   (the module trees match the plans); the Mach-O consolidated module was proposed and **never
   built**; archive/wasm/python/dotnet were pure proposals from day one. `docs/parsers/java/README.md`
   is the one exception — it's labeled `living capability ledger` and it earns that: I cross-checked
   ~57 `java_*` tool names, `run_java_{triage,security,recovery}_analysis`, `parse_java_class_bytes`,
   `src/analysis/java_class.rs`, and the `java/glaurung-jvm-tools` Maven bridge, all present.
4. `docs/parsers/README.md` (the index) is excellent and current: verified its CLI examples
   (`classfile`, `luac`, `pe resources/manifest/version` with exit code 4 on absent resource,
   `--tree` advertised-but-unwired) line-for-line against `python/glaurung/cli/commands/{classfile,luac,pe}.py`.
5. `docs/triage/README.md`, `packer-config.md`, and `similarity.md` (the three non-historical
   triage docs) are exactingly accurate: `TriageConfig.packers` field names/defaults match
   `src/triage/config.rs` exactly; the CTPH size-based parameter table matches
   `ctph_recommended_params_py` in `src/python_bindings/similarity.rs` exactly (16 KiB / 1 MiB
   cutoffs, `(8,4,8)`/`(16,5,16)`/`(32,6,16)`); the documented "`--sim`/`--tree` advertised but not
   wired to the formatter" bug is real — `args.sim` and `args.tree` are never read in
   `triage.py`'s `execute()`.
6. The other six `docs/triage/*.md` files (`IMPLEMENTATION.md`, `ADDITIONAL_FEATURES.md`,
   `ADVANCED-FEATURES.md`, `DETAILED_IMPLEMENTATION_PLAN.md`, `RECOMMENDATIONS.md`,
   `SIGNATURE_DESIGN.md`) are all correctly banner-labeled historical design notes from Sept 2025,
   and **substantially duplicate each other** (overlay handling, Rich header analysis, certificate
   validation, deep symbol analysis all appear in 2-4 of them independently). Some proposals
   shipped since (overlay → `src/triage/overlay.rs`, 521 lines; Rich header →
   `src/triage/rich_header.rs`, 443 lines); others didn't (Authenticode validation:
   `src/triage/signing.rs` is 17 lines; scriptable/WASM-sandboxed signatures: not implemented).
7. `docs/syscalls/` (3 files) is genuinely current, not orphaned: it is prose methodology/evidence
   guidance with **zero** number tables of its own (0 markdown-table rows in `linux.md`/`windows.md`),
   correctly pointing at kernel source and at the real, tested Windows syscall-atlas tools
   (`python/glaurung/llm/tools/windows_syscall_{atlas_diff,handler_correlate,stub_atlas}.py`, each
   with a matching test). The real raw syscall tables (`reference/specifications/kernel/*.tbl`,
   `*.master`, `linux_syscalls.h`) are vendored reference data that **no code loads** — orphaned,
   but out of this scope's docs (they're not `.md` files under audit).
8. `docs/formats/` (4 files) is a small, current, high-quality reference layer that explicitly does
   not duplicate `docs/parsers/` — it states a "validation boundary" rule (module + fixture + test)
   and each concrete claim I checked (12 `compiler_detection.rs` function names, Android
   packed-relocation/PAC-BTI/DEX/AXML/APK/sepolicy claims, sepolicy header field layout) matched
   source exactly.
9. Two broken spec-file references found by direct existence check: `docs/parsers/archive/README.md`
   cites `/reference/specifications/archive/archive.h` (does not exist — no libarchive header was
   ever vendored); `docs/parsers/macho/README.md` cites
   `/reference/specifications/macho/golang_macho.go` (the real file is at
   `reference/specifications/elf/golang_macho.go` — wrong directory).
10. `triage-parsers-extra` (`goblin`+`pelite`, Cargo.toml line 80) is real and matches
    `docs/triage/IMPLEMENTATION.md`'s feature table exactly. Per CLAUDE.md it was broken (did not
    compile) from 2025-09-01 until fixed by `114a5c4c` ("solver: fix all three backends, and gate
    the 11 feature configurations nobody built"); the file itself (`src/triage/parsers.rs`) even
    carries a code comment documenting the compile failure. It only ever does binary
    parse-success/fail corroboration for the triage confidence score — it is not, and was never
    described by these docs as, a second deep parser.
11. `JVM_AGENTIC_ANALYSIS_PLAN.md` (3277 lines, the largest file in scope) is a live implementation
    diary that explicitly disclaims its own older "Current State" passages as potentially stale
    ("Treat named source and focused tests as authoritative") — an unusually honest self-audit
    already baked in.
12. No dead/renamed source paths were found among the "current" (non-historical) docs. All
    file-path, function-name, CLI-flag and CLI-subcommand claims I spot-checked in the
    non-historical docs matched current source; failures were confined to the two spec-file paths
    (#9) inside historical design-proposal docs, which don't claim to be current anyway.

---

## Per-file table

Legend for "last commit": all 37 files show `c902c115 2026-08-11` as the literal last commit
(a repo-wide "snapshot: preserve complete primary working tree" commit — see Cross-cutting
findings). I additionally give the last *substantive content* commit and the creation commit,
since the snapshot commit is uninformative on its own.

| path | lines | last commit / real last edit / created | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `docs/parsers/README.md` | 210 | c902c115 2026-08-11 / content rewritten by c902c115, banners by 0ec35a2e 2026-08-07 / e4f5186c 2025-08-31 | index | current | `pe resources` exit-4-on-absent, `--tree` unwired, `src/formats/mod.rs` module list (`apk,axml,dex,elf,pe,sepolicy`), test commands (`cargo test formats::elf`, `python/tests/test_classfile.py`) all verified against source | keep |
| `docs/parsers/elf/README.md` | 208 | same pattern | reference | historical (self-labeled, accurate) | banner: "predates the owned ELF parser"; `src/formats/elf/` does exist with 12 submodules matching the real API, this doc's illustrative types are separate | keep (as archive), link from index already present |
| `docs/parsers/elf-consolidation-plan.md` | 357 | same | design-proposal | historical (accurate) | banner correct: `src/formats/elf/{headers,sections,segments,symbols,dynamic,notes,relocations,packed_relocations,...}.rs` all exist, consolidation plan was executed | keep |
| `docs/parsers/elf-migration-guide.md` | 596 | same | design-proposal | historical (accurate) | banner: "not revalidated against current ELF API" — correctly hedged | keep |
| `docs/parsers/elf-technical-design.md` | 575 | same | design-proposal | historical (accurate) | banner: "design snapshot, not the current Rust API" | keep |
| `docs/parsers/pe-coff/README.md` | 283 | same | reference | historical (self-labeled, accurate) | banner correct; real API is `src/formats/pe/{headers,sections,types,utils,mod}.rs` + `directories/{debug,export,import,resource,tls}.rs`, confirmed via `pe resources/manifest/version` CLI | keep |
| `docs/parsers/pe-coff/WINDOWS_RESOURCES_CAPABILITIES_TEST_PLAN.md` | 447 | same, created 4580392f 2026-05-16 | roadmap/plan | historical (self-labeled: "Much of this roadmap has since been implemented") | matches `directories/resource.rs` and `pe resources/manifest/version` CLI presence | keep, low priority to prune |
| `docs/parsers/pe-consolidation-plan.md` | 508 | same | design-proposal | historical (accurate) | consolidation was executed, `src/formats/pe/` matches | keep |
| `docs/parsers/pe-migration-guide.md` | 627 | same | design-proposal | historical (accurate) | banner correctly hedges code samples as archival | keep |
| `docs/parsers/pe-technical-design.md` | 762 | same | design-proposal | historical (accurate) | banner correct | keep |
| `docs/parsers/macho/README.md` | 322 | same | reference | historical (self-labeled, accurate) | confirmed: no `src/formats/macho`; Mach-O handled by `src/symbols/macho.rs` (288 lines), `src/analysis/macho_stubs.rs`, `src/symbols/analysis/macho_env.rs`, triage sniffers | keep |
| `docs/parsers/macho-consolidation-plan.md` | 302 | same | design-proposal | historical (accurate — proposal never built) | banner: "proposed consolidated `src/formats/macho` module was not implemented" — confirmed by `git log --all -- 'src/formats/macho*'` (zero hits) | keep |
| `docs/parsers/macho-migration-guide.md` | 545 | same | design-proposal | historical (accurate) | banner: "targets an unimplemented consolidated parser" | keep |
| `docs/parsers/macho-technical-design.md` | 514 | same | design-proposal | historical (accurate) | banner correct; cites `/reference/specifications/macho/golang_macho.go` — **broken, file is actually at `reference/specifications/elf/golang_macho.go`** | revise: fix the one broken spec-file path, else keep |
| `docs/parsers/android/README.md` | 291 | same | reference | historical (self-labeled, accurate) | banner correct; current owned modules are `src/formats/{apk,axml,dex,sepolicy}` — confirmed by `docs/formats/android.md` which is the actually-current version of this content | merge-into `docs/formats/android.md` (that file is the accurate, current successor); keep this as historical if merged content preserves anything unique |
| `docs/parsers/archive/README.md` | 145 | same | design-proposal | historical (accurate) | banner correct: no `src/formats/archive`; triage does bounded container detection only (`src/triage/containers.rs`, `recurse.rs`). Broken ref: `/reference/specifications/archive/archive.h` does not exist (only `ZIP_APPNOTE.TXT`, `tar_format.html`, `pax_format.html`, `magic_archive_signatures.txt` are present) | revise: drop/fix the `archive.h` reference line |
| `docs/parsers/dotnet/README.md` | 220 | same | design-proposal | historical (accurate) | banner correct; real .NET support is `src/analysis/cil_metadata.rs` (CIL metadata parser, added by PR #210, `0880f2d7`), not a `src/formats/dotnet` module; all 4 cited spec files exist | keep |
| `docs/parsers/python/README.md` | 254 | same | design-proposal | historical (accurate) | banner correct; confirmed zero `*.rs` files implementing marshal/code-object parsing anywhere in `src/`; only header/magic detection in `src/triage/` | keep |
| `docs/parsers/wasm/README.md` | 145 | same | design-proposal | historical (accurate) | banner correct; confirmed zero `wasm.rs` parser module ever existed (`git log --all -- '*wasm*.rs'` → empty); only `Format::Wasm` detection in triage. All 4 cited spec files + sample `.wasm` fixture exist | keep |
| `docs/parsers/java/README.md` | 751 | same | reference | current / living ledger | verified ~57 `java_*` LLM tools in `python/glaurung/llm/tools/`, `src/analysis/java_class.rs` (666 lines), `parse_java_class_bytes` PyO3 binding, `run_java_{triage,security,recovery}_analysis` in `java_runner.py`, CLI `glaurung java {triage,security,recovery}` all present as claimed | keep, this is the reference model other parser docs should follow |
| `docs/parsers/java/JVM_AGENTIC_ANALYSIS_PLAN.md` | 3277 | same, last real content 389b4065 2026-05-15, created bb7b2f5f 2026-05-15 | roadmap/plan | mostly-current (self-disclaiming) | opens with its own caveat: "Earlier 'Current state' passages...can lag the capability ledger in README.md. Treat named source and focused tests as authoritative." — an honest built-in staleness warning; `src/analysis/java_class.rs` and `java/glaurung-jvm-tools/` (Maven project, ASM/CFR/Vineflower bridge) both confirmed to exist | keep as record; do not treat as spec |
| `docs/formats/README.md` | 36 | same, created 0ec35a2e 2026-08-07 | index | current | states the "validation boundary" rule (module + fixture + test); correctly distinguishes itself from `docs/parsers/` | keep |
| `docs/formats/android.md` | 135 | same, created aeaa803a 2026-07-13 | reference | current | 12 concrete function/module claims (`ElfParser::android_packed_relocations()`, `relr_relocations()`, `scan_aarch64_prologue_function_starts`, `ApkReader`, `decode_ioc`, `is_sepolicy`, `parse_header`) all verified present in `src/formats/elf/`, `src/analysis/cfg/scan.rs`, `src/formats/apk/mod.rs`, `src/analysis/linux_ioctl.rs`, `src/formats/sepolicy/mod.rs`; test commands (`cargo test --test android_dex_triage` etc.) verified to exist under `tests/` | keep; this is the up-to-date superset of `docs/parsers/android/README.md` |
| `docs/formats/compiler-artifacts.md` | 132 | same, created ef1aa85c 2025-09-03 | reference | current | all 12 named functions (`detect_language_and_compiler_with_path`, `detect_from_rich_header`, `has_go_buildid`, etc.) confirmed present via `grep` in `src/triage/compiler_detection.rs` | keep |
| `docs/formats/sepolicy-policydb-format.md` | 117 | same, created cf979067 2026-07-13 | reference (implementation spec) | current | header field layout (`magic 0xf97cff8c`, `"SE Linux"`, version-dependent `ocon_num` 7@v30/9@v33-35) matches `src/formats/sepolicy/mod.rs` `parse_header`/`is_sepolicy`; explicitly marks itself research-beyond-header as not-yet-implemented | keep |
| `docs/syscalls/README.md` | 21 | same, created 0ec35a2e 2026-08-07 | index | current | correctly frames itself as non-authoritative for numbers; points to `docs/design/` for unimplemented dispatch models and `docs/windows-port/README.md` for shipped coverage | keep |
| `docs/syscalls/linux.md` | 69 | same, created c5c7d10d 2025-09-08 | reference | current | zero syscall-number tables (verified: 0 markdown table rows); correctly states no shipped Linux syscall decoder/emulator exists | keep |
| `docs/syscalls/windows.md` | 72 | same, created c5c7d10d 2025-09-08 | reference | current | references real, tested tools: `windows_syscall_atlas_diff.py`, `windows_syscall_handler_correlate.py`, `windows_syscall_stub_atlas.py`, each with a matching `python/tests/test_windows_syscall_*_tool.py` | keep |
| `docs/triage/README.md` | 203 | same, created dd84d822 2025-08-31 | user-guide | current | exhaustively verified: exit codes 0/2/3 match `triage.py`; `--max-read-bytes`/`--max-file-size`/`--max-depth` defaults (10485760/104857600/1) match `add_arguments`; "`--sim`/`--tree` advertised but not wired" confirmed true (`args.sim`/`args.tree` never read in `execute()`); `detect-packer` JSON-always-returns-0 confirmed in `detect_packer.py` | keep |
| `docs/triage/packer-config.md` | 63 | same, created 258f63d9 2025-09-03 | reference | current | `PackerConfig` field names and defaults (`scan_limit=524288`, `upx_detection_weight=0.6`, `upx_version_weight=0.2`, `packer_signal_weight=0.30`) match `src/triage/config.rs` lines 864-929 exactly; correctly notes `detect-packer` CLI uses a separate code path (`glaurung.llm.kb.packer_detect`), not `TriageConfig.packers` | keep |
| `docs/triage/similarity.md` | 84 | same, created 258f63d9 2025-09-03 | reference | current | CTPH size-parameter table (`<16KiB→(8,4,8)`, `<1MiB→(16,5,16)`, `else→(32,6,16)`) matches `ctph_recommended_params_py` in `src/python_bindings/similarity.rs` exactly; all cited functions (`ctph_hash_path`, `ctph_similarity`, `ctph_pairwise_matrix`, `cluster_single_linkage`, `ctph_top_k`) confirmed in `python/glaurung/similarity.py` and `_native/similarity.pyi` | keep |
| `docs/triage/IMPLEMENTATION.md` | 198 | same, created e4f5186c 2025-08-31 | roadmap/plan | historical (self-labeled, accurate) | banner correct; its feature-flag table (`triage-core`, `triage-heuristics`, `triage-containers`, `triage-parsers-extra`) matches `Cargo.toml` `[features]` exactly | keep |
| `docs/triage/ADDITIONAL_FEATURES.md` | 421 | same, created 9bf29ef0 2025-09-02 | design-proposal | historical (self-labeled, accurate) | proposes overlay handling, Rich header, Authenticode, resource analysis — overlay and Rich header now shipped (`src/triage/overlay.rs` 521 lines, `rich_header.rs` 443 lines); Authenticode still thin (`signing.rs` 17 lines) | archive — heavy duplication with `ADVANCED-FEATURES.md`, `DETAILED_IMPLEMENTATION_PLAN.md`, `RECOMMENDATIONS.md` (see cross-cutting) |
| `docs/triage/ADVANCED-FEATURES.md` | 673 | same, created 08f80772 2025-09-01 | design-proposal | historical (self-labeled, accurate) | proposes "Binary DNA Fingerprinting", clustering, control-flow analysis — overlaps `ADDITIONAL_FEATURES.md` and `RECOMMENDATIONS.md` on fuzzy hashing/rich metadata/certificate topics | archive — duplicate coverage |
| `docs/triage/DETAILED_IMPLEMENTATION_PLAN.md` | 886 | same, created 9bf29ef0 2025-09-02 | design-proposal | historical (self-labeled, accurate) | step-by-step code sketches for overlay + Rich header (both since shipped, real implementations diverge from sketches) | archive — largest of 4 overlapping wishlists |
| `docs/triage/RECOMMENDATIONS.md` | 258 | same, created 9bf29ef0 2025-09-02 | design-proposal | historical (self-labeled, accurate) | prioritized list overlapping the same feature set as the 3 files above (scriptable signatures, deep symbol analysis, format-specific deep parsing, plugin architecture) | archive — duplicate coverage, merge historical value into one file if kept at all |
| `docs/triage/SIGNATURE_DESIGN.md` | 497 | same, created 9bf29ef0 2025-09-02 | design-proposal | historical (self-labeled, accurate) | proposes 3-tier signature system incl. sandboxed WASM scripting; confirmed not implemented (`src/triage/signatures.rs` is 238 lines of static heuristics, no WASM sandbox, no script tier) | keep as historical, or archive alongside the other 4 |

## Directory-level summaries

### `docs/parsers/`
21 files, ~8,900 lines. Two very different populations coexist under one directory:
- **The index** (`README.md`) plus the **Java** subtree (`java/README.md`,
  `JVM_AGENTIC_ANALYSIS_PLAN.md`) are genuinely current, actively maintained, and unusually
  well-verified against source (this is the area with real ongoing engineering investment —
  57 LLM tools, a bundled Maven decompiler bridge, agentic runners).
- **Everything else** — the 9 `README.md` files for android/archive/dotnet/elf/macho/pe-coff/
  python/wasm, and the 9 `elf-*`/`macho-*`/`pe-*` consolidation-plan/migration-guide/
  technical-design docs — is a coherent, self-aware historical corpus from a Sept 2025 "let's
  build unified parsers" push. ELF and PE consolidation happened as planned (real
  `src/formats/{elf,pe}/` trees exist and roughly match the plans' module lists). Mach-O
  consolidation was planned in equal detail and never executed. Archive/.NET/Python/WASM were
  proposals from day one and never got a `src/formats/` module at all.
- A clean structure: keep `README.md` as the single index (it already does this job well); keep
  `java/` as the living reference; either delete the 9 historical `README.md`s and 9
  consolidation/migration/design docs (their unique value — format background, spec citations —
  already lives in `docs/formats/` for Android, or is fully superseded by the real module for
  ELF/PE) or move them verbatim under a `docs/parsers/_archive/` (or repo-wide `docs/_history/`)
  directory so the index doesn't have to keep threading "historical" disclaimers through 8,000+
  lines of proposal text next to 210 lines of live index.

### `docs/formats/`
4 files, 420 lines. Small, current, and does not duplicate `docs/parsers/` — it explicitly states
a "validation boundary" (module + fixture + test) that the parser docs don't state as crisply, and
in practice `docs/formats/android.md` is a **more current and detailed** rewrite of
`docs/parsers/android/README.md`'s live content (same subject, current numbers, actual function
names) while the parsers/android page is frozen 2025-era proposal text. This directory is close to
ideal already; the only structural improvement is formally absorbing the still-live parts of
`docs/parsers/android/README.md` into it and leaving a pointer instead of two files describing the
same modules from two eras.

### `docs/syscalls/`
3 files, 162 lines. Not a data reference (no number tables at all) — it's a short, accurate
"how to reason about syscall evidence" guide plus a pointer to the real syscall-atlas LLM tools.
It is not orphaned: the Windows page's tool references are real and tested. It is, however, thin
relative to what a reader might expect from the directory name; a reader wanting actual raw
syscall tables has to go to `reference/specifications/kernel/` (out of scope here, vendored,
unused by any code path I could find — worth flagging to whoever owns `reference/`). Clean
structure: keep as-is, 3 files is right-sized for what this material actually is.

### `docs/triage/`
9 files, 3,281 lines. One live user-guide/reference cluster (`README.md`, `packer-config.md`,
`similarity.md` — 350 lines total, exceptionally accurate) sits inside a directory dominated
(2,933 lines, 89%) by six overlapping Sept-2025 wishlist/plan documents that were never merged
with each other and were never fully executed. `IMPLEMENTATION.md`,
`DETAILED_IMPLEMENTATION_PLAN.md`, `ADDITIONAL_FEATURES.md`, `ADVANCED-FEATURES.md`, and
`RECOMMENDATIONS.md` in particular propose overlapping subsets of the same ~10 features (overlay
handling, Rich header, Authenticode/certificates, resource analysis, fuzzy hashing/clustering,
scriptable signatures, deep symbol analysis) with no cross-references distinguishing what shipped
from what didn't per-item — only file-level banners. `SIGNATURE_DESIGN.md` stands a bit apart
(one coherent proposal, not a checklist mashup). Clean structure: keep the 3 live files; collapse
the 6 historical files into a single `docs/triage/_history/roadmap-2025.md` (or delete) — the
useful signal ("overlay and Rich header shipped, Authenticode/scriptable-signatures did not") is
currently something a reader has to reconstruct file-by-file rather than something any one file
states.

## Cross-cutting findings

**Duplicated coverage:**
- `docs/parsers/android/README.md` (291 lines, historical/frozen) vs `docs/formats/android.md`
  (135 lines, current) describe the same modules (`src/formats/{apk,axml,dex,sepolicy}`,
  packed relocations, PAC/BTI). The `formats/` version is strictly better and newer (created
  2026-07-13 vs 2025-08-31) — the `parsers/` version should be retired or reduced to a pointer.
- `docs/triage/ADDITIONAL_FEATURES.md`, `ADVANCED-FEATURES.md`, `DETAILED_IMPLEMENTATION_PLAN.md`,
  `RECOMMENDATIONS.md` all independently propose overlay handling, Rich-header analysis, and
  certificate/Authenticode validation (3-4x redundant coverage of the same three features across
  four files, ~2,200 lines combined).
- Nine parser-family `README.md`s plus nine `elf-*/macho-*/pe-*` design docs cover ELF/PE/Mach-O
  three times each (README + consolidation-plan + migration-guide + technical-design, minus
  migration-guide for android/archive/dotnet/python/wasm/java which only get one README each).

**Contradictions between docs and code:** none found among the "current"-labeled docs — every
concrete claim checked (function names, CLI flags, exit codes, config defaults, feature flags,
test paths) matched source. The historical docs do "contradict" current code by design (that's
what makes them historical), but each one now carries a banner saying so, so this isn't a silent
contradiction — a reader is warned in the first 5 lines.

**Contradictions between docs:** `docs/parsers/android/README.md` (historical, implies deep
malware-analysis capability was the goal) reads differently in tone/scope from
`docs/formats/android.md` (current, precisely bounded "magic + header only" for sepolicy) — not a
factual contradiction once you notice the banners, but a naive reader skimming both could come
away with different pictures of sepolicy support.

**Broken references found (not previously known — new findings from this audit):**
- `docs/parsers/archive/README.md` line 18: `/reference/specifications/archive/archive.h` does
  not exist anywhere in the repo (checked `reference/specifications/archive/`, which has only
  `ZIP_APPNOTE.TXT`, `tar_format.html`, `pax_format.html`, `magic_archive_signatures.txt`).
- `docs/parsers/macho-technical-design.md` and `docs/parsers/macho/README.md` line 21:
  `/reference/specifications/macho/golang_macho.go` does not exist at that path; the actual file
  is `reference/specifications/elf/golang_macho.go` (misfiled under the wrong format directory,
  or the doc has the wrong path — either way it's currently a dead link).

**Knowledge that exists ONLY in docs and would be lost if deleted:**
- The **Mach-O, .NET, WASM, and Python-bytecode technical-design/consolidation docs** are the only
  place the intended data models (proposed Rust types, field layouts, phase plans) for those
  formats exist — none of that appears in code or tests since the modules were never built. If
  Glaurung ever revisits building a real Mach-O/.NET/WASM/Python parser, these documents are the
  only design record. This is explicitly why their banners say "retained to explain intent" rather
  than recommending deletion.
- `docs/triage/SIGNATURE_DESIGN.md`'s 3-tier signature architecture (compiled/runtime/scripted-WASM)
  is not implemented anywhere and exists only in this doc.
- `docs/parsers/pe-coff/WINDOWS_RESOURCES_CAPABILITIES_TEST_PLAN.md`'s original test-corpus
  planning (which binary shapes to source, why) predates and partially explains the current
  `pe resources/manifest/version` test fixtures — worth a skim before deleting even though "much
  of this roadmap has since been implemented."
- `docs/syscalls/linux.md` and `windows.md` contain genuinely useful, non-code-derivable
  **methodology** (how to bind a syscall claim to OS/build/arch/ABI, why a libc wrapper ≠ a
  syscall) that isn't written down anywhere else in the repo I found.

## Proposed new structure for this scope

```
docs/parsers/
  README.md                      keep — the live index; already good, minor: fix macho.rs golang ref via formats/android merge note
  java/
    README.md                    keep — living capability ledger, the model for the rest
    JVM_AGENTIC_ANALYSIS_PLAN.md keep — living diary, already self-disclaiming
  _archive/                       new — landing spot for retired design docs (or move to a repo-wide docs/_history/)
    elf-consolidation-plan.md      archived (rewrite of nothing, just relocated)
    elf-migration-guide.md         archived
    elf-technical-design.md        archived
    pe-consolidation-plan.md       archived
    pe-migration-guide.md          archived
    pe-technical-design.md         archived
    macho-consolidation-plan.md    archived
    macho-migration-guide.md       archived
    macho-technical-design.md      archived (fix golang_macho.go path before archiving)
    elf-README.md                  archived (was docs/parsers/elf/README.md)
    pe-coff-README.md              archived (was docs/parsers/pe-coff/README.md)
    pe-coff-WINDOWS_RESOURCES_CAPABILITIES_TEST_PLAN.md  archived
    macho-README.md                archived (was docs/parsers/macho/README.md)
    android-README.md              archived (was docs/parsers/android/README.md; superseded by docs/formats/android.md)
    archive-README.md              archived (fix or drop archive.h ref before archiving)
    dotnet-README.md               archived
    python-README.md               archived
    wasm-README.md                 archived

docs/formats/
  README.md                       keep — current index, states the validation-boundary rule
  android.md                      keep — current, supersedes parsers/android/README.md content
  compiler-artifacts.md           keep — current, verified against compiler_detection.rs
  sepolicy-policydb-format.md     keep — current implementation spec

docs/syscalls/
  README.md                       keep as-is
  linux.md                        keep as-is
  windows.md                      keep as-is

docs/triage/
  README.md                       keep — current, exceptionally accurate operator guide
  packer-config.md                keep — current
  similarity.md                   keep — current
  _archive/                        new
    IMPLEMENTATION.md              archived
    roadmap-2025-merged.md         merge of ADDITIONAL_FEATURES.md, ADVANCED-FEATURES.md,
                                    DETAILED_IMPLEMENTATION_PLAN.md, RECOMMENDATIONS.md
                                    (4 overlapping wishlists -> 1 file, dedup the ~10 repeated
                                    feature proposals, note per-item shipped/not-shipped status)
    SIGNATURE_DESIGN.md            archived (kept separate — it's coherent, not a checklist mashup)
```

## Ground truth for other auditors / the plan writer

- **`src/formats/` module list (real, from `src/formats/mod.rs`):** `apk`, `axml`, `dex`, `elf`,
  `pe`, `sepolicy`. That's it — no `macho`, `dotnet`, `wasm`, `python`, `archive`, or `java` module
  exists there.
- **Mach-O support** lives in `src/symbols/macho.rs` (288 lines), `src/analysis/macho_stubs.rs`,
  `src/symbols/analysis/macho_env.rs`, plus triage detection/sniffing — never a `src/formats/macho`.
- **.NET/CIL support** lives in `src/analysis/cil_metadata.rs` (added by PR #210, commit
  `0880f2d7`, "feat(analysis): .NET CIL metadata parser") — never a `src/formats/dotnet`.
- **WASM and CPython bytecode have no parser code anywhere in `src/`** — only
  `Format::Wasm`/CPython-bytecode magic detection in `src/triage/`. Confirmed via
  `git log --all -- '*wasm*.rs'` (zero commits ever) and equivalent checks.
- **`triage-parsers-extra` Cargo feature** = `["goblin", "pelite"]` (Cargo.toml line 80), used only
  in `src/triage/parsers.rs` for pass/fail corroboration of the triage confidence score (not a
  second deep parser). It was broken (didn't compile) from ~2025-09-01 until fixed by `114a5c4c`.
- **Triage CLI flags** (`python/glaurung/cli/commands/triage.py`): `--max-read-bytes` (default
  10,485,760), `--max-file-size` (default 104,857,600), `--max-depth` (default 1), `--sim`/
  `--no-sim` (exist but **not wired** into the formatter — dead flags), `--str-min-len`,
  `--str-max-samples`, `--str-lang`/`--no-str-lang`, `--str-max-lang-detect`, `--str-classify`/
  `--no-str-classify`, `--str-max-classify`, `--str-max-ioc-per-string`, `--tree` (exists, **not
  wired** into plain output — dead flag), `--strings-only-lang`. Exit codes: 0 success (possibly
  with warnings), 2 bad path/args, 3 exception during analysis.
- **`PackerConfig` fields** (`src/triage/config.rs`): `scan_limit=524288`,
  `upx_detection_weight=0.6`, `upx_version_weight=0.2`, `packer_signal_weight=0.30`. This is
  entirely separate from `glaurung detect-packer`, which uses
  `glaurung.llm.kb.packer_detect.detect_packer` and has no config surface.
- **CTPH parameter table** (`src/python_bindings/similarity.rs`): input `<16 KiB → (window=8,
  digest=4, precision=8)`; `16 KiB–<1 MiB → (16,5,16)`; `≥1 MiB → (32,6,16)`.
- **Full CLI subcommand list** (from `uv run glaurung --help`, corroborated in
  `python/glaurung/cli/main.py`): `triage, strings, symbols, disasm, cfg, ask, decompile, explain,
  name-func, repl, graph, detect-packer, diff, kickoff, patch, verify-recovery, export, undo, redo,
  xrefs, frame, strings-xrefs, view, find, bookmark, rename, comment, label, proto, journal,
  classfile, java, java-recovery-report, luac, pe, windows-risk, types, windows, locks, group`.
- **Java/JVM tooling scale:** 57 `java_*` files under `python/glaurung/llm/tools/`, a bundled Maven
  project (`java/glaurung-jvm-tools/`) wrapping ASM/CFR/Vineflower/JavaParser, and 3
  `run_java_{triage,security,recovery}_analysis` entry points wired to `glaurung java
  {triage,security,recovery}`. This is a much bigger, more actively developed surface than the
  ELF/PE/Mach-O consolidation efforts, and its docs are correspondingly the most current in this
  entire scope.
- **The mass-edit commit that added the self-classification banners across this scope is
  `0ec35a2e`** (2026-08-07, "docs: overhaul documentation and examples"); a later commit
  `c902c115` (2026-08-11, "snapshot: preserve complete primary working tree") is the literal
  `git log -1` result for every file in scope and did rewrite `docs/parsers/README.md` and
  `docs/triage/README.md` substantially (330/411 line diffs) — treat `c902c115` as the practical
  "last touched" commit, not as evidence the content is unreviewed since 2025.
