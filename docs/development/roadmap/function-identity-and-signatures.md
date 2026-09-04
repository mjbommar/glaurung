# Function identity and signature libraries: what is open

> **Kind:** plan · **Status:** proposed

The one live list of unfinished work across the function-identity ladder
(structural invariants, the canonical function representation, value
fingerprints, WARP GUIDs, the re-ranker) and the signature-library program
(harvesters, the `gsig/1` container, distribution, coverage). Everything
here was either measured and deferred, or scoped out on purpose, on
2026-09-02 and 2026-09-03; the records are
[`history/program-measures-2026-09-02.md`](../../history/program-measures-2026-09-02.md)
and [`history/sessions/2026-09-03-signature-libraries.md`](../../history/sessions/2026-09-03-signature-libraries.md).
The reference pages each keep a "Not done here" section for their own
component; this page is the union, with the precondition and the reason
for each item, so nothing is only findable by reading every page.

Rules from the [decompiler roadmap](README.md) apply: an item ticks only
when a production caller exists, and a measured rejection (`[r]`) is not
revived unchanged.

## What shipped, so the list below is read against it

Published set `base 2026.09.2` (serial 2): 446 libraries, 533,820
signatures, signed and content-addressed on `https://assets.glaurung.dev`.
Coverage measured on 2026-09-03: two thirds of library code in a static
binary from a harvested distro release; four fifths of library code in a
Windows system binary from a harvested build at 99.4 percent precision;
near zero on dynamically linked userland, by design.

## A. Integration: built but not consulted

These are the highest-value items because the data already exists.

- [ ] **WARP matcher in the analysis pass.** The 82 Windows GUID libraries
  (329,695 GUIDs) are fetched, cached and ingested into the KB, but discovery
  consults only FLIRT-kind blobs; `apply_flirt_overrides` has no GUID
  counterpart. Needed: compute GUIDs during discovery, look them up in the
  loaded WARP blobs (cache first, then KB), apply names under the same
  `set_by` and ambiguity rules. Precondition: none. Measured value: 68.1
  percent of all functions on a same-build Windows binary with zero wrong.
  Owner page: [`reference/signature-distribution.md`](../../reference/signature-distribution.md) "Not done yet".
- [ ] **PLT and import names in the referenced-name resolver.** The resolver
  uses symbol-table, DWARF and earlier FLIRT names; PLT stubs and import
  thunks are not fed in because their only source re-parses the object and
  discovery asserts a parse-count ceiling. Needed for dynamically linked
  binaries, where 17.6 percent of signatures (those with `crc_len == 0`)
  depend on it. Measured: 36 genuine false positives out of 127 names on
  Ubuntu `/usr/bin` came from exactly this class of small functions.
  Owner page: [`reference/function-signature-libraries.md`](../../reference/function-signature-libraries.md) "Not done here".
- [ ] **Minimum-size and confidence floor on FLIRT names.** Same evidence as
  above; a 16-fixed-byte floor was proven necessary for WARP (four false
  positives at 8) and the FLIRT path has no equivalent gate in the analysis
  pass.
- [ ] **Membership gate over the shipped libraries.** `identity_gate_build`
  exists and `match_warp_library` consults a gate when present; none is
  built for the published sets. About 380 KB for 337k GUIDs.
- [ ] **Re-ranker KB helper.** `rerank_candidates` needs `reference_calls`
  and `reference_groups`; `siglib` stores no call graph among library
  functions, so a helper today would decode with both context terms at
  zero. Precondition: a library call graph, obtainable from the `.a`
  relocation walk the harvester already performs.
  Owner page: [`reference/function-identity-rerank.md`](../../reference/function-identity-rerank.md) "Known gaps".

## B. Breadth: more sources for the same machinery

- [ ] **More distro cells.** The `base` matrix is Debian bookworm and trixie,
  Ubuntu jammy, noble and resolute, Alpine 3.20 and 3.21, on amd64 and
  arm64. Measured: a binary from an unharvested release matches nothing
  (Debian bookworm vs this box: 0 of 1,090), so every added release is
  coverage. Next: Fedora via koji `-static` RPMs, older Ubuntu LTS, i386 and
  riscv64 cells, uClibc-ng and Buildroot for firmware. The harvester and
  matrix spec (`tools/sig_matrix/base.toml`) take new rows without code.
- [ ] **More libraries per cell.** The ranked target list in the design page
  (OpenSSL, zlib, BusyBox, libcurl, SQLite, libxml2, Lua, libpng, PCRE2,
  zstd, brotli, lz4, then the firmware daemons) is only partly harvested.
- [ ] **MSVC CRT and STL patterns from an archive we own.** No unlinked MSVC
  objects exist on any machine or NAS tree we have. Needs a Visual Studio
  Build Tools or `xwin` install on a device where the licence was accepted,
  and a NOTICE review before publishing derived patterns. Third-party
  signature sets are not an option (decision of 2026-09-03).
- [ ] **PDB fetching for the Windows corpus.** The WARP libraries are bounded
  by the 7.3 GB local symbol cache: 169 of 5,408 Windows 11 PEs had a PDB.
  `glaurung.pdb_fetch.ensure_pdb_cached` already speaks the symbol-server
  protocol; pointing it at the roughly 5,000 misses is the largest single
  coverage gain available on Windows.
- [ ] **AArch64 and ARM32 WARP GUIDs.** `warp_functions_from_bytes` raises
  `UnsupportedArchitecture`; the ARM64 Windows images in the corpus produce
  nothing. Needs constant propagation for `adrp`+`add` relocatable pairs.
- [ ] **Rust: more toolchains, and the Go path.** Rust cross-toolchain
  transfer is zero (mangling and codegen both change), so each toolchain
  release is its own cell; harvest per `channel-rust-*.toml`. Go is solved by
  `gopclntab` recovery, not signatures, and that recovery is not yet wired
  as an identity scheme.
- [ ] **Cortex-M: remaining multilibs and the weak-alias case.** Six of the
  toolchain's multilibs are built; `fflush` naming as `fflush_unlocked`
  (newlib's cross-unit weak alias) is a known archive-only blind spot.

## C. The identity ladder's own next slices

- [ ] **Value fingerprints, slice two.** Callee-to-caller propagation (the
  literature's 0.08 Recall@1 lever and the only known answer to differential
  inlining) and AArch64 seeds. The interpreter is not the blocker.
  Owner page: [`reference/function-identity-values.md`](../../reference/function-identity-values.md) "What the next slice needs".
- [ ] **Corpus-frequency weights for value fingerprints.** Implemented,
  measured worse, not adopted; recorded so it is not re-tried unchanged.
  `[r]` in the sense above.
- [ ] **Re-ranker: the paper's adjacency terms.** Measured harmful on this
  corpus (8 cells up, 31 down); shipped as the non-default `revdecode_paper`
  preset. `[r]` unless the call-graph input changes.
- [ ] **CFR `nosize` on the cross-bitness lane, and LSH banding.** Both
  deferred until the corpus is large enough that a flat scan is the slower
  option (the schema survey's "flat scan until 1e5" guidance).
- [ ] **Tree edit distance on the region tree.** A true metric on recovered
  structure; blocked while `structure_v2` is under concurrent change.
- [ ] **Production fix for CFG wall-clock non-determinism.** Diagnosed in
  [`design/cfg-discovery-determinism-2026-09-02.md`](../../design/cfg-discovery-determinism-2026-09-02.md);
  the harness runs unbounded, production still uses the 100 ms per-function
  clock. Moves all four fixture baselines, so it lands between decompiler
  refreshes, not during one.

## D. Distribution and format

- [ ] **GitHub Releases mirror.** The publish tool prints the `gh release`
  commands for every set; none has been run. Sigstore attestations come
  free with immutable releases once the repository exists.
- [ ] **Delta channel.** Content addressing already means an unchanged blob
  is never re-fetched; a ClamAV-style diff is worth having only when full
  manifests become the complaint.
- [ ] **Zstd dictionary training.** Measured worth 2.45x to 2.70x per chunk
  on real prologues; not built because the whole database is 36 MiB.
- [ ] **SQL-indexed masked-prefix table (`siglib_flirt`, `siglib_reference`).**
  Schema-reserved, unpopulated; the in-memory scan is the cheaper option
  until a library set is far larger than today's.
- [ ] **FLIRT L3 tail-byte discriminator and WARP constraint disambiguation.**
  Schema-reserved; collisions at that level are reported ambiguous instead.
  Constraint disambiguation was measured useless for the one motivating
  case, so it is `[r]` until a new case appears.
- [ ] **Signing-key rotation drill.** The trusted-key directory supports
  several keys; a rotation has never been exercised end to end.

## E. Measurement debt

- [ ] **Whole-`/usr/bin` sweep.** `tools/measure_signature_coverage.py` ran
  the truth-scored subset (17 files); the full 2,191-file sweep without
  truth was killed at 55 minutes and claims nothing for the rest.
- [ ] **Cross-build Windows lane in the coverage tool.** Within one image
  every known module is at a library's own source build; the "same module,
  different build" cell is measured only in the WARP lane's own tests
  (0.27 to 0.37 across Windows 10 to 11).
- [ ] **A second Linux truth lane.** The round-trip trees' `addr2name` maps
  name only project code, so 55 of 62 FLIRT names there could not be
  graded. `dbgsym` packages for the harvested cells would fix this.
