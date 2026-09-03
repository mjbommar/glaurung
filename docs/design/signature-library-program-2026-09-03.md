# Signature library program — design and execution record, 2026-09-03

> **Kind:** design · **Status:** proposed
> Execution ledger at the end. Inputs: the sourcing/distribution/format research
> report (filed beside this page as
> `signature-library-program-2026-09-03/sourcing-and-distribution.md`),
> the Docker-builder and format survey, the NAS Windows survey, and measurements
> taken on this machine on 2026-09-03 against master `935b7db1`..`5e882019`.

## What the measurements settled

**The matcher is already precise; coverage is the whole problem.** With the
glibc 2.43 library built from this box's own `libc.a` (2,690 signatures, 0.3 s),
a stripped `gcc -O2 -static` binary gets 731 of 1,090 text functions named, 0
wrong, 16 correctly withheld as ambiguous. The same binary against glibc
libraries from Debian trixie, bookworm and bullseye scores 1, 0 and 0. At the
signature level, Ubuntu-vs-Debian identity is 0.2 percent, while adjacent
releases inside one distro line share 26 to 43 percent. The flags differ
(Ubuntu adds LTO, frame pointers, FORTIFY 3, CET). So one library per
(distro, release, arch, package version) is not a nicety; it is the unit of
usefulness, and the corpus is 10^5 to 10^6 signatures, not 10^3.

**JSON cannot carry that.** Measured over 15,534 real signatures: JSON costs
1,202 bytes per signature; a packed encoding with an interned string table 114;
packed plus zstd 52. At 10^6 signatures that is 1.2 GB versus 52 MB. The
library is also re-parsed from JSON on every `analyze()` call today, and it
does not ship in the wheel at all (the default path is cwd-relative).

**Zero-copy is not worth its cost.** `fast-flirt` loads 944k patterns in 361
ms including inflation and trie construction. A format that avoids a 0.4 s
once-per-session cost by imposing alignment and major-version churn (rkyv) or
a schema compiler (FlatBuffers) buys nothing here.

**Two defects only scale exposes.** The builder's ambiguity key includes
`function_len`, which the matcher never compares, so 268 keys (576 signatures,
3.7 percent) are indistinguishable at match time yet survive as distinct
entries. And 17.6 percent of signatures have `crc_len == 0`, the L1-only case
where FLIRT relies on referenced-name resolution, which `apply_flirt_overrides`
does not yet wire in.

**Windows has no unlinked objects anywhere on the NAS.** The corpus is 19,000
linked system PEs plus 5,369 keyed PDBs plus 400k vendor drivers. That is the
input for exact-match WARP libraries and for validation, not for masked
patterns. MinGW-w64 archives are free (ZPL) and now build (COFF support landed
at `5e882019`), but its import libraries are pure thunks and worthless; only
`libmingwex`, `libgcc` and `libstdc++` carry bodies. MSVC CRT patterns need a
Build Tools or `xwin` acquisition on a device where the licence was accepted.

## Sources on the NAS, surveyed 2026-09-03

`/nas4/data/binary-analysis/` (read-only) adds three things the box does not
have. `armtc/` is a full ARM GNU 13.2.1 `arm-none-eabi` toolchain with 780
static archives across every Cortex-M multilib (newlib `libc`, `libc_nano`,
`libm`, `libstdc++`, `libsupc++`, `libnosys`, and per-multilib `libgcc`), the
bare-metal signature source we lacked; its provenance is the vendor release,
not a build log. The round-trip trees (`rt-libopencm3/`, `rt-diffutils/`,
`rt-dpkg/`, `rt-sysvinit/`) and `decbench-holdout-source-rebuild-2026-08-06/`
(42 projects at O0, O2 and O2-noinline, including eight ARM EABI5 static
firmware projects) keep source, stripped and unstripped outputs and
address-to-name maps, so they are validation ground truth, though they discard
the intermediate objects. `glaurung/binaries/` also holds distro userland from
Ubuntu 20.04 to 24.04, Debian bullseye and bookworm, Alpine 3.18 and 3.19, and
a glibc BusyBox, which is what the `base` set gets scored against. There is no
MIPS or RISC-V material anywhere in the tree; those need a Buildroot or
OpenWrt toolchain sourced elsewhere. The 548,303-entry driver manifest is a
file inventory with hashes only, no PE metadata. The earlier survey of the
`workspace-infosec` tree stands: no unlinked Windows objects anywhere.

## Decisions

1. **Unit of distribution** is one blob per `(scheme, library, version,
   variant, arch)` key, named by its sha256, so mirrors are interchangeable and
   the 26 to 43 percent cross-release overlap deduplicates at the blob level.
2. **Format `gsig/1`**: a chunked container with a fixed uncompressed header
   (`magic, format_version, reader_min, arch, scheme, counts, dict_id`), a
   chunk table (`kind, compression, sizes, offset`; unknown kinds skipped by
   size), `postcard`-encoded records over an interned string table, masks as
   bitmaps (1 bit per byte), 64 KB independently zstd-compressed chunks with a
   seek table, and the match index rebuilt into an arena at load. Versioning
   lives in the container, not the encoding. Bytes are a pure function of the
   inputs (sorted records and strings, fixed level and dictionary id). JSON
   stays as import/export. `ruzstd` (pure Rust) in the shipped reader, `zstd`
   in the builder only. SQLite may be generated as an analyst sidecar, never
   shipped as the corpus.
3. **Loading**: once per process, keyed by path and mtime, mmap-backed;
   resolution order `GLAURUNG_SIG_DIR`, then `~/.cache/glaurung/sigs/`, then a
   tiny bundled `base` set inside the wheel. `GLAURUNG_SIGS_OFFLINE=1` forbids
   network.
4. **Distribution**: GitHub Releases on a dedicated `glaurung-sigs` repository
   as primary (2 GiB per asset, no bandwidth cap, immutable releases with
   Sigstore attestations), Cloudflare R2 as mirror, Hugging Face as an optional
   second mirror, PyPI carrying only the resolver and the `base` set. A
   Nix-shaped content-addressed `manifest.json` (schema, set version, monotonic
   serial, validity window, minimum Glaurung version, one entry per blob with
   sha256, sizes, licence, provenance, URLs) signed with minisign, verified
   in-process by `minisign-verify` with the public key embedded. Sigstore is an
   optional layer on top, never a client dependency.
5. **Sourcing, in order**: snapshot.debian.org via `/mr/` and `/file/`
   (content-addressed, robots-permitted; `/archive/*` is not); Launchpad
   `binaryFileUrls` for Ubuntu; Alpine APKINDEX plus CDN for musl and the only
   `-Os` corpus; Fedora koji `-static` RPMs; Rust sysroot rlibs pinned via
   `channel-rust-*.toml` with `.llvmbc` stripped; MinGW from our own Docker
   images with dpkg provenance; MSVC via `xwin`/vcpkg static triplets after a
   NOTICE review; Go is solved by `gopclntab` recovery, not signatures.
   **No third-party signature sets are consumed** (decision of 2026-09-03:
   every published signature is derived by us from an archive we can name
   and re-fetch; `mandiant/siglib`, FLIRTDB, sig-database and similar are
   out, regardless of licence).
6. **Legal position**: we redistribute signatures and names, never archives
   or objects, on the property Hex-Rays states for the format ("contains no
   byte from the original libraries, except for the names"); every blob
   carries provenance sufficient to re-fetch and re-derive; takedown is
   honoured. MSVC-derived sets are produced on a licensed build device.
7. **Priority of libraries** (evidence in the research report): MSVC CRT and
   STL; glibc, libstdc++, libgcc; musl; uClibc-ng; Rust std/core; OpenSSL;
   zlib; BusyBox; libcurl; SQLite; libxml2/expat; Lua; libpng/libjpeg/libtiff;
   PCRE2, zstd, brotli, lz4; then the firmware daemons (dnsmasq, hostapd,
   miniupnp, dropbear, lighttpd/boa/uhttpd). Ship `base` first: glibc, libm,
   libstdc++, libz for current and previous Debian, Ubuntu, Alpine, Fedora on
   amd64 and arm64, about 50 keys and 150k signatures, roughly 8 MB compressed.

## Harvester traps, all measured

`libm.a` is a GNU ld script (`GROUP ( libm-2.43.a libmvec.a )`); five glibc
archives are 8-byte stubs since 2.34; MinGW import libraries are 6-byte thunks;
Rust `.rcgu.o` is 43 percent `.llvmbc`; Go ships no archives; dated rustup
manifests exist only on their own date; COFF symbols carry no size and derived
extents run into alignment padding (now trimmed). Each of these silently
produces a wrong or empty library rather than an error, so the harvester
records per-archive outcomes and never treats an empty result as success.

## Execution ledger

| # | Item | State | Branch / commit | Notes |
|---|---|---|---|---|
| 1 | Baseline measurement | done | this page | glibc 731/1,090 named, 0 wrong |
| 2 | COFF archives in the builder | landed, pushed | `5e882019` | MinGW 0 to 474 raw; hello relink 62/62 |
| 3 | Docker harvest with dpkg provenance | landed (integration line) | `bab4dd8b`, `bea1e5ee` | 419 archives, 508 MB; 299 with signatures, 147,733 unique of 235,043 raw in 40 s after COFF |
| 4 | WARP libraries from NAS PE+PDB | merged (integration line) | `68509346` | cross-servicing recall 0.83 to 0.94 with at most 3 wrong; cross-release 0.27 to 0.37; 0 false names on 48 MinGW PEs; 82 libraries, 226,346 GUIDs |
| 5 | Matcher correctness: ambiguity key, resolver wiring, load-once | merged (integration line) | `04e9afd0` | matcher-indistinguishable keys 276 to 0, dropped-ambiguous 1,179 to 0; over 4 static binaries and 4,357 truth functions, correct 2,931 to 2,979 with wrong unchanged at 12; cached load 0.002 s vs 0.022 s; PLT/import names not yet fed to the resolver |
| 6 | `gsig/1` format and loader | merged (integration line) | `cbc23304` | JSON 1,326 B/sig; gsig store (uncompressed) 229 B/sig; gsig zstd 101 B/sig, 13.1x smaller than JSON; load to first match, merged x86_64 (116,593 sigs), release: 153.6 ms JSON vs 81.1 ms gsig; RSS delta, same corpus: 296.3 vs 134.3 MiB; 0 round-trip failures over 561 harvested libraries |
| 7 | Harvester v1: Debian, Ubuntu, Alpine | merged (integration line) | `b480e04c` | 14 network cells, 561 archives indexed, 140 MB fetched |
| 8 | Distribution: manifest, minisign, client cache, CLI | merged (integration line) | `e0597778` | signed content-addressed manifest, minisign dev key `FA6FDB763B3E76EF` (to be replaced before a real release), `glaurung sigs list\|fetch\|verify\|status\|path`, publish dry run at `~/.cache/glaurung/release/2026.09.1`: 292 blobs, 211 MB, commands printed and unrun; `data/sigs` now packaged in the wheel |
| 9 | Consume mandiant/siglib via lancelot-flirt | dropped | | user decision 2026-09-03: no third-party signature sources; the lane was stopped and its outputs removed |
| 10 | MSVC via xwin/vcpkg | queued | | NOTICE review first |
| 11 | Rust sysroot harvester; gopclntab path for Go | Rust half merged (lane) | `siglib/rust-sysroot`, `96187c92` | 13 crates x 2 toolchains (1.88.0, 1.97.1), 26 libraries, 3,375 unique signatures, 0.06 s build; same-toolchain recall 47-48% of defined text symbols on two stripped Rust binaries, cross-toolchain **0 correct** in every cell (mangling scheme plus codegen); `unwind` yields 0 sigs on both (object has zero defined symbols, confirmed); no `src/flirt/` change needed. Go: gopclntab path still queued, unchanged from Decision 5 |
| 12 | R2 mirror, dictionary training, delta channel | queued | | after the corpus is large |
| 13 | Cortex-M libraries from the ARM toolchain, validated on `rt-libopencm3` and the holdout firmware | merged (integration line) | `440a67fd` | 48 libraries, 32,812 unique signatures; 209 of 210 names correct over 7,622 truth functions across rt-libopencm3 and three holdout projects; alias tie-break defect fixed, 21 wrong to 1 |
