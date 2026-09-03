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
   NOTICE review; `mandiant/siglib` consumed under Apache-2.0 via
   `lancelot-flirt` behind an optional feature. Go is solved by `gopclntab`
   recovery, not signatures. Libraries with no licence (FLIRTDB, sig-database)
   are never consumed.
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
| 4 | WARP libraries from NAS PE+PDB | in flight | `siglib/warp-windows` | cross-build recall is the measurement |
| 5 | Matcher correctness: ambiguity key, resolver wiring, load-once | in flight | `siglib/matcher-correctness` | blocking before any publish |
| 6 | `gsig/1` format and loader | in flight | `siglib/gsig-format` | JSON kept as import/export |
| 7 | Harvester v1: Debian, Ubuntu, Alpine | in flight | `siglib/harvester-v1` | `base` matrix |
| 8 | Distribution: manifest, minisign, client cache, CLI | in flight | `siglib/distribution` | dry-run publish only; the human creates the release |
| 9 | Consume mandiant/siglib via lancelot-flirt | queued | | optional feature |
| 10 | MSVC via xwin/vcpkg | queued | | NOTICE review first |
| 11 | Rust sysroot harvester; gopclntab path for Go | queued | | |
| 12 | R2 mirror, dictionary training, delta channel | queued | | after the corpus is large |
