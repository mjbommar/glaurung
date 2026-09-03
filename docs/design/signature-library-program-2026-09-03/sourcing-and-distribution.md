# Signature libraries: sourcing, distribution, and format

> **Kind:** design · **Status:** proposed
>
> Research report, 2026-09-03. Scope: how Glaurung gets from one toy library (16 signatures, `data/sigs/`) to a
> real, redistributable family of FLIRT/WARP signature libraries.

Everything labelled **measured** in this document was run on this box today
(Ubuntu 26.04, gcc 15.2.0, glibc 2.43, the current `master` build of the native
extension, `tools/build_guard.py` reporting `fresh`). Raw numbers are in
`MEASUREMENTS.md` beside this file. Everything else is cited to a URL that came
back from a fetch or a search; anything I could not confirm is marked
UNVERIFIED.

---

## 0. The result that reframes the question

Before any of the sourcing research, I ran the existing builder, unchanged,
against this box's own `/usr/lib/x86_64-linux-gnu/libc.a`:

- **glibc 2.43 -> 2,690 signatures in 0.15 s** (4,375 raw candidates, 137 dropped
  as ambiguous). Seven real archives (glibc, libm, libstdc++, libcrypto, libssl,
  libz, Rust `libstd`) yield **15,534 signatures, 18.7 MB of JSON**.
- Matching that glibc library against a **real** statically linked binary
  (`gcc -O2 -static`, stripped, 817 KB, 1,090 defined code-symbol addresses):
  **747 hits, 731 unique, 731 correct, 0 wrong, 16 correctly withheld as
  ambiguous, in 0.27 s.** Precision 1.000, verified against the unstripped
  symbol table. 649 of the 731 needed the CRC (L2), 82 resolved on pattern alone.

The engine works. The gap is entirely sourcing, distribution and format. But the
same experiment produced the number that should govern all three decisions:

| library used against that binary | correct | wrong |
|---|---|---|
| glibc 2.43, this box's own `libc.a` | **731** | 0 |
| glibc 2.41-12, Debian trixie | **1** | 0 |
| glibc 2.36-9, Debian bookworm | **0** | 0 |
| glibc 2.31, Debian bullseye | **0** | 0 |

And, independent of any linking, at the signature level (masked pattern + mask +
crc16 + crc_len, over names present in both):

| pair | shared names | identical signatures |
|---|---|---|
| Ubuntu 26.04/2.43 vs Debian/2.41 | 2,511 | 5 (**0.2%**) |
| Ubuntu 26.04/2.43 vs Debian/2.36 | 2,318 | 1 (0.0%) |
| Debian 2.41 vs Debian 2.36 (same distro line) | 2,429 | 1,045 (**43.0%**) |
| Debian 2.36 vs Debian 2.31 (same distro line) | 1,973 | 514 (26.1%) |

Cross-distro transfer is **nil**. Adjacent releases inside one distro line share
26-43%. This is not a surprise given the flags - Ubuntu 26.04's
`dpkg-buildflags` (measured) is `-O2 -fno-omit-frame-pointer
-mno-omit-leaf-frame-pointer -flto=auto -ffat-lto-objects
-fstack-protector-strong -fstack-clash-protection -fcf-protection` with
`-D_FORTIFY_SOURCE=3`, while Debian defaults to FORTIFY level 2, no LTO, no
forced frame pointers ([dpkg-buildflags(1)](https://manpages.debian.org/unstable/dpkg-dev/dpkg-buildflags.1.en.html),
[Ubuntu Security/Features](https://wiki.ubuntu.com/Security/Features)).

**Consequence:** coverage is a *breadth* problem, not a *depth* problem. Curating
25 beautiful libraries at one build point is worth almost nothing; the answer
must be an automated harvester over the (distro, release, arch, package version)
matrix. Which in turn means the format and the distribution channel have to
carry 10^5-10^6 signatures cheaply, and that content-dedup across adjacent
releases is worth 26-43%.

---

## Q1. Sourcing

### 1.1 Linux: Debian and Ubuntu (rank 1)

`libc6-dev` ships, measured: `libc.a`, `libc_nonshared.a`, `libm-2.43.a`,
`libmvec.a`, `libresolv.a`, `libBrokenLocale.a`, plus **five 8-byte empty stubs**
(`libpthread.a`, `libdl.a`, `librt.a`, `libanl.a`, `libutil.a`) - glibc 2.34
merged them into libc ([announcement](https://lists.gnu.org/archive/html/info-gnu/2021-08/msg00001.html)).
Two harvester traps, both measured: `libm.a` is a **GNU ld script**
(`GROUP ( libm-2.43.a libmvec.a )`), so a `*.a` glob feeding `ar` silently drops
libm; and the empty stubs must not read as failures. Masking viability, measured
over all 2,233 `libc.a` members: **2,088 (93.5%) carry relocations, 37,485
entries**. Distro `.a` files are exactly the input the builder wants.

**snapshot.debian.org is the workhorse and it is verified working, anonymous,
content-addressed.** Its `robots.txt` disallows `/archive/*`, `/binary/*` and
`/package/*` but **not** `/mr/` or `/file/`, so a bulk harvester must go through
the machine-readable API:

```bash
# 1. enumerate: 813 versions of libc6-dev, 2.0.7t-1 (1998) .. 2.44-1  [measured]
curl -s https://snapshot.debian.org/mr/binary/libc6-dev/
# 2. resolve one version to per-arch content hashes (15 arches for 2.36-9) [measured]
curl -s 'https://snapshot.debian.org/mr/binary/libc6-dev/2.36-9/binfiles?fileinfo=1'
# 3. fetch by SHA-1 -- this is the byte-pinning primitive
curl -sSL -o libc6-dev.deb https://snapshot.debian.org/file/82bdd995c40d95372b69be64cda8abcb69de04da
dpkg-deb -x libc6-dev.deb root/     # no root required
# -> root/usr/lib/x86_64-linux-gnu/libc.a  (5,445,986 bytes)  [measured]
```

`debsnap -d out/ -a amd64 libc6-dev 2.36-9` wraps the same thing. `apt-get
download --print-uris` emits URI + size + SHA-512 without downloading, which is a
manifest generator. **Ubuntu** goes through Launchpad (anonymous, no auth):

```bash
PUB=$(curl -sG https://api.launchpad.net/devel/ubuntu/+archive/primary \
  --data-urlencode ws.op=getPublishedBinaries \
  --data-urlencode binary_name=libc6-dev --data-urlencode exact_match=true \
  --data-urlencode distro_arch_series=/ubuntu/noble/amd64 \
  --data-urlencode status=Published --data-urlencode ws.size=1 \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["entries"][0]["self_link"])')
curl -sG "$PUB" --data-urlencode ws.op=binaryFileUrls
```

EOL suites: `https://old-releases.ubuntu.com/ubuntu/dists/` (200,
dapper..oracular), `http://deb.debian.org/debian/pool/main/g/glibc/` (200).

**Licence.** glibc is LGPL-2.1+; libstdc++ is GPL-3 with the GCC Runtime Library
Exception (both read from the local `copyright` files). Redistributing the
`.deb`s carries corresponding-source obligations. Redistributing *derived
signatures* does not, on the FLIRT reasoning in 1.4. **Never mirror the archives;
ship signatures plus a manifest (package, version, arch, suite, snapshot SHA-1)
that lets anyone re-fetch and re-derive.** Debian's infrastructure supports this:
`reproduce.debian.net` reports forky at **24,476 good / 309 bad (98.75%)**, and
`buildinfos.debian.net` serves a 310 MB `buildinfo-pool.list` mapping binaries to
exact build environments.

### 1.2 Alpine / musl (rank 2 - cheapest, and the only `-Os` corpus)

Raw CDN, no `apk`, no root:

```bash
curl -sO https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64/APKINDEX.tar.gz
tar xzf APKINDEX.tar.gz          # P:/V:/A:/S: records
curl -sO https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64/musl-dev-1.2.5-r11.apk
mkdir x && tar xzf musl-dev-1.2.5-r11.apk -C x
```

Measured: `musl-dev` `libc.a` = 9,415,882 bytes, 1,345 members, **1,924 unique
text symbols** - about half glibc's surface, in one archive; every other archive
in the package is an 8-byte stub. **~291 `-static` packages exist** in v3.21
(157 main + 134 community, measured from APKINDEX), including
`openssl-libs-static`, `zlib-static`, `curl-static`, `sqlite-static`,
`busybox-static`. Alpine's `abuild` defaults are `-Os -fstack-clash-protection`
([default.conf](https://github.com/alpinelinux/abuild/blob/master/default.conf)),
so Alpine code shapes are structurally unlike every `-O2` distro. Nothing else
gives you that axis.

### 1.3 Fedora / RHEL (rank 4)

koji is directory-listable and needs no dnf:
`https://kojipkgs.fedoraproject.org/packages/glibc/2.42/9.fc43/x86_64/glibc-static-2.42-9.fc43.x86_64.rpm`
(verified), extracted with `rpm2cpio pkg.rpm | cpio -idmv`. Fedora ships static
libs in separate `-static` subpackages. The packaging-guidelines page is behind
Anubis anti-bot and returned 403 to every fetch attempt, so the *policy* text is
**UNVERIFIED**; the empirical fact (a `glibc-static` RPM exists in koji) is
verified.

### 1.4 Windows / MSVC (rank 3 by value, rank 1 by legal care)

`libcmt.lib`, `libvcruntime.lib`, `msvcrt.lib`, `oldnames.lib` come from the MSVC
toolset; `libucrt.lib` and the Win32 import libs from the Windows SDK. Both are
obtainable headlessly - `vs_buildtools.exe --quiet --add
Microsoft.VisualStudio.Workload.VCTools`, or on Linux via
[xwin](https://github.com/Jake-Shadle/xwin) (MIT/Apache-2.0) or
[msvc-wine](https://github.com/mstorsjo/msvc-wine). xwin's own README quantifies
the payload: **26 CRT `.lib` (~81 MiB) and 456 SDK `.lib` (~170 MiB)** per
variant.

Both gate on accepting <https://go.microsoft.com/fwlink/?LinkId=2086102> (the
VS 2019 Diagnostic Build Tools licence). msvc-wine: *"As Visual Studio isn't
redistributable, the installed toolchain isn't either."* The EULA's SCOPE OF
LICENSE forbids sharing/publishing the software and also *"reverse engineer,
decompile or disassemble"* - the latter is the clause a careful reading must
confront, because it is contractual rather than copyright.

**The derived-signature question has a direct, quotable answer from the format's
author.** Hex-Rays,
[IDA F.L.I.R.T. Technology: In-Depth](https://docs.hex-rays.com/core/flirt/concepts/ida-f.l.i.r.t.-technology-in-depth.md):

> *"the signature file contains no byte from the original libraries, except for
> the names of the functions."*

The same document has a section headed **Copyright** naming the problem the
design solves (*"standard libraries may simply not be distributed with a
disassembler"*), records that *"about 95% of a signature file are function
names"*, and gives library-to-signature ratios of 100:1 to 500:1. Precedent is
well-resourced: Hex-Rays commercially ships a FLIRT Signature Bundle covering
VS16/VS17 and Windows SDK 10.0.26100.15; Mandiant published ~798 MB of MSVC
`.pat` under Apache-2.0; the NSA ships 79.5 MB of VS-derived `.fidb` in an
Apache-2.0 repo. No Microsoft objection or DMCA action was found - that is
**UNVERIFIED (absence of evidence)**, not clearance.

**Read: proceed, with conditions.** Derive on a build device where the licence
was accepted; publish only masked patterns, CRCs and names; never publish `.lib`
or `.obj`, and never the inputs; record provenance per set; honour takedown.

**mingw-w64 is free (ZPL-2.1) but half of it is worthless**, measured rather
than assumed: `libkernel32.a` is 1,583,504 bytes across 1,759 members, and every
member is a 6-byte `jmp *0x0(%rip)` thunk plus import descriptors (`.text` = 8
bytes). Same for `libmsvcrt.a`. **Signatures from mingw import libraries are
useless.** `libmingwex.a` (1,984,036 B, 291 members) and the MinGW `libstdc++.a`
hold real bodies, are worth signing, and are freely redistributable.

### 1.5 Rust (rank 5, high value per byte)

`.rlib` is an `ar` archive (verified: `!<arch>` magic). Members, measured on
`libstd-*.rlib`: exactly three - `lib.rmeta`, `lib.rmeta-link`, and one
`.rcgu.o`. The sysroot holds **27 rlibs / 162 MB** per stable toolchain;
`libstd` is 11.7 MB with 1,333 text symbols, `libcore` 2.9 MB with 566.

Two facts a harvester must know. **Bitcode dominates the object**: in `libstd`'s
`.rcgu.o`, `.llvmbc` is 5,038,616 bytes (43%) while all `.text*` sections sum to
372,401 bytes (3.2%). Strip it first. And pinning goes through
`https://static.rust-lang.org/dist/channel-rust-<ver>.toml` (200), which gives
per-target `xz_url` + SHA-256; dated manifests exist only on the manifest's own
`date` (`2026-07-16` is 200, `2026-07-14` is 404), so do not derive it from
`rustc -V`. Relocations are per-function (`R_X86_64_GOTPCREL`/`PC32` against
v0-mangled symbols in `.text._RIN...` sections), so extraction is clean. Measured
end to end: the `libstd` rlib yields **906 signatures**.

### 1.6 Go: do not build a signature corpus (rank: skip)

Measured on go1.23.4: `$GOROOT/pkg/` holds **zero** `.a` files and `$GOCACHE`
(122 MB) holds zero. `go build -buildmode=archive` produces `__.PKGDEF` +
`_go_.o`, where `__.PKGDEF` is binary *export data*, not a symbol index. Meanwhile
stripped Go binaries retain `gopclntab` and `moduledata`, from which
[GoReSym](https://github.com/mandiant/GoReSym) recovers function names and
start/end addresses directly. **Recommendation: implement gopclntab parsing
instead; reserve signatures for the obfuscated case** (cf. Volexity's
GoResolver). This matters because Go is otherwise near the top of the priority
list - SentinelOne took NOBELIUM's GoldMax from **4,771 functions to 22** by
stripping Go stdlib code.

### 1.7 Third-party signature sets we could consume

| Set | Licence | Size / content | Verdict |
|---|---|---|---|
| **mandiant/siglib** | **Apache-2.0** (verified) | 1.03 GB; 3 `.sig` (14 MB) + 52 tarballs (~798 MB of `.pat`) for VS6..VS2019 | **Use.** Archived 2021 - pin a commit. Its vcpkg-static-triplet Docker pipeline is also the model for our own MSVC builds. |
| Ghidra FunctionID (`ghidra-data`) | Apache-2.0 (no separate payload terms found) | 10 `.fidb`, 79.5 MB, **all Visual Studio** (vs2012/15/17/19/vsOlder x86+x64) | Legal, impractical: no Rust `.fidb` reader exists (crates.io search for `fidb`/`packeddatabase` returns zero). |
| threatrack/ghidra-fidb-repo | **MIT** | 62 MB, Linux (glibc-static, boost, openssl, zlib, lua, libstdc++, EL6/7 + Ubuntu) | Legal; same reader problem. Useful as a *coverage target* to beat. |
| rizinorg/sigdb | LGPL-3.0 (README only, no LICENSE file) | 207 MB deflated FLIRT `.sig` | Avoid - viral-adjacent for a dataset, and the licence is not properly declared. |
| Maktm/FLIRTDB, push0ebp/sig-database, PlatyPew/ida-flirtdb | **No LICENSE file at all** | 63.8 MB / 49.8 MB / 1.33 GB | **Do not redistribute.** No grant. |
| Vector35/warp | Apache-2.0 (format + Rust impl) | spec + `.fbs` schemas | Format yes. The bundled MSVC signature data ships inside Binary Ninja with no published licence and no public repo - **do not extract**. |

`lancelot-flirt` **0.10.0** (Apache-2.0, 2026-07-09) parses *and compiles*
`.pat`/`.sig`. `docs/reference/function-signature-libraries.md` declined it for
building; for **consuming** siglib it is the right answer, behind an optional
feature. A newer alternative appeared: **`fast-flirt` 0.2.2** (Apache-2.0,
2026-05-27, pure Rust, three deps) - see Q3, its published numbers change the
format calculus.

### 1.8 The ranked target list

Ordered by expected functions-recognised-per-unit-of-work, with the evidence.

**Tier 1 - runtimes, highest function mass per binary**

1. **MSVC CRT (libcmt/vcruntime/UCRT)** - the only thing Ghidra ships FID for.
2. **Go runtime + stdlib** - GoldMax 4,771 -> 22 functions; ~2000% growth in Go
   malware (Intezer). *Solve via gopclntab, not signatures.*
3. **MSVC C++ STL / ATL / MFC** - capa's largest single sig file (7.58 MB).
4. **glibc** - 74.21% of dynamically-linked Linux malware imports it (Cozzi et
   al., *Understanding Linux Malware*, IEEE S&P 2018), and *">80% of the samples
   we analyzed are statically linked"* in the same corpus.
5. **Rust std/core + rlib crates** - statically linked by language design.
6. **uClibc / uClibc-ng** - 24.24% of that same corpus; FirmSec: *"all routers
   adopt ... uClibc."*
7. **libstdc++ / libgcc** - 7.12% / 9.74%; libgcc is over-represented on
   soft-float embedded targets.
8. **musl** - Alpine/static-container default. No corpus-level frequency
   measurement found (UNVERIFIED); ranked on judgement.
9. **Delphi VCL / .NET** - IDA's FLIRT spec covers Borland VCL explicitly.

**Tier 2 - cross-platform OSS, measured-frequent**

10. **OpenSSL/libcrypto** - most CVEs of any component in FirmSec (132 CVEs,
    1,304 of 34,136 images, [arXiv:2212.13716](https://arxiv.org/abs/2212.13716));
    Binarly found three OpenSSL versions statically linked into single UEFI
    images. Measured here: 7,066 signatures from one `libcrypto.a`, our largest
    single source.
11. **zlib** - siglib, Karta, FLIRTDB, Marcelli Dataset-1; 5.24% in Cozzi.
12. **BusyBox** - FirmSec's #1 at 3,326 images.
13. **libcurl** - 3.64% in Cozzi; in IDA's Ubuntu Feeds bundle.
14. **SQLite** - the amalgamation means it is *always* statically linked.
15. **libxml2 / expat** (1.44% in Cozzi), 16. **Lua/LuaJIT** (FirmSec top-10 in
    every firmware category), 17. **libpng / libjpeg-turbo / libtiff** (the Karta
    trio), 18. **PCRE2, zstd, brotli, lz4** (IDA Feeds ships `libzstd`).
19. **mbedTLS** - in siglib, but FirmSec measured **<1%** of firmware: malware
    relevance, not firmware.
20. **Boost, Qt, protobuf, Crypto++, Detours** - FLIRTDB/siglib directory
    evidence; frequency UNVERIFIED, ranked on judgement.

**Tier 3 - whole statically linked daemons that recur in firmware.**
21. **Dnsmasq**, 22. **wpa_supplicant/hostapd**, 23. **MiniUPnP/libupnp**
(FIRMADYNE: 16.4% of images ship UPnP on by default), 24. **Dropbear** (SSH on
2.2% of images vs telnet 19.8%, so Dropbear over OpenSSH), 25.
**lighttpd/boa/uhttpd/thttpd** (Costin et al. collected 847 web-server configs
across 32,356 images), 26. **iptables, util-linux, Samba, net-snmp**, 27.
**cJSON/Jansson**.

**Deliberately excluded:** Black Duck OSSRA and Census III top-component lists.
They measure package-manager dependency graphs (all ten of OSSRA's top ten are
JavaScript) - the wrong denominator for compiled `.text`.

**Sizing the matrix.** 25 libraries x ~12 (distro, release) points x 4-6 arches
is ~1,500 library-builds; at the measured ~2,200 signatures/library that is
**~3.3M signatures**, above the 10^6 the brief posits. Scope by demand: ship
`base` (glibc/libstdc++/libm per current+previous release of Debian, Ubuntu,
Alpine, Fedora, amd64+arm64) first, which is ~50 keys and ~150k signatures.

---

## Q2. Distribution

### 2.1 The channel

**Primary: GitHub Releases on a dedicated `glaurung-sigs` repository.** The docs
are explicit: *"Each file included in a release must be under 2 GiB"*, max 1000
assets per release, and *"There is no limit on the total size of a release, nor
bandwidth usage"*
([about-releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)).
The counterweight is the Acceptable Use Policy section 9 (throttling for *"significantly
excessive"* bandwidth), not the release docs. **Immutable Releases went GA
2025-10-28** and carry Sigstore-bundle attestations automatically - note that
immutable releases require create-draft, upload, then publish (a post-publish
upload returns 422).

Never put the blobs in git: the repo-proper limits are 100 MiB/file hard block
and a 5 GB soft repo ceiling.

**Fallback/mirror: Cloudflare R2**, which contractually charges **$0 egress**
($0.015/GB-month storage; ~$15/month for 1 TB stored + 1 TB/month out). Backblaze
B2 at $6.95/TB-month with free egress through Cloudflare/Fastly is the cheaper
variant. S3 is roughly an order of magnitude more for this workload.

**Not primary: Hugging Face.** Xet chunk-level dedup is attractive given the
measured 26-43% cross-release overlap, but the anonymous limit is **3,000
resolver requests per 5-minute window per IP** - which a `snapshot_download` over
a many-file sig repo hits from CI - and free public storage is explicitly
best-effort, conditioned on being *"as useful to the community as possible"*.
Good mirror, wrong primary.

**Not the data channel: PyPI.** 100 MB per file, 10 GB per project by default.
`glaurung-sigs-<family>` wheels suit small families (spaCy's pattern: wheel URLs
pinnable in `requirements.txt`); a multi-GB family cannot ship there. **PyPI
carries the index and the resolver, not the corpus.** **GHCR/ORAS** is free for
public packages with a 10 GB layer cap and anonymous pulls, but forces every
consumer through an OCI client for what is an HTTPS GET.

### 2.2 Prior art worth copying

ClamAV is the closest analogue: a signed, versioned `.cvd` with a 512-byte
header (build time, version, sig count, flevel, MD5, signature, builder),
**incremental `cdiff` patches** so freshclam *"only transfers the differences"*,
and since 1.5.0 external `.cvd.sign` files. Nix is the model for the *index*:
content-addressed store paths, one `<hash>.narinfo` per object carrying
`StorePath`/`URL`/`Compression`/`FileHash`/`FileSize`/`NarHash`/`NarSize`/
`References` and an **Ed25519 `Sig`** - the cache is dumb static HTTP and all
trust lives in the detached signature. Debian's `InRelease` supplies the rule
that hashes are mandatory and MD5/SHA-1 are unacceptable.

One correction to a common assumption: **capa does not attach a rules zip to its
releases** - the last eight (v8.0.1..v9.4.0) carry only platform binary zips,
with rules and sigs inside them; its FLIRT sigs are committed directly in git
(`mandiant/capa/sigs/`, 15.2 MB, Apache-2.0). Ghidra ships `.fidb` inside the
distribution, not the git tree. Binary Ninja is moving from SigKit to WARP with a
**server** at `https://warp.binary.ninja`, source tags filtered to
`official`/`trusted`; no public bulk `.warp` dump was found.

### 2.3 The recommended design

```jsonc
// https://sigs.glaurung.dev/v1/manifest.json  (and the same file as a Release asset)
{
  "schema_version": 1,
  "set_version": "2026.09.1",
  "serial": 41,                     // monotonic; downgrade defence
  "built_utc": "2026-09-03T12:00:00Z",
  "valid_until": "2027-03-03T00:00:00Z",
  "min_glaurung_version": "0.9.0",
  "blobs": [
    {
      "key": "glibc/2.43-2ubuntu2.3/ubuntu-26.04-gcc15.2.0-O2/x86_64",
      "kind": "flirt-masked-pattern-v1",
      "signatures": 2690,
      "format": "gsig/1",
      "compression": "zstd:19+dict:sha256-9f2c...",
      "sha256": "6f1a...",           // of the compressed blob, and its name on disk
      "size_bytes": 135834,
      "uncompressed_bytes": 254114,
      "licence": "LGPL-2.1-or-later (inputs); signatures: derived, see NOTICE",
      "provenance": {
        "source": "snapshot.debian.org",
        "package": "libc6-dev", "version": "2.43-2ubuntu2.3", "arch": "amd64",
        "input_sha1": "82bdd995c40d95372b69be64cda8abcb69de04da",
        "buildinfo": "https://buildinfos.debian.net/..."
      },
      "urls": [
        "https://github.com/.../releases/download/2026.09.1/6f1a....gsig.zst",
        "https://sigs.glaurung.dev/blob/6f1a....gsig.zst",
        "hf://datasets/glaurung/sigs@<40-char-sha>/6f1a....gsig.zst"
      ]
    }
  ]
}
```

Blobs are **stored and named by their sha256**, so mirrors are interchangeable, a
stale mirror cannot serve a mismatched file under a live name, and the 26-43%
cross-release overlap deduplicates for free at the blob level once we split
per-library-per-release.

Client: cache at `~/.cache/glaurung/sigs/<sha256>`; `GLAURUNG_SIG_DIR` overrides;
`GLAURUNG_SIGS_OFFLINE=1` forbids network and uses only what is cached (mirroring
`HF_HUB_OFFLINE`); a bundled fallback manifest so a fresh install with no network
still has the tiny `base` set.

**Signing: minisign as the mandatory floor, Sigstore as the optional upgrade.**
Sign the *manifest only* - one Ed25519 signature transitively covers every blob
via its hash, exactly Nix's model - and put `set_version` and `serial` in
minisign's **trusted comment**, which is what that field is documented for
("to prevent downgrade attacks"). Verify in-process with **`minisign-verify`
0.2.5** (MIT, zero dependencies, 12.8M downloads), public key embedded in the
binary: about thirty lines, works air-gapped, no OIDC, no Rekor. Layer GitHub
Artifact Attestations and a `cosign sign-blob` bundle on top for anyone who wants
transparency-log provenance; do **not** make the Rust client depend on the
`sigstore` crate, which self-describes as experimental at 0.14.0.

---

## Q3. Format

### 3.1 What the incumbents do

**WARP** (`warp.fbs`, verified in-repo): FlatBuffers, `file_identifier "WARP"`,
`ChunkHeader{version, type, compression_type, size, target}` where `size` is the
*uncompressed* length so readers can pre-allocate, `File{header, chunks}`. Two
verified surprises: `CompressionType::Zstd` is actually **zlib** (`flate2` in
`rust/src/chunk.rs`, `78 9c` at 0x2a of the fixture), and the file identifier is
**never written** (`finish_minimal`). Lookup is a `HashMap<FunctionGUID, ...>`
**rebuilt at chunk load**.

**Ghidra `.fidb`**: a Java `PackedDatabase` - `ObjectOutputStream` header, magic
`0x2e30212634e92c20`, then a **deflate** ZIP payload that `PackedDatabase`
*unpacks to a temporary database on open*, the worst load-time design of the
three. Inside, a nine-column Functions table indexed only on `FULL_HASH` and
`NAME_ID`, so specific-hash lookup is an unindexed scan. Density:
`el7.x86_64.fidb` = 6,091,199 bytes for 53,823 entries = **113 B/function**.

**IDA `.sig`**: `IDASGN` magic, optional raw-zlib body, a **trie** of `{length,
wildcard mask (varint, applied from the pattern end), literals, children}` whose
leaves carry `crc_len` + big-endian `crc16` + length + names + tail bytes +
referenced names. Hex-Rays' economics: MFC 2.x = 33,634 names, 2.5 MB -> 700 KB,
**~21 B/function**, and *"about 95% of a signature file are function names"*.
**capa** ships 15,179,585 bytes declaring 102,012 / 165,632 / 55,161 functions =
**~47 B/function**.

### 3.2 Our own numbers

Measured over the 15,534 real signatures:

| encoding | total | bytes/signature |
|---|---|---|
| current JSON | 18,674,811 | **1,202** |
| packed binary, interned string table | 1,776,682 | **114** |
| packed + zstd-19 | 804,839 | **52** |
| (JSON + zstd-19, glibc only) | 186,372 | ~69 |

Interning is where most of the win is: 15,418 distinct function names and 10,279
distinct reference names collapse to a **581,838-byte** string table, against
267,647 bytes of reference-name text in glibc's JSON alone. At 52 B/signature we
land squarely between capa's 47 and Ghidra's 113 - which is the sanity check that
the encoding is not doing anything exotic.

**Extrapolated to 10^6 signatures: JSON 1.2 GB, packed 114 MB, packed+zstd
52 MB.** That is the whole argument for changing format.

The chunking measurement (from the format survey, on 14,015 real prologues +
names) settles the container: per-record zstd frames **expand** the data (0.91x);
64 KB independently compressed chunks reach 2.45x (2.70x with a 16 KB trained
dictionary) against 3.48x for a single unseekable block. So: 64 KB frames plus a
seek table, which is what the Zstandard Seekable Format standardises (skippable
frame `0x184D2A5E`, footer `0x8F92EAB1`) and remains a valid plain `.zst`.

### 3.3 The load-time premise does not hold

**`fast-flirt` 0.2.2** publishes the number nobody else does: a **944k-pattern**
corpus loads in **361 ms** (2.6M patterns/sec) *including* zlib-inflating the
`.sig` bodies and building a multi-level trie, matches at 9.5M calls/sec, ~240x
over a linear scan, and drops from ~250 MiB to **~75 MiB** resident by using an
arena of borrowed slices instead of per-node allocations.

That reframes Q3's central question. Zero-copy formats exist to avoid a cost that
measures at ~0.4 s per 10^6 records, once per session. And the memory win people
attribute to rkyv/FlatBuffers is available from an arena regardless of wire
format. **Do not pay rkyv's alignment and major-version constraints, or
FlatBuffers' `flatc`/vtable/verifier tax, to save 300 ms.**

### 3.4 Recommendation

**A chunked container (`gsig/1`) of `postcard`-encoded records with an interned
string table, 64 KB independently zstd-compressed chunks plus a seek table, and
the match index rebuilt into an arena at load. SQLite as an optional sidecar
index, never the source of truth.**

Concretely, at the Rust struct level:

```rust
/// One `.gsig` file = one (library, version, variant, arch) key.
/// Header is uncompressed and fixed-size so a reader can index without inflating.
#[repr(C)]
pub struct GsigHeader {
    magic: [u8; 4],          // b"GSIG"
    format_version: u16,     // 1  -- bump only on incompatible change
    reader_min: u16,         // refuse if reader < this
    arch: u16,               // enum
    scheme: u16,             // flirt-masked-pattern-v1 | warp-function-guid-v1 | ...
    n_signatures: u32,
    n_strings: u32,
    dict_id: u32,            // 0 = none; else index into the manifest's dictionaries
    chunk_count: u32,
    // followed by: [ChunkEntry; chunk_count], then the chunk payloads
}

#[repr(C)]
pub struct ChunkEntry {
    kind: u8,                // 0 = string table, 1 = signatures, 2 = refs, 3 = guids
    compression: u8,         // 0 = none, 1 = zstd
    _pad: [u8; 2],
    compressed_size: u32,
    uncompressed_size: u32,  // WARP's rule: readers pre-allocate exactly
    file_offset: u64,
}

/// Decoded record. `postcard` on the wire, varint everywhere.
/// EVERY field added after v1 carries a default equal to the v1 behaviour,
/// exactly as the current JSON schema does.
pub struct SigRecord {
    name: StrId,             // u32 into the string table
    pattern: PatternRef,     // (offset, len) into the arena's pattern blob
    mask: BitmapRef,         // 1 bit/byte, not 1 byte/byte: 62 KB not 497 KB
    crc16: u16,
    crc_len: u8,
    function_len: u32,
    refs: RefRange,          // (offset, count) into a flat [(u32 off, StrId)] array
}

/// What lives in memory. One allocation for bytes, one for records.
pub struct SigLibrary {
    arena: Box<[u8]>,        // string table + patterns + masks + ref array
    records: Box<[SigRecord]>,
    /// Rebuilt at load. 361 ms/10^6 measured by fast-flirt; not worth serialising.
    by_first_byte: [Range<u32>; 256],
    /// Only for schemes where the identity is a plain equality key.
    by_guid: Option<Box<[(u128, u32)]>>,   // sorted; binary search in place
}
```

Two design notes carried straight from the measurements. **Masks must be
bitmaps**: at one byte per byte they cost 497,088 bytes for the 15,534
signatures, at one bit per byte 62,136. And **the record must not carry
`function_len` into the equality key** - see the defect below.

Forward compatibility is bought the way every incumbent buys it: an explicit
version in the header *and* per chunk, unknown chunk kinds skipped by their
recorded size, and a `reader_min` that lets a producer say "this one really is
incompatible". postcard has no struct-evolution story at all
(*"backwards/forwards compatibility ... outside the scope of the postcard wire
format"*), so the versioning has to live in the container, not the encoding.

Determinism, for reproducible builds: sort records by `(name, pattern)` as the
current builder already does, sort the string table, fix the zstd level and
dictionary by id, and the bytes are a pure function of the inputs.

Python readability is preserved without a second format: the `.gsig` reader is
exposed through PyO3, and the *optional* SQLite sidecar (measured at 110 B/row
for 10^6 rows, **0.11 ms open + 0.108 ms first indexed lookup**, byte-identical
across rebuilds modulo 8 header bytes) is what an analyst queries ad hoc.
Generate it; do not ship it as the corpus.

### 3.5 Crates considered

Verified against the crates.io API on 2026-09-03.

| Crate | Version | Licence | Last release | Pure Rust | Verdict |
|---|---|---|---|---|---|
| **bincode** | 3.0.0 | MIT | 2025-12-16 | - | **Dead.** 3.0.0's `lib.rs` is `compile_error!("https://xkcd.com/2347/")`; repo archived; last usable is 2.0.1 (2025-03-10). **Glaurung depends on `bincode = "2.0.1"` today** - see Risks. |
| **postcard** | 1.1.3 | MIT/Apache-2.0 | 2025-07-24 | yes | **Recommended wire encoding.** Varint, no evolution story - version the container. |
| wincode | 0.6.1 | Apache-2.0 | 2026-08-10 | yes | bincode's own nominated successor, if bincode-shaped encoding is wanted. |
| rkyv | 0.8.18 | MIT | 2026-08-05 | yes | Excellent, deterministic and cross-platform within 0.8; rejected on alignment + major-version churn for a 300 ms saving. |
| flatbuffers | 25.12.19 | Apache-2.0 | 2025-12-19 | runtime yes | Best evolution story; needs C++ `flatc` unless paired with `planus`. WARP's choice. |
| planus | 1.3.0 | MIT/Apache-2.0 | 2026-01-25 | yes | Pure-Rust `.fbs` compiler; the escape hatch if we go FlatBuffers. |
| capnp | 0.27.0 | MIT | 2026-08-02 | yes | 76.6 ns/access - weakest zero-copy option for a hot path. |
| **zstd** | 0.13.3 | MIT | 2025-02-20 | **no** (vendors C zstd via `zstd-sys`) | Use for the *builder*. |
| **ruzstd** | 0.9.0 | MIT | 2026-07-26 | **yes** | **Now compresses** as well as decompresses. Use for the shipped reader so the wheel needs no C toolchain. |
| rusqlite / libsqlite3-sys | 0.40.2 / 0.38.2 | MIT | 2026-08-08 | no (`bundled` compiles sqlite3.c) | Sidecar only. Python's stdlib `sqlite3` reads it with zero deps. |
| redb | 4.2.0 | MIT/Apache-2.0 | 2026-08-17 | yes | Pure-Rust embedded KV, stable file format, MSRV 1.90. The alternative sidecar if the C dependency is unacceptable. |
| fst | 0.4.7 | Unlicense/MIT | **2021-06-06** | yes | Frozen. Masks are implementable via `Automaton`, but a wildcard at position 0 defeats pruning. Exact-prefix layer only. |
| memmap2 | 0.9.11 | MIT/Apache-2.0 | 2026-06-22 | yes | Already a dependency. |
| blake3 | 1.8.7 | CC0/Apache-2.0 | 2026-08-20 | effectively yes (`build.rs` falls back to pure Rust) | Already a dependency; use for the identity gate keys as now. |
| xorf | 0.13.0 | MIT | 2026-08-21 | yes | Already a dependency; the BinaryFuse8 membership gate. |
| uuid | 1.26.0 | Apache-2.0/MIT | 2026-08-26 | yes | Already a dependency; WARP GUIDs. |
| minisign-verify | 0.2.5 | MIT | 2026-03-03 | yes, zero deps | **Recommended** manifest verification. |
| sigstore | 0.14.0 | Apache-2.0 | 2026-05-22 | yes | Self-described experimental. Optional, out-of-process. |
| lancelot-flirt | 0.10.0 | Apache-2.0 | 2026-07-09 | yes | For *consuming* `.pat`/`.sig` (siglib). Optional feature; 13 direct deps incl. `clap 3`, `bitflags 1`. |
| fast-flirt | 0.2.2 | Apache-2.0 | 2026-05-27 | yes, 3 deps | The load-time datapoint; worth evaluating as an alternative reader. |

---

## Risks

1. **`bincode` is unmaintained and `Cargo.toml:22` pins `bincode = "2.0.1"`.**
   3.0.0 is a deliberate tombstone. Nothing is broken today, but a shipped crate
   should not build a new format on a dead dependency. Either migrate the two
   call sites to `postcard`/`wincode` or accept the pin knowingly.
2. **The builder's ambiguity key includes a field the matcher never compares.**
   Measured on the 7-library merged set: **268 keys (576 signatures, 3.7%)** are
   indistinguishable to `match_at` yet survive as distinct entries, because
   `build_flirt_library.py` keys on `function_len` and the matcher does not.
   Example: glibc `_IO_seekoff` (len 646) and `_IO_seekpos` (len 492) share
   prologue, an all-fixed mask, and `crc16=7706` with `crc_len=1`. Referenced
   names break 251 of the 268; **17 have identical reference sets too.** 16 of
   the 268 are cross-library (glibc `__res_randomid` vs libstdc++
   `_ZNSt6chrono3_V212steady_clock3nowEv`). At 16 signatures this could not show;
   at 15,534 it is the first thing scale exposes. **Fix before publishing
   anything.**
3. **CRC coverage is thin for a fifth of signatures.** Measured: `crc_len == 0`
   for 2,732 of 15,534 (17.6%) and 1-3 bytes for a further 1,251. Those match on
   pattern alone, which is exactly the L1-only case where FLIRT expects the
   caller-name discriminator - and `apply_flirt_overrides` still calls `match_at`
   with no resolver. Referenced-name resolution needs wiring before a large
   library ships.
4. **MSVC EULA exposure is contractual, not copyright.** The mitigation is
   procedural (derive on a licensed build device, publish no inputs, record
   provenance, honour takedown), and it is not eliminable.
5. **Two ecosystems have no licence at all** (FLIRTDB, sig-database,
   ida-flirtdb). Easy to consume by accident; must be a hard rule in the
   harvester.
6. **GitHub AUP section 9** is the ceiling on the free channel. The R2 mirror in the
   manifest is the mitigation, and it must exist *before* it is needed.
7. **Harvester traps, all measured:** `libm.a` is an ld script; five glibc
   archives are 8-byte stubs; mingw import libs are pure thunks; Rust `.rcgu.o`
   is 43% `.llvmbc`; Go ships no archives at all; dated rustup manifests exist
   only on the manifest's own date. Each of these silently produces a wrong or
   empty library rather than an error.
8. **Snapshot rate limits are undocumented.** The site says HTTP-layer limiting
   replaced netfilter limiting but publishes no numbers (UNVERIFIED). A harvester
   must be politely paced and resumable, and must go through `/mr/` + `/file/`
   because `/archive/*` is `Disallow`ed in robots.txt.

---

## Implementation plan

Effort is one focused engineer-day unless stated.

1. **Fix the ambiguity key** (risk 2): drop `function_len` from
   `build_flirt_library.py`'s key so builder and matcher agree, and add a test
   asserting zero matcher-indistinguishable pairs survive. *0.5 day.*
   **Blocking.**
2. **Wire the referenced-name resolver** into `apply_flirt_overrides` (risk 3).
   `match_at_with_refs` already exists and is tested; it needs the PLT and symbol
   maps threaded through. *2 days.*
3. **Land the `gsig/1` format** behind the existing JSON reader: `postcard`
   records, interned string table, bitmap masks, chunked container, `ruzstd`.
   Keep JSON as an import/export path so nothing existing breaks. Golden-bytes
   test for determinism. *3 days.*
4. **Harvester v1: Debian/Ubuntu + Alpine.** `/mr/` + `/file/`, Launchpad
   `binaryFileUrls`, Alpine APKINDEX + CDN; `dpkg-deb -x` / `tar xzf`; ld-script
   resolution; empty-archive detection; provenance per key. One `.gsig` per
   (package, version, arch, suite). *4 days.*
5. **Publish `base`**: glibc/libm/libstdc++/libz for current+previous Debian,
   Ubuntu, Alpine, Fedora on amd64+arm64 - roughly 50 keys, ~150k signatures,
   ~8 MB compressed at the measured 52 B/signature. Manifest + minisign +
   GitHub Release. *2 days.*
6. **Client fetch path**: manifest verify, content-addressed cache at
   `~/.cache/glaurung/sigs/`, `GLAURUNG_SIG_DIR`, `GLAURUNG_SIGS_OFFLINE`,
   bundled fallback manifest. *2 days.*
7. **Consume `mandiant/siglib`** behind an optional `flirt-import` feature using
   `lancelot-flirt` 0.10.0 - this is the cheapest path to MSVC coverage and it is
   Apache-2.0. *2 days.*
8. **Harvester v2: MSVC via `xwin` + vcpkg static triplets**, following siglib's
   own reproducible pipeline. Legal review of the NOTICE text first. *5 days.*
9. **Rust sysroot harvester** (strip `.llvmbc`, pin via `channel-rust-*.toml`)
   and **Go gopclntab recovery** as an explicitly non-signature path. *3 + 4
   days.*
10. **R2 mirror, dictionary training, and a `cdiff`-style delta channel** once
    the corpus is large enough that full re-downloads are the complaint. *3
    days.*

Steps 1-6 are the minimum that turns a 16-signature demo into something worth
shipping, and they total about two weeks.
