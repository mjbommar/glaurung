# Signature sources: the `base` matrix

> **Kind:** reference · **Status:** maintained

Where the static archives a signature library is built from come from, how they
are fetched, and what may and may not be redistributed afterwards.

A companion to [FLIRT-style signature libraries](function-signature-libraries.md),
which describes what a signature *is*, and to the "System archives" section of
[the sample corpus](sample-corpus.md), which describes the in-image harvest.
This page is about the network harvest: the other axis.

## Why breadth, not depth

One measurement decides the shape of the whole corpus. A stripped
`gcc -O2 -static` binary built on this box (Ubuntu 26.04, glibc 2.43, 1,090
defined text symbols) matched against glibc libraries built from four different
sources:

| library | correctly named | wrong |
|---|---|---|
| glibc 2.43, this box's own `libc.a` | **731** | 0 |
| glibc 2.41-12, Debian trixie | 1 | 0 |
| glibc 2.36-9, Debian bookworm | 0 | 0 |
| glibc 2.31, Debian bullseye | 0 | 0 |

The matcher is not the problem: precision was 1.000 in the first row, with 16
candidates correctly withheld as ambiguous. **Coverage is the problem**, and the
unit of coverage is `(distro, release, arch, package version)`. Twenty-five
beautifully curated libraries at one build point are worth almost nothing;
automated breadth over the matrix is the only thing that helps.

`python/glaurung/tools/harvest_sources.py` is that automation.

## The `base` matrix

Declared in [`tools/sig_matrix/base.toml`](../../tools/sig_matrix/base.toml).
Seven `(distro, release)` rows, two architectures each, three packages each:

| distro | releases | arches | packages |
|---|---|---|---|
| Debian | bookworm (12), trixie (13) | amd64, arm64 | `libc6-dev`, `@libstdcxx-dev`, `zlib1g-dev` |
| Ubuntu | jammy (22.04), noble (24.04), resolute (26.04) | amd64, arm64 | `libc6-dev`, `@libstdcxx-dev`, `zlib1g-dev` |
| Alpine | v3.20, v3.21 | x86_64, aarch64 | `musl-dev`, `@libstdcxx-dev`, `zlib-static` |

Ubuntu's three are the current LTS and the two before it, per Launchpad's own
series list on the day the spec was written (`resolute` "Current Stable
Release", `noble` and `jammy` "Supported"). Alpine is in `base` for two axes
nothing else supplies: **musl** rather than glibc, and `abuild`'s `-Os` rather
than everyone else's `-O2`.

**Fedora is out of scope for this lane**, and the spec says so in an
`out_of_scope` key rather than simply omitting it. Its static libraries are in
separate `-static` subpackages on koji, extraction needs `rpm2cpio` (absent on
this machine), and the packaging-guidelines page that would document the policy
is behind an anti-bot gate that returned 403 to every fetch. The empirical fact
that `glibc-static-2.42-9.fc43.x86_64.rpm` exists in koji is verified; the
policy is not.

### `@libstdcxx-dev` is resolved, not named

The spec writes `@libstdcxx-dev` where a C++ development package belongs,
because its name is a per-release fact. The harvester walks the `Depends` graph
from `g++` and records the edge it followed. Two shapes, both real:

| release | edge | resolves to |
|---|---|---|
| bookworm | `g++ -> g++-12 -> libstdc++-12-dev` | `libstdc++-12-dev` |
| trixie | `g++ -> g++-14 -> g++-14-x86-64-linux-gnu -> libstdc++-14-dev` | `libstdc++-14-dev` |
| Alpine v3.21 | `g++ -> libstdc++-dev` | `libstdc++-dev` |

A one-hop resolver gets bookworm and jammy right and reports "no
libstdc++-N-dev" for trixie, noble and resolute -- three of the seven releases,
failing in a way that reads like the package having been renamed. Picking the
highest `N` present is also wrong: trixie publishes `libstdc++-12-dev`,
`-13-dev` and `-14-dev`, and only one of them is what the distribution's own
C++ packages were built against.

## Fetch mechanics

### Debian

Two steps, because they answer different questions. The suite's own `Packages`
index says what `bookworm/main` publishes *today*; `snapshot.debian.org` is
content-addressed and permanent, which is what a provenance record needs, so a
manifest written now still re-fetches years later after the suite has moved on.

```bash
# 1. suite -> exact version (and SHA-256, and the Depends graph)
curl -s https://deb.debian.org/debian/dists/bookworm/main/binary-amd64/Packages.xz | xz -d

# 2. version -> per-arch content hash
curl -s 'https://snapshot.debian.org/mr/binary/libc6-dev/2.36-9/binfiles?fileinfo=1'

# 3. hash -> bytes
curl -sSL -o libc6-dev.deb https://snapshot.debian.org/file/82bdd995c40d95372b69be64cda8abcb69de04da
dpkg-deb -x libc6-dev.deb root/     # no root required
```

The `binfiles` response has no architecture field: the architecture is inside
the filename (`libc6-dev_2.36-9_amd64.deb`), and 2.36-9 has fifteen of them.
A harvester that does not split it out fetches whichever the dict iterated
first, which for a signature library is not a small error -- an aarch64
`libc.a` keyed as amd64 matches nothing and looks like the matcher being broken.

### Ubuntu

Launchpad is the authority on what is published in a `(series, arch)`, and it
is anonymous:

```bash
PUB=$(curl -sG https://api.launchpad.net/devel/ubuntu/+archive/primary \
  --data-urlencode ws.op=getPublishedBinaries \
  --data-urlencode binary_name=libc6-dev --data-urlencode exact_match=true \
  --data-urlencode distro_arch_series=/ubuntu/noble/amd64 \
  --data-urlencode status=Published --data-urlencode ws.size=1 \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["entries"][0]["self_link"])')
curl -sG "$PUB" --data-urlencode ws.op=binaryFileUrls
```

Neither call carries a checksum, so the mirror's `Packages` index supplies the
SHA-256 the download is verified against -- and it has to be **three** indexes,
not one. Every Ubuntu LTS moves `libc6-dev` into `-updates` or `-security`
within weeks of release: noble's release pocket has 2.39-0ubuntu8 and Launchpad
publishes 2.39-0ubuntu8.8. A resolver reading only `dists/<series>/` finds a
version Launchpad has long since superseded and has no hash for the one it
actually downloads.

Mirror selection is not cosmetic either: amd64 is on `archive.ubuntu.com`,
every other architecture on `ports.ubuntu.com`, and an Obsolete series on
`old-releases.ubuntu.com` (which has both `/ubuntu/` and `/ubuntu-ports/`). A
harvester that knows only the first URL silently harvests nothing for arm64.

### Alpine

The cheapest source in the matrix, and the only one that hands out the licence
inline:

```bash
curl -sO https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64/APKINDEX.tar.gz
tar xzf APKINDEX.tar.gz          # P: V: A: S: C: L: o: D: p: records
curl -sO https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64/musl-dev-1.2.5-r11.apk
mkdir x && tar xzf musl-dev-1.2.5-r11.apk -C x
```

An `.apk` is three concatenated gzip streams -- signature, control, data. GNU
`tar xzf` walks all three; Python's `tarfile` stops at the end of the first, so
the harvester shells out to `tar` and says so when it has to fall back.

The `C:` field is `Q1` plus the base64 of a 20-byte SHA-1, and it covers the
package's control stream rather than the whole file, so it is recorded as
provenance but cannot verify a download. The file is addressed by its own
SHA-256 instead.

## Network manners

Every request the harvester makes:

- carries `User-Agent: glaurung-sig-harvester/1.0 (+https://github.com/mjbommar/glaurung)`
  -- the project and a place to complain, because an anonymous bulk fetcher is
  indistinguishable from an abusive one;
- waits a fixed delay (default 0.5 s) after the previous one;
- is retried up to four times with exponential backoff, and **not** retried on
  a 4xx that is not 429;
- counts against a hard total-byte cap (default 6 GiB) checked *before* the
  request goes out.

**Robots.** `snapshot.debian.org` disallows `/archive/*`, `/binary/*` and
`/package/*`; only `/mr/` and `/file/` are ever requested, and `/mr/binary/...`
is not `/binary/...` -- the distinction is the whole reason the machine-readable
API exists. `launchpad.net` disallows `/api/`; the API is served from
`api.launchpad.net`, a different host with no `robots.txt`, and downloads come
from `launchpad.net/ubuntu/+archive/primary/+files/`, which is allowed.
`launchpad.net` also sets `DisallowAITraining: /`; nothing fetched here is used
to train anything. `deb.debian.org` and `dl-cdn.alpinelinux.org` serve no
`robots.txt`.

**Resumability.** Packages land in a content-addressed cache under
`~/.cache/glaurung/sources/<source>/<sha256[:2]>/<sha256>/<name>`, with a
by-SHA-1 and a by-URL index into it, so a second run over a warm cache issues
no package request at all and an interrupted run leaves nothing half-written.
Package *indexes* are re-read by default, because they are the one thing here
that legitimately changes; `--reuse-indexes` turns that off for re-deriving an
old harvest or checking that a warm re-run is byte-identical.

## The measured harvest, 2026-09-03

Command, on `siglib/harvester-v1` with the extension built by
`uv run maturin develop --release` and `tools/build_guard.py` reporting `fresh`:

```bash
uv run python -m glaurung.tools.harvest_sources \
    --spec tools/sig_matrix/base.toml \
    --output ~/.cache/glaurung/system-libs
uv run python samples/docker/harvest_system_archives.py \
    --index-root ~/.cache/glaurung/system-libs
uv run python tools/build_signature_set.py \
    --harvest-root ~/.cache/glaurung/system-libs \
    --output ~/.cache/glaurung/system-libs/sigs \
    --image debian- --image ubuntu- --image alpine- --merge
```

**141,076,709 bytes downloaded in 116 requests**, 4,867,232 served from a cache
warmed by earlier single-cell runs; 2.3% of the 6 GiB cap. Fourteen cells, 142
archives, 0 failures.

| cell | variant | archives | archive bytes | raw sigs | unique | ambiguous | build s | stubs | ld scripts | not-archive |
|---|---|---|---|---|---|---|---|---|---|---|
| alpine-v3.20-aarch64 | alpine-v3.20-gcc-13.2.1 | 7 | 19,856,564 | 6,920 | 3,639 | 438 | 0.5 | 8 | 0 | 0 |
| alpine-v3.20-x86_64 | alpine-v3.20-gcc-13.2.1 | 7 | 17,592,610 | 6,867 | 3,925 | 388 | 0.4 | 8 | 0 | 0 |
| alpine-v3.21-aarch64 | alpine-v3.21-gcc-14.2.0 | 7 | 20,935,044 | 7,477 | 3,977 | 476 | 0.5 | 8 | 0 | 0 |
| alpine-v3.21-x86_64 | alpine-v3.21-gcc-14.2.0 | 7 | 18,744,886 | 7,539 | 4,355 | 420 | 0.4 | 8 | 0 | 0 |
| debian-bookworm-amd64 | debian-bookworm-gcc-12.2.0 | 11 | 16,846,338 | 11,560 | 5,833 | 548 | 0.7 | 6 | 1 | 1 |
| debian-bookworm-arm64 | debian-bookworm-gcc-12.2.0 | 10 | 13,856,776 | 9,930 | 4,868 | 517 | 0.6 | 6 | 0 | 1 |
| debian-trixie-amd64 | debian-trixie-gcc-14.2.0 | 12 | 18,767,412 | 12,771 | 6,589 | 599 | 0.7 | 6 | 1 | 1 |
| debian-trixie-arm64 | debian-trixie-gcc-14.2.0 | 12 | 16,453,112 | 11,823 | 5,839 | 619 | 0.8 | 6 | 1 | 1 |
| ubuntu-jammy-amd64 | ubuntu-jammy-gcc-11.4.0 | 11 | 17,737,768 | 11,688 | 5,843 | 566 | 0.7 | 5 | 1 | 1 |
| ubuntu-jammy-arm64 | ubuntu-jammy-gcc-11.4.0 | 10 | 13,969,606 | 9,688 | 4,718 | 516 | 0.6 | 5 | 0 | 1 |
| ubuntu-noble-amd64 | ubuntu-noble-gcc-13.3.0 | 12 | 19,464,578 | 12,922 | 6,503 | 642 | 0.8 | 6 | 1 | 1 |
| ubuntu-noble-arm64 | ubuntu-noble-gcc-13.3.0 | 12 | 16,109,116 | 11,816 | 5,706 | 645 | 0.7 | 6 | 1 | 1 |
| ubuntu-resolute-amd64 | ubuntu-resolute-gcc-15.2.0 | 12 | 20,288,560 | 13,245 | 6,734 | 631 | 0.8 | 6 | 1 | 1 |
| ubuntu-resolute-arm64 | ubuntu-resolute-gcc-15.2.0 | 12 | 17,379,414 | 12,724 | 6,077 | 688 | 0.8 | 6 | 1 | 1 |
| **14 cells** | | **142** | **248,001,784** | **146,970** | **74,606** | **7,693** | **9.0** | **90** | **8** | **10** |

121 of the 142 archives yielded signatures. The 21 that did not are
`libc_nonshared.a`, `libg.a` and `libssp_nonshared.a` -- one to four members
each, no signable function bodies. Output is 95.6 MB of JSON, which is the
argument for `gsig/1` restated: at 1,202 bytes per signature, JSON does not
scale past this.

Added to the Docker harvest already in the same tree, the catalogue is **17
images, 561 archives, 756.6 MB, 222,339 unique signatures**.

### The four outcomes that are not failures

The last three columns are the reason the harvester reports outcomes rather
than a pass/fail. Every one was hit in this run:

- **90 empty stubs.** Eight bytes: the `ar` magic and nothing else. glibc
  merged `libpthread`, `libdl`, `librt`, `libanl` and `libutil` into libc in
  2.34 and has shipped stubs ever since, and every Alpine archive except
  `libc.a` is one. Counting these as failures turns a correct harvest red.
- **8 ld scripts.** `/usr/lib/x86_64-linux-gnu/libm.a` is six lines of GNU ld
  script reading `GROUP ( /usr/lib/x86_64-linux-gnu/libm-2.36.a
  /usr/lib/x86_64-linux-gnu/libmvec.a )`. The paths are **absolute**, so
  following them literally reaches the *host's* glibc when the host has one --
  a wrong answer that succeeds, which is worse than one that fails. Nothing
  outside the extraction root is ever returned. Following them correctly is
  worth 578 signatures on noble-amd64 alone (`libm-2.39` plus `libmvec`).
- **10 not-archives.** `libmcheck.a` is a single relocatable ELF wearing an
  archive's name.
- **Thin archives** (`!<thin>\n`, members are paths into a build tree that does
  not exist here) are classified but did not occur in `base`.

### Compiler evidence, and where it runs out

The `variant` column is `<distro>-<release>-<compiler>` and the compiler half
is evidence with its provenance recorded, not a guess. Four rungs:

| rung | where it comes from | cells in this run |
|---|---|---|
| `comment-section` | an ELF `.comment` in a harvested member (`GCC: (Alpine 14.2.0) 14.2.0`) | the 4 Alpine cells |
| `built-using` | the package stanza's `Built-Using` field | none |
| `libstdcxx-package-version` | the `libstdc++-N-dev` version harvested in the same cell -- that package *is* GCC | the 10 Debian and Ubuntu cells |
| `distro-default` | the spec's `default_compiler`, a major version only | none |

The third rung exists because **Debian and Ubuntu strip `.comment` from
static-library objects**. Measured: `readelf -S` on `adler32.o` out of
`zlib1g-dev 1:1.2.13.dfsg-1`'s `libz.a` reports no `.comment` section at all,
where the Alpine equivalent has one. Without that rung all ten glibc cells
would carry a major-version-only `distro-default` variant and two different
point releases of gcc would key the same library.

## Cross-release overlap

How much two libraries actually share, at the level the matcher compares:
**masked pattern, mask, CRC16 and CRC length**, over the names present in both.
`function_len` is deliberately excluded -- the builder puts it in its ambiguity
key but the matcher never compares it. Regenerate any row with:

```bash
uv run python tools/sig_library_overlap.py --archive libc \
    --triplet x86_64-linux-gnu --markdown \
    --pair debian-bookworm-amd64 debian-trixie-amd64
```

### glibc, `x86_64-linux-gnu`

| left | right | shared names | identical | identical % |
|---|---|---|---|---|
| debian-bookworm-amd64 | debian-trixie-amd64 | 2429 | 1041 | **42.9%** |
| ubuntu-jammy-amd64 | ubuntu-noble-amd64 | 2401 | 453 | 18.9% |
| ubuntu-noble-amd64 | ubuntu-resolute-amd64 | 2591 | 849 | 32.8% |
| debian-bookworm-amd64 | ubuntu-jammy-amd64 | 2362 | 31 | 1.3% |
| debian-trixie-amd64 | ubuntu-noble-amd64 | 2502 | 5 | **0.2%** |
| debian-trixie-amd64 | ubuntu-resolute-amd64 | 2511 | 5 | **0.2%** |
| ubuntu-jammy-amd64 (network) | linux-amd64 (Docker image, `ubuntu:22.04`) | 2531 | 2531 | **100.0%** |

### glibc, `aarch64-linux-gnu`

| left | right | shared names | identical | identical % |
|---|---|---|---|---|
| debian-bookworm-arm64 | debian-trixie-arm64 | 2166 | 10 | 0.5% |
| ubuntu-jammy-arm64 | ubuntu-noble-arm64 | 2125 | 471 | 22.2% |
| ubuntu-noble-arm64 | ubuntu-resolute-arm64 | 2395 | 1 | 0.0% |
| debian-bookworm-arm64 | ubuntu-jammy-arm64 | 2190 | 1131 | 51.6% |
| debian-trixie-arm64 | ubuntu-resolute-arm64 | 2416 | 390 | 16.1% |
| ubuntu-jammy-arm64 (network) | linux-arm64 (Docker image) | 2238 | 2238 | **100.0%** |

### musl libc

| left | right | shared names | identical | identical % |
|---|---|---|---|---|
| alpine-v3.20-x86_64 | alpine-v3.21-x86_64 | 1271 | 961 | 75.6% |
| alpine-v3.20-aarch64 | alpine-v3.21-aarch64 | 1267 | 824 | 65.0% |

### libstdc++ and libz, `x86_64-linux-gnu`

| library | left | right | shared names | identical | identical % |
|---|---|---|---|---|---|
| libstdc++ | debian-bookworm-amd64 | debian-trixie-amd64 | 1941 | 1041 | 53.6% |
| libstdc++ | ubuntu-jammy-amd64 | ubuntu-noble-amd64 | 1850 | 167 | 9.0% |
| libstdc++ | ubuntu-noble-amd64 | ubuntu-resolute-amd64 | 1963 | 399 | 20.3% |
| libstdc++ | debian-trixie-amd64 | ubuntu-resolute-amd64 | 1989 | 201 | 10.1% |
| libz | debian-bookworm-amd64 | debian-trixie-amd64 | 101 | 6 | 5.9% |
| libz | ubuntu-jammy-amd64 | ubuntu-noble-amd64 | 102 | 12 | 11.8% |
| libz | ubuntu-noble-amd64 | ubuntu-resolute-amd64 | 108 | 16 | 14.8% |
| libz | debian-trixie-amd64 | ubuntu-resolute-amd64 | 103 | 13 | 12.6% |

### What the numbers say

**Cross-distro transfer is nil.** 0.2% between trixie and either recent Ubuntu,
on 2,500 shared names. The flags explain it: Ubuntu's `dpkg-buildflags` adds
LTO, forced frame pointers, `_FORTIFY_SOURCE=3` and CET where Debian does not.
One library per `(distro, release, arch, package version)` is the unit of
usefulness, not a nicety.

**Adjacent releases inside a distro line share 19-43% on x86_64**, which is what
makes blob-level deduplication worth doing at distribution time -- but *not*
enough to skip building either release.

**The two 100.0% rows are a cross-check on this lane itself.** The Docker
harvester's `linux-amd64` image is `ubuntu:22.04`; the network harvester's
`ubuntu-jammy-amd64` cell resolves the same package versions through Launchpad
and fetches them from the librarian. Every one of 2,531 shared glibc signatures
is byte-identical between them, and 2,238 of 2,238 on arm64. The two paths agree
exactly. Independently, `ubuntu-resolute-amd64`'s `libc.a` yields
**2,690 unique from 4,375 raw, 137 dropped** -- the same three numbers the
research report measured against this box's *own* `/usr/lib/x86_64-linux-gnu/libc.a`,
which is Ubuntu 26.04.

**Do not read the aarch64 table as the amd64 one.** Its within-distro rows are
much lower (bookworm to trixie is 0.5%, noble to resolute 0.0%) and one
cross-distro row is much higher (bookworm to jammy, 51.6%). Both directions are
reproducible from the command above; neither is explained here, and neither
should be quoted as a general rule. The safe reading is the one the amd64 table
and the architecture control below already support: build every cell.

**Control.** `debian-trixie-amd64` against `debian-trixie-arm64`: 2,267 shared
names, **0** identical signatures. Same distro, same release, same package
version, different instruction set. Architecture is part of the key.

## Licence and redistribution

**We redistribute signatures and names. We never redistribute the archives.**
Not the `.deb`, not the `.apk`, not the `.a` inside them, and not the `.o`
members. None of them is checked into this repository or shipped in any wheel
or release asset.

The position rests on what a signature file is, which the format's own author
states plainly. Hex-Rays,
[IDA F.L.I.R.T. Technology: In-Depth](https://docs.hex-rays.com/core/flirt/concepts/ida-f.l.i.r.t.-technology-in-depth.md):

> the signature file contains no byte from the original libraries, except for
> the names of the functions.

That is literally true of what this builder emits: a 32-byte pattern with every
relocated byte masked out, a CRC16 over the bytes after it, a length, and a
name. The same document has a section headed **Copyright** naming the problem
the design solves -- that "standard libraries may simply not be distributed with
a disassembler" -- and records that about 95% of a signature file is function
names.

Every manifest carries what is needed to check us: package, version,
architecture, suite, source URL, and at least one content hash (SHA-1 from
snapshot and APKINDEX, SHA-256 from a `Packages` index). Anyone can re-fetch the
exact bytes and re-derive the exact signatures. Takedown requests are honoured.

Licences, as the harvest observed them:

| package | spec's summary | what the source says |
|---|---|---|
| `libc6-dev` | LGPL-2.1-or-later | free-form `copyright`, not machine-readable |
| `libstdc++-N-dev` | GPL-3.0-or-later WITH GCC-exception-3.1 | free-form `copyright` |
| `zlib1g-dev` | Zlib | DEP-5 `License:` field: `Zlib` |
| `musl-dev` | MIT | APKINDEX `L:` field: `MIT` |
| `libstdc++-dev` (Alpine) | GPL-3.0-or-later WITH GCC-exception-3.1 | APKINDEX `L:`: `GPL-2.0-or-later AND LGPL-2.1-or-later` |
| `zlib-static` | Zlib | APKINDEX `L:` field: `Zlib` |

A free-form Debian `copyright` file is **not** reduced to an SPDX identifier.
`libc6-dev`'s names the LGPL in three places and the GPL in two, for different
files; collapsing that to one string would be a guess wearing a fact's clothes.
What the manifest records instead is the file's path and the SHA-256 of its
text, which pins the exact statement, beside the spec's human-curated summary.
Where a package declares its licence machine-readably -- Alpine's `L:` field,
Debian's DEP-5 `License:` -- that string is quoted verbatim, including where it
disagrees with the summary, as Alpine's libstdc++ does.

## What this lane did not do

- **Fedora**, above.
- **MSVC and MinGW.** MinGW archives come from the Docker harvest; MSVC needs
  an acquisition on a device where the licence was accepted, which is a
  separate item.
- **`gsig/1`.** Output is JSON, 95.6 MB for 142 archives. The format lane
  converts it.
- **Shipping.** None of these libraries is in `data/sigs/` or in any wheel. The
  distribution lane owns the manifest, the signing and the client cache.
- **More packages per cell.** `base` is three; OpenSSL, BusyBox, SQLite and the
  rest of the priority list in the program's research report are a matter of
  adding rows to the spec, not of changing the harvester.
