# Signature-source fixtures

Real responses from the three distribution sources
`python/glaurung/tools/harvest_sources.py` talks to, plus real files out of the
packages it extracts. Nothing here is invented: every byte came back from the
command in the table below, on **2026-09-03**, and
`python/tests/test_signature_source_harvest.py` parses these and nothing else.

They exist because every way the harvester goes wrong is a *parsing* failure
against a shape nobody checked, and a parsing failure here is silent -- an
unreadable `Depends` field just means the cell has one fewer library in it.

## Captured responses

| File | URL | Trimmed? |
|---|---|---|
| `snapshot-mr-binary-libc6-dev.json` | `https://snapshot.debian.org/mr/binary/libc6-dev/` | yes -- `result` cut to the newest 20 of 813 entries (74 KB whole); the `_glaurung_note` key records it |
| `snapshot-binfiles-libc6-dev-2.36-9.json` | `https://snapshot.debian.org/mr/binary/libc6-dev/2.36-9/binfiles?fileinfo=1` | no, byte for byte |
| `launchpad-getPublishedBinaries-libc6-dev-noble-amd64.json` | `https://api.launchpad.net/devel/ubuntu/+archive/primary?ws.op=getPublishedBinaries&binary_name=libc6-dev&exact_match=true&distro_arch_series=/ubuntu/noble/amd64&status=Published&ws.size=2` | no, byte for byte |
| `launchpad-binaryFileUrls-libc6-dev-noble-amd64.json` | `https://api.launchpad.net/devel/ubuntu/+archive/primary/+binarypub/247543526?ws.op=binaryFileUrls` | no, byte for byte |
| `alpine-APKINDEX-v3.21-x86_64.txt` | `https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64/APKINDEX.tar.gz`, the `APKINDEX` member | yes -- 9 of ~4,000 records (2.2 MB whole): the ones the `base` matrix resolves |
| `debian-Packages-bookworm-amd64.txt` | `https://deb.debian.org/debian/dists/bookworm/main/binary-amd64/Packages.xz`, decompressed | yes -- 9 of ~64,000 stanzas (8.8 MB compressed): `libc6-dev`, `zlib1g-dev` and the whole `g++` dependency path |
| `debian-Packages-trixie-amd64.txt` | `https://deb.debian.org/debian/dists/trixie/main/binary-amd64/Packages.xz`, decompressed | yes -- 13 stanzas, same selection |

Two `Packages` fixtures rather than one because the dependency shape changed
between the releases and the harvester has to handle both:
bookworm is `g++ -> g++-12 -> libstdc++-12-dev`, trixie is
`g++ -> g++-14 -> g++-14-x86-64-linux-gnu -> libstdc++-14-dev`. A one-hop
resolver passes on bookworm and silently drops the C++ library from trixie,
noble and resolute.

## Files out of real packages

Both copied byte for byte out of `libc6-dev 2.36-9+deb12u14` (amd64), fetched
from `https://snapshot.debian.org/file/d609b4707ac7cb95b042958e54fec4d78596ecfc`
and extracted with `dpkg-deb -x`:

| File | What it is |
|---|---|
| `debian-bookworm-libm.a.ldscript` | `/usr/lib/x86_64-linux-gnu/libm.a`, which is not an archive but a GNU ld script reading `GROUP ( /usr/lib/x86_64-linux-gnu/libm-2.36.a /usr/lib/x86_64-linux-gnu/libmvec.a )`. The paths are **absolute**, so following them literally reaches the host's own glibc rather than the extracted package. |
| `debian-bookworm-libpthread.a.stub` | `/usr/lib/x86_64-linux-gnu/libpthread.a`: eight bytes, the `ar` magic and nothing else. glibc merged pthread into libc in 2.34 and has shipped these stubs ever since. A correct result, not a failure. |

## Manifests

`manifests/` holds three real per-cell harvest trees -- one per backend --
recorded in `docs/reference/signature-sources.md`: `debian-trixie-amd64`,
`ubuntu-noble-arm64`, `alpine-v3.21-x86_64`. Provenance only, no archive
content; the archives themselves are distribution packages under their own
licences and are never checked in.

They are checked against the *same* schema
`python/tests/test_system_archive_harvest.py` applies to the Docker harvester's
manifests, because the two harvesters exist to produce one catalogue:
`samples/docker/harvest_system_archives.py --index-root` indexes both trees and
`tools/build_signature_set.py` reads that index without knowing which harvester
wrote a row.

## Refreshing

These are a record of what the sources returned on a date, not a moving target;
a suite that has published a new glibc since does not make them wrong. Recapture
only when a source changes its response *shape*, and update this table with the
new date and command when you do.
