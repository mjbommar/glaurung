"""Harvest distribution static archives over the network, with provenance.

`samples/docker/harvest_system_archives.py` is the *local* half of this job: it
runs inside a `samples/docker` build image and copies out the archives that
image happens to carry, keyed by the `dpkg` database sitting beside them. That
gives one build point per image, and one image per architecture we happen to
build. The signature-library program needs the other axis -- the same library
across releases and distributions -- because the measurement that started the
program is that a glibc library from the wrong release names **one** function
out of 1,090 while the right one names 731. Coverage is a breadth problem.

This module is the network half. It reads a matrix spec (`tools/sig_matrix/`),
resolves every `(distro, release, arch, package)` cell to an exact package
version and a content hash, fetches the package from the distribution's own
infrastructure, extracts its static archives, and writes the same manifest
schema the Docker harvester writes -- so
``harvest_system_archives.py --index-root`` builds one catalogue over both and
``tools/build_signature_set.py`` builds signatures for both without knowing
which harvester produced a row.

**Why this file lives here and not in `samples/docker/`.** The Docker harvester
is in `samples/docker/` because it must run *inside* an image that has no
`glaurung` installed and no repository checkout -- it is copied in and executed
with the image's own `python3`, so it cannot import anything. This one runs on
the host, in the repository's own environment, and is a peer of
`build_flirt_library.py`: same package, same `python -m glaurung.tools.<x>`
entry point, same output tree. Putting it beside its sibling in
`glaurung.tools` is what lets the two be run one after the other.

Three source backends, one interface:

* **Debian** -- suite to exact version through the release's own `Packages`
  index; version to bytes through `snapshot.debian.org`, whose ``/mr/`` and
  ``/file/`` endpoints are the only ones its ``robots.txt`` permits a machine
  to walk (``/archive/*``, ``/binary/*`` and ``/package/*`` are disallowed).
* **Ubuntu** -- Launchpad ``getPublishedBinaries`` and ``binaryFileUrls``,
  anonymous, with the release's `Packages` index for the SHA-256 to verify
  against; ``archive.ubuntu.com`` for amd64, ``ports.ubuntu.com`` for arm64 and
  ``old-releases.ubuntu.com`` once a series goes obsolete.
* **Alpine** -- ``APKINDEX.tar.gz`` from the CDN and the ``.apk`` beside it.

**Network manners.** One fixed delay between requests, bounded retries with
exponential backoff, a User-Agent naming the project and a contact URL, a hard
cap on total bytes downloaded, and a content-addressed cache under
``~/.cache/glaurung/sources/`` so a second run fetches nothing. No endpoint any
`robots.txt` disallows is ever requested.

**Licence position.** The packages are distribution packages under their own
licences and are never redistributed by this repository -- not the ``.deb``,
not the ``.apk``, not the ``.a`` inside them. What is redistributable is the
derived signature file, which by construction holds a masked pattern, a CRC and
a name rather than a copy of the library. Every manifest carries the source
URL, the package hash and the suite, which is enough for anyone to re-fetch the
exact bytes and re-derive the exact signatures. See
``docs/reference/signature-sources.md``.

Usage:
    python -m glaurung.tools.harvest_sources \\
        --spec tools/sig_matrix/base.toml \\
        --output ~/.cache/glaurung/system-libs

    # What would be fetched, and how many bytes, without fetching it:
    python -m glaurung.tools.harvest_sources --spec ... --dry-run
"""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import json
import lzma
import re
import shutil
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Protocol, Sequence

#: Matches ``samples/docker/harvest_system_archives.py``. The two harvesters
#: write the same manifest shape on purpose: one catalogue, two producers.
SCHEMA_VERSION = "1"

#: The eight bytes that open an ``ar`` archive, and the thin-archive variant.
AR_MAGIC = b"!<arch>\n"
AR_THIN_MAGIC = b"!<thin>\n"

#: ``GROUP ( ... )`` / ``INPUT ( ... )`` in a GNU ld script. glibc ships
#: ``libm.a`` as a script naming the versioned ``libm-2.43.a``, so a harvest
#: that does not read this misses libm entirely.
_LD_SCRIPT_RE = re.compile(r"(?:GROUP|INPUT)\s*\(([^)]*)\)")

#: ``libstdc++-14-dev`` and friends, in a Debian ``Depends`` field.
_LIBSTDCXX_DEV_RE = re.compile(r"\blibstdc\+\+-(\d+)-dev\b")

#: ``g++-14`` in the ``g++`` metapackage's ``Depends`` field.
_GXX_VERSIONED_RE = re.compile(r"\bg\+\+-(\d+)\b")

#: The ``GCC: (Debian 12.2.0-14+deb12u1) 12.2.0`` string an ELF ``.comment``
#: section carries.
_COMMENT_GCC_RE = re.compile(r"GCC:\s*\(([^)]*)\)\s*([0-9][0-9.]*)")

#: A trailing dotted version, as in a ``gcc --version`` first line.
_TRAILING_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+)\s*$")

#: The placeholder a spec uses for "whatever C++ dev package this release's
#: default g++ depends on".
LIBSTDCXX_TOKEN = "@libstdcxx-dev"

#: Identify ourselves and say where to complain. Both halves matter: an
#: anonymous bulk fetcher is indistinguishable from an abusive one.
CONTACT_URL = "https://github.com/mjbommar/glaurung"
USER_AGENT = f"glaurung-sig-harvester/1.0 (+{CONTACT_URL})"

#: Seconds between requests to the same host. Not a rate limiter, a manner.
DEFAULT_DELAY_SECONDS = 0.5

#: Total bytes this process may pull down before it refuses to continue.
DEFAULT_BYTE_CAP = 6 * 1024**3

#: How many times a transient failure is retried, and the base of the backoff.
DEFAULT_RETRIES = 4
DEFAULT_BACKOFF_SECONDS = 1.5

#: Distro architecture name -> the GNU triplet its static archives live under.
_TRIPLET_BY_ARCH: dict[tuple[str, str], str] = {
    ("debian", "amd64"): "x86_64-linux-gnu",
    ("debian", "arm64"): "aarch64-linux-gnu",
    ("debian", "i386"): "i386-linux-gnu",
    ("debian", "armhf"): "arm-linux-gnueabihf",
    ("debian", "riscv64"): "riscv64-linux-gnu",
    ("ubuntu", "amd64"): "x86_64-linux-gnu",
    ("ubuntu", "arm64"): "aarch64-linux-gnu",
    ("ubuntu", "i386"): "i386-linux-gnu",
    ("ubuntu", "armhf"): "arm-linux-gnueabihf",
    ("ubuntu", "riscv64"): "riscv64-linux-gnu",
    ("alpine", "x86_64"): "x86_64-linux-musl",
    ("alpine", "aarch64"): "aarch64-linux-musl",
    ("alpine", "x86"): "i386-linux-musl",
    ("alpine", "armv7"): "arm-linux-musleabihf",
}

#: GNU triplet prefix -> the ``--arch`` tag ``build_flirt_library`` takes.
#: Same table as the Docker harvester's, because it keys the same libraries.
_ARCH_BY_PREFIX: tuple[tuple[str, str], ...] = (
    ("x86_64", "x86_64"),
    ("i686", "i386"),
    ("i386", "i386"),
    ("aarch64", "aarch64"),
    ("arm", "arm"),
    ("riscv64", "riscv64"),
    ("powerpc64le", "ppc64le"),
    ("s390x", "s390x"),
)


class HarvestError(RuntimeError):
    """A harvest could not continue. Distinct from a per-package failure."""


class DownloadCapExceeded(HarvestError):
    """The lane's total download budget is spent."""


# ---------------------------------------------------------------------------
# Pure parsers. Everything here is a function of bytes we already have, which
# is what makes the network layer testable against committed fixtures.
# ---------------------------------------------------------------------------


def parse_snapshot_versions(payload: str | bytes) -> list[str]:
    """Return the package versions ``snapshot.debian.org`` knows about.

    Args:
        payload: The body of ``https://snapshot.debian.org/mr/binary/<pkg>/``.

    Returns:
        Every ``binary_version``, newest first as snapshot orders them, with
        duplicates removed and order otherwise preserved. 813 entries for
        ``libc6-dev`` at the time of writing, back to 1998.

    Raises:
        HarvestError: The body is not the JSON object that endpoint returns.
    """
    try:
        data = json.loads(payload)
        rows = data["result"]
    except (ValueError, KeyError, TypeError) as exc:
        raise HarvestError(f"not a snapshot /mr/binary listing: {exc}") from exc
    seen: set[str] = set()
    out: list[str] = []
    for row in rows:
        version = str(row.get("binary_version", ""))
        if version and version not in seen:
            seen.add(version)
            out.append(version)
    return out


def parse_snapshot_binfiles(payload: str | bytes) -> list[dict[str, Any]]:
    """Return one row per file of one package version, with its SHA-1.

    ``/mr/binary/<pkg>/<ver>/binfiles?fileinfo=1`` maps a SHA-1 to the several
    names that hash has ever been published under. The architecture is not a
    field: it is in the filename, ``libc6-dev_2.36-9_amd64.deb``, which is why
    this parser splits it out rather than leaving the caller to.

    Args:
        payload: The endpoint's body.

    Returns:
        Rows of ``{sha1, name, arch, size, path, archive_name, first_seen}``,
        sorted by ``(arch, name, sha1)`` so a re-parse is order-stable.

    Raises:
        HarvestError: The body is not that endpoint's JSON.
    """
    try:
        data = json.loads(payload)
        fileinfo = data["fileinfo"]
    except (ValueError, KeyError, TypeError) as exc:
        raise HarvestError(f"not a snapshot binfiles response: {exc}") from exc

    rows: list[dict[str, Any]] = []
    for sha1, entries in fileinfo.items():
        for entry in entries:
            name = str(entry.get("name", ""))
            rows.append(
                {
                    "sha1": str(sha1),
                    "name": name,
                    "arch": _arch_from_deb_name(name),
                    "size": int(entry.get("size", 0)),
                    "path": str(entry.get("path", "")),
                    "archive_name": str(entry.get("archive_name", "")),
                    "first_seen": str(entry.get("first_seen", "")),
                }
            )
    rows.sort(key=lambda r: (r["arch"], r["name"], r["sha1"]))
    return rows


def _arch_from_deb_name(name: str) -> str:
    """``libc6-dev_2.36-9_amd64.deb`` -> ``amd64``; ``""`` when unreadable."""
    stem = name[: -len(".deb")] if name.endswith(".deb") else name
    parts = stem.rsplit("_", 1)
    return parts[1] if len(parts) == 2 else ""


def parse_launchpad_published(payload: str | bytes) -> list[dict[str, Any]]:
    """Return the publication rows of a Launchpad ``getPublishedBinaries`` call.

    Args:
        payload: The API response body.

    Returns:
        Rows of ``{self_link, binary_package_name, binary_package_version,
        source_package_name, source_package_version, status, pocket,
        date_published, component_name}``, in the order Launchpad returned
        them (newest publication first).

    Raises:
        HarvestError: The body is not a Launchpad collection.
    """
    try:
        data = json.loads(payload)
        entries = data["entries"]
    except (ValueError, KeyError, TypeError) as exc:
        raise HarvestError(f"not a Launchpad collection: {exc}") from exc

    keys = (
        "self_link",
        "binary_package_name",
        "binary_package_version",
        "source_package_name",
        "source_package_version",
        "status",
        "pocket",
        "date_published",
        "component_name",
    )
    return [{k: entry.get(k) for k in keys} for entry in entries]


def parse_launchpad_file_urls(payload: str | bytes) -> list[str]:
    """Return the download URLs of a ``binaryFileUrls`` call.

    Args:
        payload: The API response body, a bare JSON list of strings.

    Returns:
        The URLs, unchanged.

    Raises:
        HarvestError: The body is not a list of strings.
    """
    try:
        data = json.loads(payload)
    except ValueError as exc:
        raise HarvestError(f"not JSON: {exc}") from exc
    if not isinstance(data, list) or not all(isinstance(u, str) for u in data):
        raise HarvestError("binaryFileUrls did not return a list of strings")
    return list(data)


def parse_apkindex(text: str) -> list[dict[str, str]]:
    """Parse an Alpine ``APKINDEX`` into one dict per package.

    The format is RFC822-ish but with one-letter keys: ``P`` package, ``V``
    version, ``A`` arch, ``S`` package size, ``I`` installed size, ``L``
    licence, ``o`` origin, ``D`` depends, ``p`` provides, ``C`` checksum.
    Records are separated by a blank line.

    Args:
        text: The decompressed ``APKINDEX`` member of ``APKINDEX.tar.gz``.

    Returns:
        One dict per record, keys as they appear in the file, in file order.
        Records with no ``P`` are dropped -- the index's own trailing blank
        lines produce them.
    """
    out: list[dict[str, str]] = []
    record: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if record.get("P"):
                out.append(record)
            record = {}
            continue
        key, sep, value = line.partition(":")
        if sep:
            record[key] = value
    if record.get("P"):
        out.append(record)
    return out


def apk_checksum_to_sha1(checksum: str) -> str:
    """Decode an APKINDEX ``C:`` field to a hex SHA-1.

    apk v2 writes ``Q1`` followed by the base64 of the 20-byte SHA-1 of the
    package's second gzip stream. Anything else -- a future ``Q2``, a truncated
    field -- returns the empty string rather than a wrong hash.

    Args:
        checksum: The raw ``C:`` value, e.g. ``Q1wUlCOIuDUtbMTXswEWsLET42K2o=``.

    Returns:
        40 lowercase hex characters, or ``""``.
    """
    if not checksum.startswith("Q1"):
        return ""
    try:
        raw = base64.b64decode(checksum[2:], validate=True)
    except (binascii.Error, ValueError):
        return ""
    return raw.hex() if len(raw) == 20 else ""


def parse_deb822(text: str) -> list[dict[str, str]]:
    """Parse a Debian control-format stream (a ``Packages`` file) into stanzas.

    Continuation lines (leading space or tab) are folded into the previous
    field with their newlines preserved, which is what ``Description`` and
    multi-line ``Depends`` need.

    Args:
        text: The decompressed index.

    Returns:
        One dict per stanza, in file order. Field names keep their case.
    """
    out: list[dict[str, str]] = []
    stanza: dict[str, str] = {}
    last_key = ""
    for line in text.split("\n"):
        if not line.strip():
            if stanza:
                out.append(stanza)
            stanza = {}
            last_key = ""
            continue
        if line[0] in " \t" and last_key:
            stanza[last_key] = stanza[last_key] + "\n" + line.strip()
            continue
        key, sep, value = line.partition(":")
        if sep:
            last_key = key
            stanza[key] = value.strip()
    if stanza:
        out.append(stanza)
    return out


def index_deb822(stanzas: Iterable[dict[str, str]]) -> dict[str, dict[str, str]]:
    """Reduce a `Packages` stream to ``package name -> stanza``.

    A suite can publish one package name more than once (``Packages`` for the
    release pocket does not, but a merged index does); the **first** stanza
    wins, deterministically, rather than the last one read.
    """
    by_name: dict[str, dict[str, str]] = {}
    for stanza in stanzas:
        name = stanza.get("Package", "")
        if name and name not in by_name:
            by_name[name] = stanza
    return by_name


def parse_ld_script(text: str) -> list[str]:
    """Return the ``.a`` names a GNU ld script's ``GROUP``/``INPUT`` lists.

    Args:
        text: The first few KB of a file that is not an ``ar`` archive.

    Returns:
        The archive names in the order they appear, with ``-l`` forms and
        non-``.a`` tokens dropped. Empty when the text is not an ld script.
    """
    names: list[str] = []
    for group in _LD_SCRIPT_RE.findall(text):
        for token in group.replace(",", " ").split():
            if token.endswith(".a"):
                names.append(token)
    return names


def triplet_for(distro: str, arch: str) -> str:
    """Return the GNU triplet a distro's static archives live under.

    Args:
        distro: ``debian``, ``ubuntu`` or ``alpine``.
        arch: The distribution's own architecture name -- ``amd64`` on Debian
            and Ubuntu, ``x86_64`` on Alpine. They disagree, and the disagreement
            is exactly why this is a table.

    Returns:
        The triplet, or ``"unknown"`` for a pair not in the table.
    """
    return _TRIPLET_BY_ARCH.get((distro, arch), "unknown")


def arch_for_triplet(triplet: str) -> str:
    """Return the ``--arch`` tag for a target triplet.

    Args:
        triplet: A GNU triplet, e.g. ``aarch64-linux-musl``.

    Returns:
        The architecture tag, or ``"unknown"``.
    """
    head = triplet.split("-", 1)[0]
    for prefix, arch in _ARCH_BY_PREFIX:
        if head == prefix:
            return arch
    return "unknown"


def variant_string(distro: str, release: str, compiler: str) -> str:
    """Return the ``<distro>-<release>-<compiler>`` variant tag.

    The variant is part of a library's identity, not metadata about it: no
    masked scheme crosses an optimisation level or a compiler, so two builds
    of glibc that differ in either are two libraries sharing a name.

    Args:
        distro: ``debian``, ``ubuntu``, ``alpine``.
        release: ``bookworm``, ``noble``, ``v3.21``.
        compiler: ``gcc-12.2.0``, or ``gcc`` when no version could be read.

    Returns:
        e.g. ``debian-bookworm-gcc-12.2.0``.
    """
    return f"{distro}-{release}-{compiler}"


# ---------------------------------------------------------------------------
# ar and ELF, in pure Python. Enough of each to answer three questions the
# harvest has to answer per file: is this an archive, how many members does it
# have, and which compiler wrote them.
# ---------------------------------------------------------------------------


def iter_ar_members(data: bytes) -> Iterator[tuple[str, bytes]]:
    """Yield ``(name, body)`` for each member of an ``ar`` archive.

    Handles the two name encodings GNU ``ar`` uses -- ``name/`` inline and
    ``/<offset>`` into the ``//`` long-name table -- and skips the ``/`` symbol
    index. A truncated archive stops yielding rather than raising: a partial
    read is a fact about the file, and the caller records it as a member count.

    Args:
        data: The whole archive.

    Yields:
        ``(member name, member bytes)`` in file order.
    """
    if not data.startswith(AR_MAGIC):
        return
    offset = len(AR_MAGIC)
    longnames = b""
    while offset + 60 <= len(data):
        header = data[offset : offset + 60]
        if header[58:60] != b"\x60\n":
            return
        raw_name = header[0:16].decode("ascii", "replace")
        try:
            size = int(header[48:58].decode("ascii", "replace").strip() or "0")
        except ValueError:
            return
        body = data[offset + 60 : offset + 60 + size]
        if len(body) < size:
            return
        offset += 60 + size + (size & 1)

        name = raw_name.strip()
        if name == "//":
            longnames = body
            continue
        if name in ("/", "/SYM64/"):
            continue
        if name.startswith("/") and name[1:].isdigit():
            start = int(name[1:])
            end = longnames.find(b"/\n", start)
            if end < 0:
                end = longnames.find(b"/", start)
            name = longnames[start : max(end, start)].decode("ascii", "replace")
        yield name.rstrip("/"), body


def elf_comment(data: bytes) -> str:
    """Return an ELF object's ``.comment`` section as text.

    That section is where the compiler stamps itself: ``GCC: (Debian
    12.2.0-14+deb12u1) 12.2.0``. It is the only in-band evidence of who built a
    distribution archive -- ``Built-Using`` is about source packages and is
    usually absent -- so the harvester reads it rather than assuming the
    release's default compiler.

    Args:
        data: A relocatable ELF object.

    Returns:
        The section's NUL-separated strings joined by ``"; "``, or ``""`` when
        the input is not an ELF or carries no ``.comment``.
    """
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return ""
    is64 = data[4] == 2
    little = data[5] == 1
    order = "little" if little else "big"

    def u(off: int, size: int) -> int:
        return int.from_bytes(data[off : off + size], order)  # type: ignore[arg-type]

    try:
        if is64:
            e_shoff, e_shentsize, e_shnum, e_shstrndx = (
                u(0x28, 8),
                u(0x3A, 2),
                u(0x3C, 2),
                u(0x3E, 2),
            )
        else:
            e_shoff, e_shentsize, e_shnum, e_shstrndx = (
                u(0x20, 4),
                u(0x2E, 2),
                u(0x30, 2),
                u(0x32, 2),
            )
        if not e_shoff or not e_shnum or e_shstrndx >= e_shnum:
            return ""
        name_off, name_size = _elf_section_extent(
            data, e_shoff, e_shentsize, e_shstrndx, is64, order
        )
        shstr = data[name_off : name_off + name_size]
        for i in range(e_shnum):
            hdr = e_shoff + i * e_shentsize
            sh_name = u(hdr, 4)
            end = shstr.find(b"\x00", sh_name)
            if shstr[sh_name : end if end >= 0 else None] != b".comment":
                continue
            off, size = _elf_section_extent(data, e_shoff, e_shentsize, i, is64, order)
            body = data[off : off + size]
            parts = [p.decode("utf-8", "replace") for p in body.split(b"\x00") if p]
            return "; ".join(dict.fromkeys(parts))
    except (IndexError, ValueError):
        return ""
    return ""


def _elf_section_extent(
    data: bytes, shoff: int, shentsize: int, index: int, is64: bool, order: str
) -> tuple[int, int]:
    """Return ``(sh_offset, sh_size)`` of one section header."""
    hdr = shoff + index * shentsize
    if is64:
        off = int.from_bytes(data[hdr + 0x18 : hdr + 0x20], order)  # type: ignore[arg-type]
        size = int.from_bytes(data[hdr + 0x20 : hdr + 0x28], order)  # type: ignore[arg-type]
    else:
        off = int.from_bytes(data[hdr + 0x10 : hdr + 0x14], order)  # type: ignore[arg-type]
        size = int.from_bytes(data[hdr + 0x14 : hdr + 0x18], order)  # type: ignore[arg-type]
    return off, size


def compiler_from_archive(path: Path, *, max_members: int = 8) -> str:
    """Read the compiler stamp out of an archive's first few ELF members.

    Args:
        path: An ``ar`` archive.
        max_members: How many members to look at before giving up. The stamp is
            the same in every member of one build, so a handful is plenty and
            a whole 5 MB `libc.a` is not worth walking.

    Returns:
        The first ``.comment`` string found, e.g.
        ``GCC: (Debian 12.2.0-14) 12.2.0``, or ``""``.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    for i, (_name, body) in enumerate(iter_ar_members(data)):
        if i >= max_members:
            break
        comment = elf_comment(body)
        if comment:
            return comment
    return ""


def compiler_tag(
    comment: str,
    fallback: str,
    *,
    built_using: str = "",
    libstdcxx_version: str = "",
) -> tuple[str, str]:
    """Condense the evidence about who built a cell into a variant fragment.

    Four sources, strongest first, and the manifest records which one answered,
    because "we read it out of the object" and "we assumed the release default"
    are not the same claim:

    1. ``comment-section`` -- an ELF ``.comment`` in a harvested member. This is
       the only in-band evidence and it is what Alpine gives (``GCC: (Alpine
       14.2.0) 14.2.0``). **Debian and Ubuntu strip it from static-library
       objects**, measured: ``readelf -S`` on ``libz.a(adler32.o)`` from
       ``zlib1g-dev 1:1.2.13.dfsg-1`` has no ``.comment`` section at all. So on
       those two this rung is simply never reached, which is exactly why the
       others exist.
    2. ``built-using`` -- the ``Built-Using`` field of the package's own stanza,
       which names the source packages a binary embeds.
    3. ``libstdcxx-package-version`` -- the version of the ``libstdc++-N-dev``
       package harvested in the same cell. That package *is* GCC: its version is
       the compiler's, to the patch level (``12.2.0-14+deb12u1`` -> 12.2.0).
    4. ``distro-default`` -- the spec's ``default_compiler``, a major version
       only.

    Args:
        comment: An ELF ``.comment`` string, or ``""``.
        fallback: The spec's ``default_compiler``, e.g. ``gcc-12``.
        built_using: A ``Built-Using`` field value, or ``""``.
        libstdcxx_version: The version of the cell's C++ dev package, or ``""``.

    Returns:
        ``(tag, evidence)``.
    """
    match = _COMMENT_GCC_RE.search(comment)
    if match:
        return f"gcc-{match.group(2)}", "comment-section"
    trailing = _TRAILING_VERSION_RE.search(comment.strip())
    if trailing:
        return f"gcc-{trailing.group(1)}", "comment-section"
    gcc_source = re.search(r"\bgcc-\d+\s*\(=\s*([0-9][0-9.]*)", built_using)
    if gcc_source:
        return f"gcc-{gcc_source.group(1)}", "built-using"
    upstream = re.match(r"(\d+\.\d+\.\d+)", libstdcxx_version)
    if upstream:
        return f"gcc-{upstream.group(1)}", "libstdcxx-package-version"
    return fallback, "distro-default"


# ---------------------------------------------------------------------------
# Archive discovery, over an extracted package root.
# ---------------------------------------------------------------------------

#: Outcomes `classify_archive` can report. Every one of these was measured on a
#: real distribution package, and every one silently produces a wrong or empty
#: library if the harvester does not name it.
OUTCOME_ARCHIVE = "archive"
OUTCOME_EMPTY_STUB = "empty_stub"
OUTCOME_LD_SCRIPT = "ld_script"
OUTCOME_THIN = "thin_archive"
OUTCOME_NOT_ARCHIVE = "not_archive"


@dataclass(frozen=True)
class ArchiveFinding:
    """One ``.a`` in an extracted package, and what it turned out to be.

    Attributes:
        path: Absolute path inside the extraction root.
        outcome: One of the ``OUTCOME_*`` constants.
        members: Number of ``ar`` members, ``0`` for anything that is not a
            readable archive.
        resolved_from: The ld script that named this archive, or ``""``.
    """

    path: Path
    outcome: str
    members: int
    resolved_from: str = ""


def classify_archive(path: Path) -> tuple[str, int]:
    """Say what a file named ``lib*.a`` actually is.

    Five outcomes, all of them measured on real packages:

    * ``archive`` -- a normal ``ar`` archive with members.
    * ``empty_stub`` -- eight bytes, magic and nothing else. glibc has shipped
      ``libpthread.a``, ``libdl.a``, ``librt.a``, ``libanl.a`` and ``libutil.a``
      this way since 2.34 merged them into libc, and every Alpine archive
      except ``libc.a`` is one too. **Not a failure**: recording it as one
      turns a correct harvest into a red run.
    * ``ld_script`` -- a GNU ld script. glibc's ``libm.a`` is
      ``GROUP ( libm-2.43.a libmvec.a )``, and no allowlist of unversioned
      basenames can reach what it names.
    * ``thin_archive`` -- ``!<thin>\\n``: members are paths, not bytes, and the
      paths point at a build tree that does not exist here.
    * ``not_archive`` -- a bare relocatable object wearing a ``.a`` name
      (``libmcheck.a``), or anything else.

    Args:
        path: The candidate file.

    Returns:
        ``(outcome, member count)``. The count is ``0`` for everything but
        ``archive``.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return OUTCOME_NOT_ARCHIVE, 0
    if data.startswith(AR_THIN_MAGIC):
        return OUTCOME_THIN, 0
    if data.startswith(AR_MAGIC):
        members = sum(1 for _ in iter_ar_members(data))
        return (OUTCOME_ARCHIVE, members) if members else (OUTCOME_EMPTY_STUB, 0)
    if parse_ld_script(data[:4096].decode("ascii", "replace")):
        return OUTCOME_LD_SCRIPT, 0
    return OUTCOME_NOT_ARCHIVE, 0


def resolve_script_target(name: str, *, script: Path, root: Path) -> Path | None:
    """Resolve one name from an ld script against an *extracted* package root.

    The paths in a distribution's own ld scripts are absolute and describe the
    installed system, not the tarball: Debian's ``libm.a`` reads
    ``GROUP ( /usr/lib/x86_64-linux-gnu/libm-2.36.a
    /usr/lib/x86_64-linux-gnu/libmvec.a )``. Following those literally reaches
    the *host's* glibc when the host happens to have one, and reaches nothing
    when it does not -- either way it is the wrong answer, and the first is the
    worse of the two because it succeeds. Re-rooting is the whole point of this
    function.

    Args:
        name: A token from ``GROUP``/``INPUT``.
        script: The ld script that named it.
        root: The extraction root; nothing outside it is ever returned.

    Returns:
        The archive, or ``None`` when it is not present under ``root``.
    """
    candidates = (
        [root / name.lstrip("/")] if name.startswith("/") else [script.parent / name]
    )
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            resolved.relative_to(root.resolve())
        except (OSError, ValueError):
            continue
        if candidate.is_file():
            return candidate
    return None


def discover_archives(root: Path) -> list[ArchiveFinding]:
    """Find every static archive under an extracted package root.

    A walk, not an allowlist of basenames. The Docker harvester can use an
    allowlist because it is looking at a whole filesystem full of archives it
    does not want; here the root *is* one package, everything in it is wanted,
    and the names are not knowable in advance -- ``libm-2.43.a`` is versioned
    and only the ld script knows the version.

    Args:
        root: Directory a package was extracted into.

    Returns:
        Findings sorted by path, with ld-script targets appearing as their own
        ``archive`` findings carrying ``resolved_from``. The script itself is
        also reported, as ``ld_script``, so the manifest shows both.
    """
    found: list[ArchiveFinding] = []
    seen: set[Path] = set()
    for path in sorted(root.rglob("*.a")):
        if not path.is_file() or path.is_symlink():
            continue
        outcome, members = classify_archive(path)
        if path not in seen:
            seen.add(path)
            found.append(ArchiveFinding(path=path, outcome=outcome, members=members))
        if outcome != OUTCOME_LD_SCRIPT:
            continue
        text = path.read_bytes()[:4096].decode("ascii", "replace")
        for name in parse_ld_script(text):
            target = resolve_script_target(name, script=path, root=root)
            if target is None or target in seen:
                continue
            sub_outcome, sub_members = classify_archive(target)
            seen.add(target)
            found.append(
                ArchiveFinding(
                    path=target,
                    outcome=sub_outcome,
                    members=sub_members,
                    resolved_from=str(path.relative_to(root)),
                )
            )
    found.sort(key=lambda f: str(f.path))
    return found


def read_copyright_licence(root: Path, package: str) -> dict[str, str]:
    """Read what a Debian package's ``copyright`` file says about its licence.

    Deliberately conservative. A machine-readable (DEP-5) file has a
    ``License:`` field and that field is quoted verbatim; a free-form one --
    which is what glibc, libstdc++ and most of the old packages actually ship
    -- is **not** parsed into an SPDX identifier, because it is not one. Debian's
    own ``libc6-dev`` copyright names the LGPL in three places and the GPL in
    two, for different files, and reducing that to a single string would be a
    guess wearing a fact's clothes.

    What is recorded instead is where the file is and the SHA-256 of its text,
    which pins the exact statement without paraphrasing it. The spec's
    ``[licences]`` table carries the human-curated summary beside it.

    Args:
        root: Extraction root.
        package: The binary package name.

    Returns:
        ``{"licence", "licence_source", "licence_file_sha256"}``. ``licence``
        is ``""`` for a free-form file.
    """
    candidate = root / "usr" / "share" / "doc" / package / "copyright"
    if not candidate.is_file():
        matches = sorted(root.glob("usr/share/doc/*/copyright"))
        if not matches:
            return {"licence": "", "licence_source": "", "licence_file_sha256": ""}
        candidate = matches[0]
    try:
        raw = candidate.read_bytes()
    except OSError:
        return {"licence": "", "licence_source": "", "licence_file_sha256": ""}
    rel = str(candidate.relative_to(root))
    digest = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8", "replace")
    machine_readable = text.lstrip().startswith("Format:")
    for line in text.splitlines():
        if machine_readable and line.startswith("License:"):
            value = line.partition(":")[2].strip()
            if value:
                return {
                    "licence": value,
                    "licence_source": f"{rel} (DEP-5 License field)",
                    "licence_file_sha256": digest,
                }
    return {
        "licence": "",
        "licence_source": f"{rel} (free-form, not machine-readable)",
        "licence_file_sha256": digest,
    }


# ---------------------------------------------------------------------------
# The network layer.
# ---------------------------------------------------------------------------


@dataclass
class Fetcher:
    """A polite, resumable, capped HTTP client with a content-addressed cache.

    Every request carries a User-Agent naming the project and a contact URL,
    waits a fixed delay after the previous one, and is retried with exponential
    backoff on a transient failure. Every response body larger than a few KB is
    written into ``<cache>/<source>/<sha256[:2]>/<sha256>/<name>``, so a second
    run over a warm cache issues no request at all and the bytes are addressed
    by what they are rather than where they came from.

    Attributes:
        cache_root: Base of the sources cache.
        delay: Seconds to wait between requests.
        cap_bytes: Total download budget for this process.
        retries: Attempts per URL before giving up.
        downloaded: Bytes actually pulled over the network so far.
        served_from_cache: Bytes answered out of the cache.
        requests: Number of network requests issued.
    """

    cache_root: Path
    delay: float = DEFAULT_DELAY_SECONDS
    cap_bytes: int = DEFAULT_BYTE_CAP
    retries: int = DEFAULT_RETRIES
    downloaded: int = 0
    served_from_cache: int = 0
    requests: int = 0
    _last_request: float = field(default=0.0, repr=False)

    def _wait(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if self._last_request and elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request = time.monotonic()

    def get(self, url: str, *, params: dict[str, str] | None = None) -> bytes:
        """Fetch a URL and return its body, without caching it.

        For the small JSON that resolution walks over: a version listing is not
        content-addressable because it changes, so caching it by hash would
        only ever produce misses.

        Args:
            url: Absolute URL.
            params: Query parameters, URL-encoded onto the URL.

        Returns:
            The response body.

        Raises:
            DownloadCapExceeded: The budget is spent.
            HarvestError: Every attempt failed.
        """
        full = f"{url}?{urllib.parse.urlencode(params)}" if params else url
        if self.downloaded >= self.cap_bytes:
            raise DownloadCapExceeded(
                f"download cap of {self.cap_bytes} bytes reached before {full}"
            )
        last: Exception | None = None
        for attempt in range(self.retries):
            self._wait()
            self.requests += 1
            request = urllib.request.Request(full, headers={"User-Agent": USER_AGENT})
            try:
                with urllib.request.urlopen(request, timeout=120) as response:
                    body = response.read()
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                last = exc
                status = getattr(exc, "code", None)
                if status is not None and 400 <= int(status) < 500 and status != 429:
                    break
                time.sleep(DEFAULT_BACKOFF_SECONDS * (2**attempt))
                continue
            self.downloaded += len(body)
            if self.downloaded > self.cap_bytes:
                raise DownloadCapExceeded(
                    f"download cap of {self.cap_bytes} bytes exceeded at {full}"
                )
            return body
        raise HarvestError(f"GET {full} failed after {self.retries} attempts: {last}")

    def get_json(self, url: str, *, params: dict[str, str] | None = None) -> Any:
        """Fetch a URL and parse its body as JSON."""
        return json.loads(self.get(url, params=params))

    def cached_path(self, source: str, digest: str, name: str) -> Path:
        """Return where a blob with this SHA-256 lives in the cache."""
        return self.cache_root / source / digest[:2] / digest / name

    def fetch_file(
        self,
        url: str,
        *,
        source: str,
        name: str,
        expect_sha256: str = "",
        expect_sha1: str = "",
    ) -> tuple[Path, str, bool]:
        """Fetch a file into the content-addressed cache, or find it there.

        Resumability is the point: the cache is keyed by the SHA-256 of the
        bytes, so a run that already has a package skips the request entirely,
        and a run interrupted halfway leaves nothing half-written (the download
        lands beside its final home and is renamed).

        Args:
            url: Where to get it.
            source: Cache namespace -- ``debian``, ``ubuntu``, ``alpine``.
            name: Filename to store it under.
            expect_sha256: Verified after download when non-empty.
            expect_sha1: Verified after download when non-empty. snapshot's
                ``/file/`` endpoint is SHA-1 addressed and gives no SHA-256.

        Returns:
            ``(path, sha256, from_cache)``.

        Raises:
            HarvestError: The bytes did not match an expected hash.
        """
        if expect_sha256:
            hit = self.cached_path(source, expect_sha256, name)
            if hit.is_file():
                self.served_from_cache += hit.stat().st_size
                return hit, expect_sha256, True
        if expect_sha1:
            marker = self.cache_root / source / "by-sha1" / f"{expect_sha1}.json"
            if marker.is_file():
                digest = json.loads(marker.read_text())["sha256"]
                hit = self.cached_path(source, digest, name)
                if hit.is_file():
                    self.served_from_cache += hit.stat().st_size
                    return hit, digest, True

        body = self.get(url)
        digest = hashlib.sha256(body).hexdigest()
        if expect_sha256 and digest != expect_sha256:
            raise HarvestError(f"{url}: sha256 {digest} != expected {expect_sha256}")
        if expect_sha1:
            got = hashlib.sha1(body, usedforsecurity=False).hexdigest()
            if got != expect_sha1:
                raise HarvestError(f"{url}: sha1 {got} != expected {expect_sha1}")

        destination = self.cached_path(source, digest, name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = destination.with_name(destination.name + ".part")
        staging.write_bytes(body)
        staging.replace(destination)
        if expect_sha1:
            marker = self.cache_root / source / "by-sha1" / f"{expect_sha1}.json"
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text(json.dumps({"sha256": digest, "name": name}) + "\n")
        return destination, digest, False


def decompress(name: str, body: bytes) -> str:
    """Decompress a package index by the extension in its URL.

    Args:
        name: The URL or filename, used only for its suffix.
        body: The compressed bytes.

    Returns:
        The decoded text.

    Raises:
        HarvestError: The suffix is not one we handle.
    """
    if name.endswith(".xz"):
        return lzma.decompress(body).decode("utf-8", "replace")
    if name.endswith(".gz"):
        return gzip.decompress(body).decode("utf-8", "replace")
    if name.endswith(".bz2"):
        import bz2

        return bz2.decompress(body).decode("utf-8", "replace")
    raise HarvestError(f"do not know how to decompress {name}")


# ---------------------------------------------------------------------------
# Extraction.
# ---------------------------------------------------------------------------


def extract_deb(package: Path, dest: Path) -> None:
    """Extract a ``.deb`` with ``dpkg-deb -x``, or with ``ar`` plus ``tar``.

    ``dpkg-deb -x`` needs no root and is present on every Debian-derived host,
    but this repository is not one by assumption. The fallback opens the outer
    ``ar`` in Python and hands the ``data.tar.*`` member to ``tarfile``, which
    is enough because a ``.deb``'s data member is a plain compressed tar.

    Args:
        package: The ``.deb``.
        dest: Directory to extract into; created if absent.

    Raises:
        HarvestError: Neither path worked.
    """
    dest.mkdir(parents=True, exist_ok=True)
    if shutil.which("dpkg-deb"):
        proc = subprocess.run(
            ["dpkg-deb", "-x", str(package), str(dest)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            return
        raise HarvestError(f"dpkg-deb -x {package}: {proc.stderr.strip()[:400]}")

    data = package.read_bytes()
    for name, body in iter_ar_members(data):
        if not name.startswith("data.tar"):
            continue
        mode = "r:xz" if name.endswith(".xz") else "r:*"
        import io

        with tarfile.open(fileobj=io.BytesIO(body), mode=mode) as tar:  # type: ignore[call-overload]
            tar.extractall(dest, filter="data")
        return
    raise HarvestError(f"{package}: no data.tar member")


def extract_apk(package: Path, dest: Path) -> None:
    """Extract an ``.apk``, which is three concatenated gzip streams in a trench coat.

    An apk v2 file is the signature stream, the control stream and the data
    stream, each an independently gzipped tar, concatenated. GNU ``tar xzf``
    walks all three; Python's ``tarfile`` stops at the end of the first, which
    is why this shells out and only falls back to ``tarfile`` when ``tar`` is
    absent -- and says so, because the fallback sees less.

    Args:
        package: The ``.apk``.
        dest: Directory to extract into.

    Raises:
        HarvestError: Extraction failed.
    """
    dest.mkdir(parents=True, exist_ok=True)
    if shutil.which("tar"):
        proc = subprocess.run(
            ["tar", "-xzf", str(package), "-C", str(dest)],
            capture_output=True,
            text=True,
            check=False,
        )
        # GNU tar warns on the trailing streams and still extracts everything;
        # a real failure leaves the destination empty.
        if any(dest.iterdir()):
            return
        raise HarvestError(f"tar -xzf {package}: {proc.stderr.strip()[:400]}")
    with tarfile.open(package, mode="r:gz") as tar:
        tar.extractall(dest, filter="data")


# ---------------------------------------------------------------------------
# The backends.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PackageRef:
    """One package, pinned hard enough to re-fetch byte for byte.

    Attributes:
        source: ``debian``, ``ubuntu`` or ``alpine``.
        distro: Same, kept separate because a future backend may serve more
            than one distribution.
        release: ``bookworm``, ``noble``, ``v3.21``.
        suite: ``bookworm/main`` -- the repository component the version was
            published in, which is what tells a later reader whether a package
            came from the release pocket or from updates.
        arch: The distribution's own architecture name.
        package: Binary package name.
        version: Exact version string.
        url: Where the bytes were fetched from.
        filename: Basename at the source.
        sha1: Content SHA-1, when the source gives one (snapshot, APKINDEX).
        sha256: Content SHA-256, when the source gives one (Packages index).
        size: Declared size in bytes, ``0`` when the source does not say.
        licence: Licence string the source's metadata declares, or ``""``.
        licence_source: Where that string came from.
        built_using: The stanza's ``Built-Using`` field, which is the second
            rung of the compiler-evidence ladder.
        notes: Anything a reader needs to interpret the row.
    """

    source: str
    distro: str
    release: str
    suite: str
    arch: str
    package: str
    version: str
    url: str
    filename: str
    sha1: str = ""
    sha256: str = ""
    size: int = 0
    licence: str = ""
    licence_source: str = ""
    built_using: str = ""
    notes: str = ""


@dataclass(frozen=True)
class Target:
    """One row of the matrix spec: a distro, a release and its architectures."""

    backend: str
    distro: str
    release: str
    version_id: str
    suite: str
    arches: tuple[str, ...]
    packages: tuple[str, ...]
    default_compiler: str
    build_flags: str


class SourceBackend(Protocol):
    """What every source has to be able to do."""

    name: str

    def resolve(self, target: Target, arch: str) -> list[PackageRef]:
        """Return one pinned :class:`PackageRef` per package in the target."""

    def fetch(self, ref: PackageRef) -> tuple[Path, str, bool]:
        """Return ``(cached path, sha256, from_cache)`` for one reference."""

    def extract(self, package: Path, dest: Path) -> None:
        """Extract a fetched package into ``dest``."""


class DebianBackend:
    """Debian: `Packages` index for the version, snapshot.debian.org for bytes.

    The split matters. The index says what ``bookworm/main`` publishes *today*,
    which is the question "which glibc is bookworm" actually asks; snapshot is
    content-addressed and permanent, which is the property a provenance record
    needs. Going to snapshot for the bytes means a manifest written now still
    re-fetches in five years, after the suite has moved on.

    snapshot's ``robots.txt`` disallows ``/archive/*``, ``/binary/*`` and
    ``/package/*``. Only ``/mr/`` and ``/file/`` are requested here.
    """

    name = "debian"
    mirror = "https://deb.debian.org/debian"
    snapshot = "https://snapshot.debian.org"

    def __init__(self, fetcher: Fetcher) -> None:
        self._fetcher = fetcher
        self._indexes: dict[tuple[str, str], dict[str, dict[str, str]]] = {}
        self.index_urls: dict[tuple[str, str], str] = {}

    def packages_index(self, release: str, arch: str) -> dict[str, dict[str, str]]:
        """Return ``package name -> stanza`` for one suite and architecture."""
        key = (release, arch)
        if key in self._indexes:
            return self._indexes[key]
        url = f"{self.mirror}/dists/{release}/main/binary-{arch}/Packages.xz"
        text = decompress(url, self._fetcher.get(url))
        index = index_deb822(parse_deb822(text))
        self._indexes[key] = index
        self.index_urls[key] = url
        return index

    def resolve_package_names(
        self, target: Target, arch: str
    ) -> tuple[list[str], dict[str, str]]:
        """Expand the spec's placeholders into real binary package names.

        Returns:
            ``(names, evidence)`` where ``evidence`` maps a placeholder to the
            dependency edge that resolved it, e.g.
            ``{"@libstdcxx-dev": "g++ -> g++-12 -> libstdc++-12-dev"}``.
        """
        index = self.packages_index(target.release, arch)
        names: list[str] = []
        evidence: dict[str, str] = {}
        for wanted in target.packages:
            if wanted != LIBSTDCXX_TOKEN:
                names.append(wanted)
                continue
            resolved, why = _resolve_libstdcxx_dev(index)
            if resolved:
                names.append(resolved)
            evidence[wanted] = why
        return names, evidence

    def resolve(self, target: Target, arch: str) -> list[PackageRef]:
        """Pin every package of one target/arch cell to a snapshot SHA-1."""
        index = self.packages_index(target.release, arch)
        names, _ = self.resolve_package_names(target, arch)
        refs: list[PackageRef] = []
        for name in names:
            stanza = index.get(name)
            if stanza is None:
                continue
            version = stanza.get("Version", "")
            sha256 = stanza.get("SHA256", "")
            filename = stanza.get("Filename", "")
            sha1, url, note = self._snapshot_file(name, version, arch)
            if not url:
                url = f"{self.mirror}/{filename}"
                note = "snapshot has no record of this version; fetched from the pool"
            refs.append(
                PackageRef(
                    source=self.name,
                    distro=target.distro,
                    release=target.release,
                    suite=target.suite,
                    arch=arch,
                    package=name,
                    version=version,
                    url=url,
                    filename=Path(filename).name or f"{name}_{version}_{arch}.deb",
                    sha1=sha1,
                    sha256=sha256,
                    size=int(stanza.get("Size", "0") or 0),
                    licence="",
                    licence_source="",
                    built_using=stanza.get("Built-Using", ""),
                    notes=note,
                )
            )
        return refs

    def _snapshot_file(
        self, package: str, version: str, arch: str
    ) -> tuple[str, str, str]:
        """Return ``(sha1, url, note)`` for one (package, version, arch)."""
        url = f"{self.snapshot}/mr/binary/{urllib.parse.quote(package)}/{urllib.parse.quote(version)}/binfiles"
        try:
            body = self._fetcher.get(url, params={"fileinfo": "1"})
            rows = parse_snapshot_binfiles(body)
        except HarvestError as exc:
            return "", "", f"snapshot lookup failed: {exc}"
        for row in rows:
            if row["arch"] == arch:
                return (
                    row["sha1"],
                    f"{self.snapshot}/file/{row['sha1']}",
                    f"snapshot {row['archive_name']} first seen {row['first_seen']}",
                )
        return "", "", f"snapshot has no {arch} file for {package} {version}"

    def fetch(self, ref: PackageRef) -> tuple[Path, str, bool]:
        return self._fetcher.fetch_file(
            ref.url,
            source=self.name,
            name=ref.filename,
            expect_sha256=ref.sha256 if "pool" in ref.url else "",
            expect_sha1=ref.sha1 if "/file/" in ref.url else "",
        )

    def extract(self, package: Path, dest: Path) -> None:
        extract_deb(package, dest)


class UbuntuBackend:
    """Ubuntu: Launchpad for the publication, the mirror index for the hash.

    ``getPublishedBinaries`` is the authority on what version is published in a
    given ``(series, arch)`` and ``binaryFileUrls`` is the download it hands
    back; neither carries a checksum, so the release's own ``Packages`` index
    supplies the SHA-256 the download is verified against and the ``g++``
    dependency edge that resolves ``libstdc++-<N>-dev``.

    Mirror selection is not cosmetic: amd64 is on ``archive.ubuntu.com``, every
    other architecture is on ``ports.ubuntu.com``, and once a series goes
    obsolete both move to ``old-releases.ubuntu.com``. A harvester that knows
    only the first URL silently harvests nothing for arm64 and nothing at all
    for an EOL suite.

    ``launchpad.net``'s ``robots.txt`` disallows ``/api/``; the API is served
    from ``api.launchpad.net``, which is a different host with no restriction,
    and downloads come from ``launchpad.net/ubuntu/+archive/primary/+files/``,
    which is allowed.
    """

    name = "ubuntu"
    api = "https://api.launchpad.net/devel"
    archive_mirror = "http://archive.ubuntu.com/ubuntu"
    ports_mirror = "http://ports.ubuntu.com/ubuntu-ports"
    old_archive_mirror = "http://old-releases.ubuntu.com/ubuntu"
    old_ports_mirror = "http://old-releases.ubuntu.com/ubuntu-ports"

    #: The pockets a supported series publishes into. The release pocket is the
    #: one a `Packages` index is usually taken from, and it is the *wrong* one
    #: for glibc: every Ubuntu LTS has moved its libc6-dev into `-updates` or
    #: `-security` within weeks of release, so a resolver that reads only
    #: `dists/<series>/` finds a version Launchpad has long since superseded and
    #: reports no checksum for the one it actually downloads.
    POCKETS = ("", "-updates", "-security")

    def __init__(self, fetcher: Fetcher) -> None:
        self._fetcher = fetcher
        self._indexes: dict[tuple[str, str], dict[str, dict[str, str]]] = {}
        self._by_version: dict[
            tuple[str, str], dict[tuple[str, str], dict[str, str]]
        ] = {}
        self._series_status: dict[str, str] = {}
        self.index_urls: dict[tuple[str, str], str] = {}

    def series_status(self, release: str) -> str:
        """Return Launchpad's status for a series, e.g. ``Supported``.

        An empty string means the series list could not be read, which the
        caller treats as "assume it is current" rather than guessing EOL.
        """
        if not self._series_status:
            try:
                data = self._fetcher.get_json(f"{self.api}/ubuntu/series")
            except (HarvestError, ValueError):
                return ""
            for entry in data.get("entries", []):
                self._series_status[str(entry.get("name"))] = str(entry.get("status"))
        return self._series_status.get(release, "")

    def mirror_for(self, release: str, arch: str) -> str:
        """Return the mirror base URL for one series and architecture."""
        obsolete = self.series_status(release) == "Obsolete"
        if arch in ("amd64", "i386"):
            return self.old_archive_mirror if obsolete else self.archive_mirror
        return self.old_ports_mirror if obsolete else self.ports_mirror

    def _load_indexes(self, release: str, arch: str) -> None:
        """Read the release, updates and security `Packages` for one arch.

        Two views are kept: ``name -> stanza`` from the release pocket, which
        is what the ``g++`` dependency walk wants (it is the *release's* default
        compiler, not a later one), and ``(name, version) -> stanza`` across all
        three pockets, which is how the exact version Launchpad published gets
        its SHA-256.
        """
        key = (release, arch)
        base = self.mirror_for(release, arch)
        by_name: dict[str, dict[str, str]] = {}
        by_version: dict[tuple[str, str], dict[str, str]] = {}
        urls: list[str] = []
        for pocket in self.POCKETS:
            url = f"{base}/dists/{release}{pocket}/main/binary-{arch}/Packages.xz"
            try:
                text = decompress(url, self._fetcher.get(url))
            except (HarvestError, lzma.LZMAError):
                # A series need not publish every pocket, and an EOL one may
                # have dropped some. Missing is not failing.
                continue
            urls.append(url)
            stanzas = parse_deb822(text)
            if not pocket:
                by_name = index_deb822(stanzas)
            for stanza in stanzas:
                name, version = stanza.get("Package", ""), stanza.get("Version", "")
                if name and version:
                    by_version.setdefault((name, version), stanza)
        self._indexes[key] = by_name
        self._by_version[key] = by_version
        self.index_urls[key] = " ".join(urls)

    def packages_index(self, release: str, arch: str) -> dict[str, dict[str, str]]:
        """Return the release pocket's ``package name -> stanza``."""
        if (release, arch) not in self._indexes:
            self._load_indexes(release, arch)
        return self._indexes[(release, arch)]

    def stanza_for(
        self, release: str, arch: str, package: str, version: str
    ) -> dict[str, str]:
        """Return the stanza for one exact version, across all three pockets."""
        if (release, arch) not in self._by_version:
            self._load_indexes(release, arch)
        return self._by_version[(release, arch)].get((package, version), {})

    def resolve_package_names(
        self, target: Target, arch: str
    ) -> tuple[list[str], dict[str, str]]:
        """Expand the spec's placeholders. Same edges as Debian's."""
        index = self.packages_index(target.release, arch)
        names: list[str] = []
        evidence: dict[str, str] = {}
        for wanted in target.packages:
            if wanted != LIBSTDCXX_TOKEN:
                names.append(wanted)
                continue
            resolved, why = _resolve_libstdcxx_dev(index)
            if resolved:
                names.append(resolved)
            evidence[wanted] = why
        return names, evidence

    def published_binary(self, release: str, arch: str, package: str) -> dict[str, Any]:
        """Return the newest ``Published`` binary publication, or ``{}``."""
        rows = parse_launchpad_published(
            self._fetcher.get(
                f"{self.api}/ubuntu/+archive/primary",
                params={
                    "ws.op": "getPublishedBinaries",
                    "binary_name": package,
                    "exact_match": "true",
                    "distro_arch_series": f"/ubuntu/{release}/{arch}",
                    "status": "Published",
                    "ws.size": "1",
                },
            )
        )
        return rows[0] if rows else {}

    def resolve(self, target: Target, arch: str) -> list[PackageRef]:
        """Pin every package of one target/arch cell to a Launchpad file URL."""
        index = self.packages_index(target.release, arch)
        names, _ = self.resolve_package_names(target, arch)
        base = self.mirror_for(target.release, arch)
        refs: list[PackageRef] = []
        for name in names:
            publication = self.published_binary(target.release, arch, name)
            url = ""
            note = ""
            version = str(publication.get("binary_package_version") or "")
            if publication.get("self_link"):
                try:
                    urls = parse_launchpad_file_urls(
                        self._fetcher.get(
                            str(publication["self_link"]),
                            params={"ws.op": "binaryFileUrls"},
                        )
                    )
                except HarvestError as exc:
                    urls, note = [], f"binaryFileUrls failed: {exc}"
                if urls:
                    url = urls[0]
                    note = (
                        f"launchpad {publication.get('pocket')} publication "
                        f"{publication.get('date_published')}"
                    )
            if not version:
                version = index.get(name, {}).get("Version", "")
            stanza = self.stanza_for(target.release, arch, name, version)
            sha256 = stanza.get("SHA256", "")
            if not sha256:
                note = (
                    f"{note}; no {name} {version} in the release, -updates or "
                    "-security index, so the download is unverified"
                ).lstrip("; ")
            if not url and stanza.get("Filename"):
                url = f"{base}/{stanza['Filename']}"
                note = f"launchpad had no publication; fetched from {base}"
            if not url:
                continue
            refs.append(
                PackageRef(
                    source=self.name,
                    distro=target.distro,
                    release=target.release,
                    suite=f"{target.release}/{publication.get('pocket', 'Release')}".lower(),
                    arch=arch,
                    package=name,
                    version=version,
                    url=url,
                    filename=f"{name}_{version}_{arch}.deb",
                    sha1="",
                    sha256=sha256,
                    size=int(stanza.get("Size", "0") or 0),
                    licence="",
                    licence_source="",
                    built_using=stanza.get("Built-Using", ""),
                    notes=note,
                )
            )
        return refs

    def fetch(self, ref: PackageRef) -> tuple[Path, str, bool]:
        return self._fetcher.fetch_file(
            ref.url, source=self.name, name=ref.filename, expect_sha256=ref.sha256
        )

    def extract(self, package: Path, dest: Path) -> None:
        extract_deb(package, dest)


class AlpineBackend:
    """Alpine: ``APKINDEX.tar.gz`` from the CDN, and the ``.apk`` beside it.

    The cheapest source in the matrix and the only one that gives two axes
    nothing else does: musl instead of glibc, and ``-Os`` instead of ``-O2``.
    The index also carries the licence (``L:``) and a content hash (``C:``, a
    base64 SHA-1) inline, so no second request is needed for either.
    """

    name = "alpine"
    cdn = "https://dl-cdn.alpinelinux.org/alpine"

    def __init__(self, fetcher: Fetcher) -> None:
        self._fetcher = fetcher
        self._indexes: dict[tuple[str, str], dict[str, dict[str, str]]] = {}
        self.index_urls: dict[tuple[str, str], str] = {}

    def apkindex(self, release: str, arch: str) -> dict[str, dict[str, str]]:
        """Return ``package name -> APKINDEX record`` for one repo/arch."""
        key = (release, arch)
        if key in self._indexes:
            return self._indexes[key]
        url = f"{self.cdn}/{release}/main/{arch}/APKINDEX.tar.gz"
        body = self._fetcher.get(url)
        text = _apkindex_member(body)
        index: dict[str, dict[str, str]] = {}
        for record in parse_apkindex(text):
            index.setdefault(record["P"], record)
        self._indexes[key] = index
        self.index_urls[key] = url
        return index

    def resolve_package_names(
        self, target: Target, arch: str
    ) -> tuple[list[str], dict[str, str]]:
        """Expand ``@libstdcxx-dev`` through Alpine's ``g++`` dependency edge."""
        index = self.apkindex(target.release, arch)
        names: list[str] = []
        evidence: dict[str, str] = {}
        for wanted in target.packages:
            if wanted != LIBSTDCXX_TOKEN:
                names.append(wanted)
                continue
            depends = index.get("g++", {}).get("D", "")
            match = re.search(r"\b(libstdc\+\+-dev)(?:=\S+)?", depends)
            if match:
                names.append(match.group(1))
                evidence[wanted] = f"g++ -> {match.group(1)}"
            else:
                evidence[wanted] = "g++ has no libstdc++-dev dependency in APKINDEX"
        return names, evidence

    def resolve(self, target: Target, arch: str) -> list[PackageRef]:
        """Pin every package of one target/arch cell to a CDN ``.apk``."""
        index = self.apkindex(target.release, arch)
        names, _ = self.resolve_package_names(target, arch)
        refs: list[PackageRef] = []
        for name in names:
            record = index.get(name)
            if record is None:
                continue
            version = record.get("V", "")
            filename = f"{name}-{version}.apk"
            refs.append(
                PackageRef(
                    source=self.name,
                    distro=target.distro,
                    release=target.release,
                    suite=target.suite,
                    arch=arch,
                    package=name,
                    version=version,
                    url=f"{self.cdn}/{target.release}/main/{arch}/{filename}",
                    filename=filename,
                    sha1=apk_checksum_to_sha1(record.get("C", "")),
                    sha256="",
                    size=int(record.get("S", "0") or 0),
                    licence=record.get("L", ""),
                    licence_source="APKINDEX L: field",
                    notes=f"origin {record.get('o', '')}",
                )
            )
        return refs

    def fetch(self, ref: PackageRef) -> tuple[Path, str, bool]:
        # The APKINDEX `C:` hash covers the package's *control* stream, not the
        # whole file, so it cannot be checked against the download. It is
        # recorded as provenance and the file is addressed by its own SHA-256.
        return self._fetcher.fetch_file(ref.url, source=self.name, name=ref.filename)

    def extract(self, package: Path, dest: Path) -> None:
        extract_apk(package, dest)


def _apkindex_member(body: bytes) -> str:
    """Return the ``APKINDEX`` member of an ``APKINDEX.tar.gz``."""
    import io

    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
        member = tar.extractfile("APKINDEX")
        if member is None:
            raise HarvestError("APKINDEX.tar.gz has no APKINDEX member")
        return member.read().decode("utf-8", "replace")


def _depends_names(stanza: dict[str, str]) -> list[str]:
    """Return the bare package names in a stanza's ``Depends`` field.

    Alternatives (``a | b``), version constraints and architecture
    qualifications are all stripped, because the walk below only needs to know
    which vertices the edge reaches.
    """
    names: list[str] = []
    for clause in stanza.get("Depends", "").replace("\n", " ").split(","):
        for alternative in clause.split("|"):
            name = alternative.strip().split(" ", 1)[0].split(":", 1)[0]
            if name:
                names.append(name)
    return names


def _resolve_libstdcxx_dev(
    index: dict[str, dict[str, str]], *, max_depth: int = 3
) -> tuple[str, str]:
    """Follow ``g++`` to the ``libstdc++-N-dev`` it actually pulls in.

    The point of walking the edge rather than picking the highest ``N`` present
    is that a release publishes several: trixie carries ``libstdc++-12-dev``,
    ``-13-dev`` and ``-14-dev``, and only one of them is what ``g++`` gives you
    and therefore what the distribution's own C++ packages were built against.

    The walk needs to be transitive because the shape changed. In bookworm
    ``g++-12`` depends on ``libstdc++-12-dev`` directly; in trixie ``g++-14``
    depends on ``g++-14-x86-64-linux-gnu``, and the C++ headers hang off *that*.
    A one-hop resolver reports "no libstdc++-N-dev" on every release from trixie
    and noble onwards, which looks exactly like the package having been renamed.

    Args:
        index: ``package name -> stanza`` for one suite and architecture.
        max_depth: How many dependency hops to follow from ``g++``.

    Returns:
        ``(package name, evidence)``. The name is ``""`` when no edge led
        anywhere, and the evidence records the path that was walked.
    """
    if "g++" not in index:
        return "", "no g++ package in the index"

    frontier: list[tuple[str, list[str]]] = [("g++", ["g++"])]
    seen = {"g++"}
    for _ in range(max_depth):
        following: list[tuple[str, list[str]]] = []
        for name, path in frontier:
            for dependency in _depends_names(index.get(name, {})):
                if dependency in seen:
                    continue
                seen.add(dependency)
                match = _LIBSTDCXX_DEV_RE.fullmatch(dependency)
                if match and dependency in index:
                    return dependency, " -> ".join([*path, dependency])
                if dependency in index:
                    following.append((dependency, [*path, dependency]))
        frontier = following

    # No edge reached it. The versioned g++ still names the N, and the
    # matching dev package is published from the same source at the same
    # version, so name it -- and say that is what happened.
    match = _GXX_VERSIONED_RE.search(index["g++"].get("Depends", ""))
    if match:
        candidate = f"libstdc++-{match.group(1)}-dev"
        if candidate in index:
            return candidate, f"g++ -> g++-{match.group(1)}; {candidate} at the same N"
    return "", f"no libstdc++-N-dev within {max_depth} hops of g++"


# ---------------------------------------------------------------------------
# The spec.
# ---------------------------------------------------------------------------


def load_spec(path: Path) -> dict[str, Any]:
    """Load and lightly validate a matrix spec.

    Args:
        path: A TOML file, e.g. ``tools/sig_matrix/base.toml``.

    Returns:
        The parsed document.

    Raises:
        HarvestError: A required key is missing or a target names an unknown
            backend.
    """
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    for key in ("schema_version", "name", "target"):
        if key not in document:
            raise HarvestError(f"{path}: spec has no {key}")
    for row in document["target"]:
        for key in ("backend", "distro", "release", "arches", "packages"):
            if key not in row:
                raise HarvestError(f"{path}: target {row.get('release')} has no {key}")
        if row["backend"] not in ("debian", "ubuntu", "alpine"):
            raise HarvestError(f"{path}: unknown backend {row['backend']}")
    return document


def targets_of(document: dict[str, Any]) -> list[Target]:
    """Return the spec's targets as :class:`Target` values."""
    return [
        Target(
            backend=row["backend"],
            distro=row["distro"],
            release=row["release"],
            version_id=str(row.get("version_id", "")),
            suite=str(row.get("suite", f"{row['release']}/main")),
            arches=tuple(row["arches"]),
            packages=tuple(row["packages"]),
            default_compiler=str(row.get("default_compiler", "gcc")),
            build_flags=str(row.get("build_flags", "")),
        )
        for row in document["target"]
    ]


# ---------------------------------------------------------------------------
# The harvest itself.
# ---------------------------------------------------------------------------


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write ``payload`` deterministically: sorted keys, trailing newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _backend_for(name: str, fetcher: Fetcher) -> Any:
    if name == "debian":
        return DebianBackend(fetcher)
    if name == "ubuntu":
        return UbuntuBackend(fetcher)
    if name == "alpine":
        return AlpineBackend(fetcher)
    raise HarvestError(f"unknown backend {name}")


def harvest_cell(
    backend: Any,
    target: Target,
    arch: str,
    output: Path,
    workdir: Path,
    *,
    expected_licences: dict[str, str],
    dry_run: bool = False,
) -> dict[str, Any]:
    """Harvest one ``(distro, release, arch)`` cell into its own manifest tree.

    Args:
        backend: A :class:`SourceBackend`.
        target: The spec row.
        arch: One of the row's architectures.
        output: Harvest root; the cell lands in
            ``<output>/<distro>-<release>-<arch>/``.
        workdir: Scratch directory for extraction. Reused and cleaned per
            package.
        expected_licences: The spec's ``[licences]`` table.
        dry_run: Resolve and report, fetch nothing.

    Returns:
        The per-cell index dict, in the Docker harvester's "image" shape so
        ``harvest_system_archives.py --index-root`` catalogues both together.
    """
    key = f"{target.distro}-{target.release}-{arch}"
    triplet = triplet_for(target.distro, arch)
    cell_root = output / key
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    refs = backend.resolve(target, arch)
    _names, evidence = backend.resolve_package_names(target, arch)

    rows: list[dict[str, Any]] = []
    outcomes: list[dict[str, Any]] = []
    compiler_comment = ""
    built_using = ""
    libstdcxx_version = ""
    lib_dir = cell_root / triplet / "lib"

    for ref in refs:
        if ref.built_using and not built_using:
            built_using = ref.built_using
        if "libstdc++" in ref.package and not libstdcxx_version:
            libstdcxx_version = ref.version
        row_base = {
            "package": ref.package,
            "package_version": ref.version,
            "package_architecture": ref.arch,
            "package_source_url": ref.url,
            "package_sha1": ref.sha1,
            "package_sha256": ref.sha256,
            "package_filename": ref.filename,
            "package_size": ref.size,
            "package_built_using": ref.built_using,
            "suite": ref.suite,
            "source_backend": ref.source,
            "source_notes": ref.notes,
            "licence_expected": expected_licences.get(ref.package, ""),
            "licence": ref.licence,
            "licence_source": ref.licence_source,
            "licence_file_sha256": "",
        }
        if dry_run:
            outcomes.append({**row_base, "outcome": "dry-run", "name": ""})
            continue

        package_path, package_sha256, from_cache = backend.fetch(ref)
        extract_root = workdir / key / ref.package
        if extract_root.exists():
            shutil.rmtree(extract_root)
        extract_root.mkdir(parents=True)
        backend.extract(package_path, extract_root)

        licence_fields = {
            "licence": ref.licence,
            "licence_source": ref.licence_source,
            "licence_file_sha256": "",
        }
        if not ref.licence:
            licence_fields = read_copyright_licence(extract_root, ref.package)

        for finding in discover_archives(extract_root):
            relative = str(finding.path.relative_to(extract_root))
            record = {
                **row_base,
                **licence_fields,
                "name": finding.path.name,
                "outcome": finding.outcome,
                "ar_members": finding.members,
                "extracted_path": relative,
                "resolved_from": finding.resolved_from,
                "package_sha256": package_sha256 or ref.sha256,
                "fetched_from_cache": from_cache,
            }
            outcomes.append(record)
            if finding.outcome != OUTCOME_ARCHIVE:
                continue
            lib_dir.mkdir(parents=True, exist_ok=True)
            destination = lib_dir / finding.path.name
            shutil.copyfile(finding.path, destination)
            if not compiler_comment:
                compiler_comment = compiler_from_archive(destination)
            rows.append(
                {
                    **record,
                    "relative_path": f"lib/{finding.path.name}",
                    "source_path": relative,
                    "size": destination.stat().st_size,
                    "sha256": _sha256_file(destination),
                    "triplet": triplet,
                    "arch": arch_for_triplet(triplet),
                }
            )
        shutil.rmtree(extract_root, ignore_errors=True)

    tag, tag_evidence = compiler_tag(
        compiler_comment,
        target.default_compiler,
        built_using=built_using,
        libstdcxx_version=libstdcxx_version,
    )
    variant = variant_string(target.distro, target.release, tag)
    compiler = {
        "driver": tag.split("-", 1)[0] or "gcc",
        "path": "",
        "version": compiler_comment or f"{tag} ({tag_evidence})",
        "package": target.default_compiler,
        "package_version": tag,
        "evidence": tag_evidence,
        "built_using": built_using,
        "libstdcxx_package_version": libstdcxx_version,
        "build_flags": target.build_flags,
    }
    for row in rows:
        row["compiler"] = compiler["version"]
        row["compiler_driver"] = compiler["driver"]
        row["variant"] = variant

    rows.sort(key=lambda r: str(r["name"]))
    outcomes.sort(key=lambda r: (str(r["package"]), str(r["name"])))

    image = {
        "name": key,
        "base": f"{target.distro}:{target.release}",
        "os_id": target.distro,
        "os_version_id": target.version_id or target.release,
        "target_os": "linux",
        "target_arch": arch,
        "dpkg_architecture": arch,
        "uname_machine": "",
        "harvest_method": "network",
    }
    source_block = {
        "backend": backend.name,
        "distro": target.distro,
        "release": target.release,
        "suite": target.suite,
        "arch": arch,
        "index_url": backend.index_urls.get((target.release, arch), ""),
        "package_name_evidence": evidence,
        "fetched_utc": generated,
        "user_agent": USER_AGENT,
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": generated,
        "triplet": triplet,
        "arch": arch_for_triplet(triplet),
        "image": image,
        "compiler": compiler,
        "compiler_note": (
            "`compiler.evidence` says which rung of the ladder answered: "
            "`comment-section` (an ELF .comment in a harvested member, the only "
            "in-band evidence -- Alpine has it, Debian and Ubuntu strip it from "
            "static-library objects), `built-using` (the package's Built-Using "
            "field), `libstdcxx-package-version` (the libstdc++-N-dev package "
            "harvested in this same cell is GCC, so its version is the "
            "compiler's), or `distro-default` (the spec's default_compiler, a "
            "major version only). It is never conflated with the package "
            "version, which is recorded separately per archive."
        ),
        "variant": variant,
        "source": source_block,
        "archives": rows,
        "outcomes": outcomes,
        "totals": {
            "archives": len(rows),
            "bytes": sum(int(r["size"]) for r in rows),
            "packages": len(refs),
            **_outcome_totals(outcomes),
        },
    }
    if not dry_run:
        write_json(cell_root / triplet / "manifest.json", manifest)

    index = {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": generated,
        "image": image,
        "source": source_block,
        "triplets": [
            {
                "triplet": triplet,
                "arch": arch_for_triplet(triplet),
                "manifest": f"{triplet}/manifest.json",
                "archives": rows,
                "totals": manifest["totals"],
            }
        ],
        "totals": manifest["totals"],
    }
    if not dry_run:
        write_json(cell_root / "index.json", index)
    return index


def _outcome_totals(outcomes: Sequence[dict[str, Any]]) -> dict[str, int]:
    """Count each ``OUTCOME_*`` in a cell, so an empty harvest is legible.

    An archive that is an 8-byte stub, an ld script or a thin archive produces
    no signatures, and each of those looks exactly like "the harvester is
    broken" if it is not named. This is the difference between a manifest that
    reports 3 archives and one that reports 3 archives, 9 empty stubs and 1 ld
    script resolved.
    """
    totals = {
        f"outcome_{name}": 0
        for name in (
            OUTCOME_ARCHIVE,
            OUTCOME_EMPTY_STUB,
            OUTCOME_LD_SCRIPT,
            OUTCOME_THIN,
            OUTCOME_NOT_ARCHIVE,
        )
    }
    for row in outcomes:
        field_name = f"outcome_{row.get('outcome')}"
        if field_name in totals:
            totals[field_name] += 1
    return totals


def harvest(
    spec_path: Path,
    output: Path,
    *,
    cache_root: Path,
    workdir: Path,
    delay: float = DEFAULT_DELAY_SECONDS,
    cap_bytes: int = DEFAULT_BYTE_CAP,
    only: Sequence[str] = (),
    dry_run: bool = False,
) -> dict[str, Any]:
    """Harvest every cell of a matrix spec.

    Args:
        spec_path: The TOML spec.
        output: Harvest root, shared with the Docker harvester's output.
        cache_root: Content-addressed sources cache.
        workdir: Scratch space for extraction.
        delay: Seconds between requests.
        cap_bytes: Total download budget.
        only: Substrings; a cell key that matches none of them is skipped.
            Empty means every cell.
        dry_run: Resolve versions and report, fetch no packages.

    Returns:
        A run summary. Per-cell failures are recorded in it, not raised: one
        release moving under us is not a reason to lose the other thirteen.
    """
    document = load_spec(spec_path)
    expected = dict(document.get("licences", {}))
    fetcher = Fetcher(cache_root=cache_root, delay=delay, cap_bytes=cap_bytes)

    cells: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for target in targets_of(document):
        backend = _backend_for(target.backend, fetcher)
        for arch in target.arches:
            key = f"{target.distro}-{target.release}-{arch}"
            if only and not any(token in key for token in only):
                continue
            try:
                index = harvest_cell(
                    backend,
                    target,
                    arch,
                    output,
                    workdir,
                    expected_licences=expected,
                    dry_run=dry_run,
                )
            except DownloadCapExceeded as exc:
                failures.append({"key": key, "error": str(exc)})
                print(f"{key}: {exc}", file=sys.stderr, flush=True)
                break
            except (HarvestError, OSError, ValueError) as exc:
                failures.append({"key": key, "error": f"{type(exc).__name__}: {exc}"})
                print(f"{key}: FAILED {exc}", file=sys.stderr, flush=True)
                continue
            totals = index["totals"]
            cells.append(
                {
                    "key": key,
                    "distro": target.distro,
                    "release": target.release,
                    "arch": arch,
                    "triplet": index["triplets"][0]["triplet"],
                    "variant": index["triplets"][0]["archives"][0]["variant"]
                    if index["triplets"][0]["archives"]
                    else "",
                    "totals": totals,
                }
            )
            print(
                f"{key}: {totals['archives']} archives, {totals['bytes']} bytes, "
                f"{totals['outcome_empty_stub']} stubs, "
                f"{totals['outcome_ld_script']} ld scripts",
                flush=True,
            )

    return {
        "schema_version": SCHEMA_VERSION,
        "spec": str(spec_path),
        "spec_name": document["name"],
        "cells": cells,
        "failures": failures,
        "network": {
            "requests": fetcher.requests,
            "downloaded_bytes": fetcher.downloaded,
            "served_from_cache_bytes": fetcher.served_from_cache,
            "cap_bytes": cap_bytes,
            "user_agent": USER_AGENT,
        },
        "totals": {
            "cells": len(cells),
            "archives": sum(int(c["totals"]["archives"]) for c in cells),
            "bytes": sum(int(c["totals"]["bytes"]) for c in cells),
            "failures": len(failures),
        },
    }


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(
        prog="harvest_sources.py",
        description=(
            "Harvest distribution static archives over the network, keyed by "
            "(distro, release, arch, package version), with provenance "
            "sufficient to re-fetch and re-derive. Never redistributes the "
            "packages themselves."
        ),
    )
    parser.add_argument(
        "--spec",
        type=Path,
        default=Path("tools/sig_matrix/base.toml"),
        help="Matrix spec to harvest.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path.home() / ".cache" / "glaurung" / "system-libs",
        help="Harvest root, shared with the Docker harvester.",
    )
    parser.add_argument(
        "--cache",
        type=Path,
        default=Path.home() / ".cache" / "glaurung" / "sources",
        help="Content-addressed cache for downloaded packages.",
    )
    parser.add_argument(
        "--workdir",
        type=Path,
        default=None,
        help="Scratch directory for extraction (default: <cache>/../extract).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY_SECONDS,
        help="Seconds between requests.",
    )
    parser.add_argument(
        "--cap-bytes",
        type=int,
        default=DEFAULT_BYTE_CAP,
        help="Total download budget for this run.",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        help="Harvest only cells whose key contains this substring; repeatable.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve versions and report; fetch no packages.",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="Write the run summary here as JSON.",
    )
    args = parser.parse_args(argv)

    output = args.output.expanduser()
    cache = args.cache.expanduser()
    workdir = (args.workdir or cache.parent / "extract").expanduser()
    workdir.mkdir(parents=True, exist_ok=True)

    summary = harvest(
        args.spec,
        output,
        cache_root=cache,
        workdir=workdir,
        delay=args.delay,
        cap_bytes=args.cap_bytes,
        only=tuple(args.only),
        dry_run=args.dry_run,
    )
    if args.summary:
        write_json(args.summary.expanduser(), summary)

    totals = summary["totals"]
    network = summary["network"]
    print(
        f"\n{totals['cells']} cells, {totals['archives']} archives, "
        f"{totals['bytes']} bytes extracted; "
        f"{network['downloaded_bytes']} bytes downloaded in "
        f"{network['requests']} requests, "
        f"{network['served_from_cache_bytes']} served from cache; "
        f"{totals['failures']} failures"
    )
    return 1 if summary["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
