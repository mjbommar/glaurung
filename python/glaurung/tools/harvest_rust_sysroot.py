"""Harvest Rust standard-library ``.rlib`` archives from installed toolchains.

Ledger item 11 (Rust half) of the signature-library program
(``docs/design/signature-library-program-2026-09-03.md``). Go is explicitly
out of scope there -- it is solved by ``gopclntab`` recovery, not signatures --
so this module only ever reads a rustup sysroot.

**Why a sysroot, not a package manager.** Every other backend in
``glaurung.tools.harvest_sources`` resolves a *distribution package* to bytes.
Rust ships no such thing: ``rustup`` installs a toolchain directory holding
``lib/rustlib/<target>/lib/*.rlib``, one archive per crate in the standard
library and its private dependency graph, with **no separate provenance
record** the way a ``.deb`` carries a ``Packages`` entry. The provenance here
is the toolchain itself -- ``rustc -vV``'s release, commit hash and commit
date -- which is why every row below carries all three rather than a package
version string.

**What an ``.rlib`` is.** An ``ar`` archive (``!<arch>\\n`` magic) whose members
are ``lib.rmeta`` (rustc's own metadata, not an object file), sometimes
``lib.rmeta-link`` (present on toolchains that also ship split rmeta as sysroot
files, absent on others measured on this box), and exactly one ``*.rcgu.o``
member -- a normal ELF relocatable object with a large ``.llvmbc`` section (43
to 45 percent of the object, measured on both toolchains below) that carries
no function bytes and is never read. `glaurung.analysis.flirt_signatures_from_archive_path`
(``src/flirt/archive.rs``) already skips any archive member that does not
parse as an object file -- confirmed by testing directly against real ``.rlib``
files during this lane, with zero changes to ``src/flirt/``: ``lib.rmeta`` and
``lib.rmeta-link`` are silently skipped and the ``.rcgu.o`` member is read
exactly as a distro archive's ``.o`` members are. No defect was found; the
existing builder handles this input class with no repository change.

**Mangling differs by toolchain, which matters for cross-toolchain transfer.**
Measured here: 1.88.0's ``libcore`` defines its 618 text symbols under legacy
Itanium mangling (``_ZN4core...E``); 1.97.1's defines its 869 under v0
(``_R...``). A relocation-masked pattern from one will never byte-match a
function compiled by the other even where the generated code is otherwise
identical, on top of whatever codegen actually changed -- one more reason a
Rust signature library is keyed by the exact toolchain, not the crate name
alone.

**Manifest schema.** Reuses the shared harvest-manifest shape
(`schema_version`, `generated_utc`, `triplet`, `arch`, `image`, `compiler`,
`compiler_note`, `archives`, `totals` -- see `MANIFEST_SCHEMA` /
`ARCHIVE_SCHEMA` / `IMAGE_KEYS` / `COMPILER_KEYS` in
``python/tests/test_system_archive_harvest.py``) so the same validators the
Docker and network harvesters are checked against apply here unchanged, and so
``samples/docker/harvest_system_archives.py --index-root`` can fold a Rust
harvest into the same top-level catalogue as the distro ones. Each archive row
adds Rust-specific fields (``crate``, ``rlib_hash``, ``channel``, ``toolchain``,
``rustc_commit_hash``, ``rustc_commit_date``, ``target_triple``, ``ar_members``,
``outcome``, ``text_bytes``, ``llvmbc_bytes``, ``defined_text_symbols``) beside
the shared ones -- additive, never a replacement for them.

Usage:
    # Enumerate every rlib in every installed toolchain's sysroot:
    python -m glaurung.tools.harvest_rust_sysroot harvest \\
        --output ~/.cache/glaurung/system-libs

    # ...pin to specific toolchains, and try to record a re-fetch pointer:
    python -m glaurung.tools.harvest_rust_sysroot harvest \\
        --output ~/.cache/glaurung/system-libs \\
        --toolchain 1.88.0-x86_64-unknown-linux-gnu \\
        --toolchain 1.97.1-x86_64-unknown-linux-gnu \\
        --network

    # Build FLIRT-style libraries for the priority crate list, keyed
    # rust-std/<rustc version>/<channel>-<target>/<arch>, and extend
    # <sigs-output>/index.json without touching rows this run did not build:
    python -m glaurung.tools.harvest_rust_sysroot build \\
        --harvest-root ~/.cache/glaurung/system-libs \\
        --sigs-output ~/.cache/glaurung/system-libs/sigs

See ``docs/reference/signature-sources.md`` ("Rust") for the measured harvest
and ``docs/reference/function-signature-libraries.md`` for what a signature
file holds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from glaurung.tools.harvest_sources import arch_for_triplet, iter_ar_members

#: Matches ``harvest_sources.SCHEMA_VERSION`` / the Docker harvester's -- one
#: catalogue, however many producers.
SCHEMA_VERSION = "1"

#: The eight bytes that open an ``ar`` archive. Every real ``.rlib`` measured
#: on this box has them; a file that does not is reported, not guessed at.
AR_MAGIC = b"!<arch>\n"

#: ``lib<crate>-<16 hex chars>.rlib``, the rustup sysroot naming convention.
#: The hash is rustc's own crate disambiguator (SVH-derived), not a semantic
#: version -- an ``.rlib`` carries no independent version number, only the
#: rustc release that produced it.
_RLIB_NAME_RE = re.compile(r"^lib(?P<crate>.+)-(?P<hash>[0-9a-f]{16})\.rlib$")

#: One ``key: value`` line of ``rustc -vV``.
_VV_LINE_RE = re.compile(r"^([A-Za-z0-9_-]+):\s*(.*)$")

#: Priority crates for the signature build (Decision 7 of the design page):
#: the standard library itself plus the private dependency graph most likely
#: to appear, unlinked, inside a stripped Rust binary.
DEFAULT_CRATES: tuple[str, ...] = (
    "std",
    "core",
    "alloc",
    "panic_unwind",
    "hashbrown",
    "addr2line",
    "gimli",
    "miniz_oxide",
    "object",
    "memchr",
    "rustc_demangle",
    "std_detect",
    "unwind",
)

#: Identify ourselves and say where to complain, matching
#: ``harvest_sources.USER_AGENT`` in spirit; this backend does not share its
#: HTTP client because it makes at most one request per toolchain.
CONTACT_URL = "https://github.com/mjbommar/glaurung"
USER_AGENT = f"glaurung-sig-harvester/1.0 (+{CONTACT_URL})"

#: Outcomes `classify_rlib` can report. An ``.rlib`` that only carries rustc's
#: own metadata (no object member at all) yields zero signatures by
#: construction -- not a failure, but worth naming so a zero in the build
#: report is not mistaken for the builder being broken.
OUTCOME_ARCHIVE = "archive"
OUTCOME_METADATA_ONLY = "metadata_only"
OUTCOME_NOT_ARCHIVE = "not_archive"


class RustSysrootError(RuntimeError):
    """A toolchain or target could not be read. Distinct from a per-rlib fact."""


@dataclass(frozen=True)
class ToolchainInfo:
    """One installed rustup toolchain, as ``rustc -vV`` describes it.

    Attributes:
        name: The rustup toolchain directory name, e.g.
            ``1.88.0-x86_64-unknown-linux-gnu``.
        channel: ``name`` with the trailing ``-<host>`` stripped, e.g.
            ``1.88.0``, ``stable``, ``nightly-2026-05-01``. Part of a
            library's variant key -- two toolchains that happen to resolve to
            the same rustc build (measured: ``stable`` and ``1.97.1`` share a
            commit hash on this box) are still tracked as distinct channels,
            because a signature's provenance is which toolchain a user has,
            not which commit it happens to alias today.
        root: The toolchain directory.
        host: ``rustc -vV``'s ``host`` field, e.g. ``x86_64-unknown-linux-gnu``.
        release: ``rustc -vV``'s ``release`` field, e.g. ``1.88.0``,
            ``1.97.0-nightly``.
        commit_hash: ``rustc -vV``'s ``commit-hash`` field.
        commit_date: ``rustc -vV``'s ``commit-date`` field.
        llvm_version: ``rustc -vV``'s ``LLVM version`` field.
        version_line: The first line of ``rustc -vV``, e.g.
            ``rustc 1.88.0 (6b00bc388 2025-06-23)``.
    """

    name: str
    channel: str
    root: Path
    host: str
    release: str
    commit_hash: str
    commit_date: str
    llvm_version: str
    version_line: str


@dataclass(frozen=True)
class RlibFinding:
    """What one ``.rlib`` turned out to hold.

    Attributes:
        path: The archive on disk, inside the toolchain's own sysroot --
            never copied, since the builder reads sections directly.
        crate: The crate name parsed from the filename.
        rlib_hash: The 16 hex character disambiguator from the filename.
        members: Every ``ar`` member name, in file order.
        object_member: The ``*.rcgu.o`` member name, or ``""`` when the
            archive carries no object at all (``metadata_only``).
        outcome: One of the ``OUTCOME_*`` constants.
        size: Archive size in bytes.
        sha256: Archive content hash.
        text_bytes: Sum of every ``.text*`` section in the object member.
        llvmbc_bytes: Size of the object member's ``.llvmbc`` section, which
            is bitcode -- irrelevant to signatures, which read ``.text*``.
        defined_text_symbols: Count of defined function symbols in the object
            member (``nm --defined-only``, ``T``/``t``), or ``None`` when
            ``nm`` was unavailable or the archive carries no object.
    """

    path: Path
    crate: str
    rlib_hash: str
    members: tuple[str, ...]
    object_member: str
    outcome: str
    size: int
    sha256: str
    text_bytes: int
    llvmbc_bytes: int
    defined_text_symbols: int | None


def default_rustup_home() -> Path:
    """Return ``$RUSTUP_HOME``, or ``~/.rustup`` when unset."""
    import os

    value = os.environ.get("RUSTUP_HOME", "")
    return Path(value).expanduser() if value else Path.home() / ".rustup"


def discover_toolchains(rustup_home: Path, *, only: Sequence[str] = ()) -> list[str]:
    """List installed toolchain directory names.

    Args:
        rustup_home: A rustup home directory (holds a ``toolchains/`` child).
        only: Substrings; a toolchain name that matches none of them is
            skipped. Empty means every toolchain.

    Returns:
        Sorted directory names. Empty when ``rustup_home`` has no
        ``toolchains/`` at all -- not an error, since the caller may be
        probing a machine with no Rust installed.
    """
    toolchains_dir = rustup_home / "toolchains"
    if not toolchains_dir.is_dir():
        return []
    names = sorted(p.name for p in toolchains_dir.iterdir() if p.is_dir())
    if only:
        names = [n for n in names if any(token in n for token in only)]
    return names


def _parse_vv(stdout: str) -> dict[str, str]:
    """Parse ``rustc -vV`` output into a field dict, plus ``version_line``."""
    lines = stdout.splitlines()
    info: dict[str, str] = {"version_line": lines[0] if lines else ""}
    for line in lines[1:]:
        match = _VV_LINE_RE.match(line)
        if match:
            info[match.group(1)] = match.group(2)
    return info


def load_toolchain(rustup_home: Path, name: str) -> ToolchainInfo | None:
    """Read one toolchain's ``rustc -vV``.

    Args:
        rustup_home: The rustup home directory.
        name: A toolchain directory name from :func:`discover_toolchains`.

    Returns:
        ``None`` when the toolchain has no ``bin/rustc`` or it could not be
        run -- skipped loudly by the caller, never silently treated as zero
        rlibs found.
    """
    root = rustup_home / "toolchains" / name
    rustc_path = root / "bin" / "rustc"
    if not rustc_path.is_file():
        return None
    try:
        proc = subprocess.run(
            [str(rustc_path), "-vV"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    info = _parse_vv(proc.stdout)
    host = info.get("host", "")
    if not host:
        return None
    return ToolchainInfo(
        name=name,
        channel=channel_for_toolchain(name, host),
        root=root,
        host=host,
        release=info.get("release", ""),
        commit_hash=info.get("commit-hash", ""),
        commit_date=info.get("commit-date", ""),
        llvm_version=info.get("LLVM version", ""),
        version_line=info.get("version_line", ""),
    )


def channel_for_toolchain(name: str, host: str) -> str:
    """Strip the trailing ``-<host>`` a rustup toolchain directory name carries.

    Args:
        name: e.g. ``1.88.0-x86_64-unknown-linux-gnu``.
        host: e.g. ``x86_64-unknown-linux-gnu``.

    Returns:
        e.g. ``1.88.0``. Unchanged when ``name`` does not end with ``host``
        (a cross-compiled toolchain directory naming convention this backend
        has not seen).
    """
    suffix = f"-{host}"
    return name[: -len(suffix)] if host and name.endswith(suffix) else name


def sysroot_lib_dir(toolchain: ToolchainInfo, target: str) -> Path:
    """Return ``<toolchain>/lib/rustlib/<target>/lib``."""
    return toolchain.root / "lib" / "rustlib" / target / "lib"


def find_rlibs(lib_dir: Path) -> list[Path]:
    """List every ``*.rlib`` directly under a sysroot lib directory."""
    if not lib_dir.is_dir():
        return []
    return sorted(lib_dir.glob("*.rlib"))


def _read_elf_sections(data: bytes) -> list[tuple[str, int]]:
    """Return ``(section name, size)`` for a 64-bit little-endian ELF object.

    Empty when the input is not recognizably that shape -- every ``.rcgu.o``
    measured on this box's ``x86_64-unknown-linux-gnu`` targets is one; a
    cross-compiled sysroot with a different ELF class or a big-endian target
    is reported as zero rather than guessed at.
    """
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return []

    def u(off: int, size: int) -> int:
        return int.from_bytes(data[off : off + size], "little")

    e_shoff = u(0x28, 8)
    e_shentsize = u(0x3A, 2)
    e_shnum = u(0x3C, 2)
    e_shstrndx = u(0x3E, 2)
    if not e_shoff or not e_shnum or e_shstrndx >= e_shnum:
        return []

    def extent(index: int) -> tuple[int, int]:
        hdr = e_shoff + index * e_shentsize
        return u(hdr + 0x18, 8), u(hdr + 0x20, 8)

    try:
        name_off, name_size = extent(e_shstrndx)
        shstr = data[name_off : name_off + name_size]
        sections: list[tuple[str, int]] = []
        for i in range(e_shnum):
            hdr = e_shoff + i * e_shentsize
            sh_name = u(hdr, 4)
            end = shstr.find(b"\x00", sh_name)
            name = shstr[sh_name : end if end >= 0 else None].decode("utf-8", "replace")
            _, size = extent(i)
            sections.append((name, size))
        return sections
    except (IndexError, ValueError):
        return []


def section_totals(object_bytes: bytes) -> dict[str, int]:
    """Sum ``.text*`` and ``.llvmbc`` section bytes in one ELF object.

    Args:
        object_bytes: A relocatable object, typically an ``.rcgu.o`` member.

    Returns:
        ``{"text_bytes", "llvmbc_bytes"}``, both ``0`` when the input is not
        a readable ELF object.
    """
    text_bytes = 0
    llvmbc_bytes = 0
    for name, size in _read_elf_sections(object_bytes):
        if name == ".llvmbc":
            llvmbc_bytes += size
        elif name.startswith(".text"):
            text_bytes += size
    return {"text_bytes": text_bytes, "llvmbc_bytes": llvmbc_bytes}


def count_defined_text_symbols(
    object_bytes: bytes, *, nm_path: str = "nm"
) -> int | None:
    """Count defined function symbols in an object, via ``nm --defined-only``.

    This is diagnostic only -- it explains a zero-signature crate (e.g. the
    ``unwind`` crate's object measured on this box carries zero defined
    symbols of any kind: its Rust source is ``extern "C"`` declarations for
    the system unwinder, with no bodies to sign) -- and is never fed to the
    builder, which reads relocations and symbols itself via the ``object``
    crate.

    Args:
        object_bytes: A relocatable object.
        nm_path: The ``nm`` binary to run.

    Returns:
        The count, or ``None`` when ``nm`` is unavailable or the bytes are
        not an object it can read.
    """
    try:
        with tempfile.NamedTemporaryFile(suffix=".o") as handle:
            handle.write(object_bytes)
            handle.flush()
            proc = subprocess.run(
                [nm_path, "--defined-only", handle.name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    count = 0
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-2] in ("T", "t"):
            count += 1
    return count


def classify_rlib(path: Path, *, count_symbols: bool = True) -> RlibFinding:
    """Read one ``.rlib``: its members, its object member's sections, and outcome.

    Args:
        path: The archive.
        count_symbols: Whether to also run ``nm`` for a defined-symbol count
            (skippable for a fast enumeration pass).

    Returns:
        A :class:`RlibFinding`. Never raises: an unreadable or truncated
        archive comes back as ``OUTCOME_NOT_ARCHIVE`` with empty members,
        which is a fact about the file, not a reason to abort the harvest.
    """
    data = path.read_bytes()
    match = _RLIB_NAME_RE.match(path.name)
    crate = match.group("crate") if match else path.name.removesuffix(".rlib")
    rlib_hash = match.group("hash") if match else ""
    sha256 = hashlib.sha256(data).hexdigest()
    size = len(data)

    if not data.startswith(AR_MAGIC):
        return RlibFinding(
            path=path,
            crate=crate,
            rlib_hash=rlib_hash,
            members=(),
            object_member="",
            outcome=OUTCOME_NOT_ARCHIVE,
            size=size,
            sha256=sha256,
            text_bytes=0,
            llvmbc_bytes=0,
            defined_text_symbols=None,
        )

    members: list[str] = []
    object_member = ""
    object_bytes = b""
    for name, body in iter_ar_members(data):
        members.append(name)
        if not object_member and name.endswith(".o"):
            object_member = name
            object_bytes = body

    outcome = OUTCOME_ARCHIVE if object_member else OUTCOME_METADATA_ONLY
    text_bytes = llvmbc_bytes = 0
    defined_text_symbols: int | None = None
    if object_bytes:
        totals = section_totals(object_bytes)
        text_bytes = totals["text_bytes"]
        llvmbc_bytes = totals["llvmbc_bytes"]
        if count_symbols:
            defined_text_symbols = count_defined_text_symbols(object_bytes)

    return RlibFinding(
        path=path,
        crate=crate,
        rlib_hash=rlib_hash,
        members=tuple(members),
        object_member=object_member,
        outcome=outcome,
        size=size,
        sha256=sha256,
        text_bytes=text_bytes,
        llvmbc_bytes=llvmbc_bytes,
        defined_text_symbols=defined_text_symbols,
    )


def channel_manifest_url_for(channel: str) -> str:
    """Return the ``channel-rust-*.toml`` URL for a toolchain channel.

    Dated nightly manifests exist only on their own date
    (``static.rust-lang.org/dist/<date>/channel-rust-nightly.toml``); a
    version-pinned or named channel (``1.88.0``, ``stable``, ``nightly``) has
    one directly under ``dist/``. Neither form is derived from ``rustc -V``'s
    commit date, which can differ from the channel's own publish date by a
    day -- measured here: the ``nightly-2026-05-01`` toolchain's commit-date
    is ``2026-04-30``.

    Args:
        channel: A toolchain channel, e.g. ``1.88.0``, ``stable``,
            ``nightly``, ``nightly-2026-05-01``.

    Returns:
        The manifest URL.
    """
    if channel.startswith("nightly-"):
        date = channel.removeprefix("nightly-")
        return f"https://static.rust-lang.org/dist/{date}/channel-rust-nightly.toml"
    return f"https://static.rust-lang.org/dist/channel-rust-{channel}.toml"


def fetch_rust_std_component(
    url: str, target: str, *, timeout: float = 20.0
) -> dict[str, str] | None:
    """Fetch a channel manifest and read the ``rust-std`` component's hash.

    Network is optional throughout this backend: a caller that does not pass
    ``--network`` never calls this, and a failure here is reported to stderr
    and treated as "no re-fetch pointer available" rather than aborting the
    harvest -- the rlibs on disk are the source of truth regardless.

    Args:
        url: A URL from :func:`channel_manifest_url_for`.
        target: The rustc target triple to read the component for.
        timeout: Socket timeout in seconds.

    Returns:
        ``{"url", "sha256", "channel_manifest_url"}`` for the ``xz`` artifact
        (falling back to the plain ``.tar.gz`` fields when ``xz`` is absent),
        or ``None`` when the fetch, parse, or target lookup failed.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            raw = response.read()
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        print(f"warning: could not fetch {url}: {exc}", file=sys.stderr)
        return None
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        print(f"warning: could not parse {url}: {exc}", file=sys.stderr)
        return None
    pkg = document.get("pkg", {}).get("rust-std", {}).get("target", {}).get(target, {})
    if not pkg:
        print(f"warning: {url} has no rust-std component for {target}", file=sys.stderr)
        return None
    return {
        "url": str(pkg.get("xz_url") or pkg.get("url") or ""),
        "sha256": str(pkg.get("xz_hash") or pkg.get("hash") or ""),
        "channel_manifest_url": url,
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write ``payload`` deterministically: sorted keys, trailing newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _outcome_totals(rows: Sequence[dict[str, Any]]) -> dict[str, int]:
    totals = {
        f"outcome_{name}": 0
        for name in (OUTCOME_ARCHIVE, OUTCOME_METADATA_ONLY, OUTCOME_NOT_ARCHIVE)
    }
    for row in rows:
        field_name = f"outcome_{row.get('outcome')}"
        if field_name in totals:
            totals[field_name] += 1
    return totals


def harvest_toolchain(
    toolchain: ToolchainInfo,
    *,
    target: str,
    output: Path,
    network: bool,
    count_symbols: bool = True,
) -> dict[str, Any]:
    """Harvest one toolchain's sysroot into its own manifest tree.

    Writes ``<output>/rust-<toolchain>/<target>/manifest.json`` and
    ``<output>/rust-<toolchain>/index.json`` in the shared harvest-manifest
    schema (``MANIFEST_SCHEMA`` / ``ARCHIVE_SCHEMA`` / ``IMAGE_KEYS`` /
    ``COMPILER_KEYS`` in ``python/tests/test_system_archive_harvest.py``),
    plus Rust-specific fields on every archive row.

    Args:
        toolchain: A loaded toolchain.
        target: The rustc target triple whose sysroot lib dir to read.
        output: Harvest root, shared with the Docker and network harvesters.
        network: Attempt to fetch the channel manifest for a re-fetch
            pointer. Off by default; a failure is never fatal either way.
        count_symbols: Passed to :func:`classify_rlib`.

    Returns:
        The per-image index dict, in the same shape
        ``samples/docker/harvest_system_archives.py --index-root`` reads.
    """
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lib_dir = sysroot_lib_dir(toolchain, target)
    rlibs = find_rlibs(lib_dir)
    arch = arch_for_triplet(target)
    key = f"rust-{toolchain.name}"

    manifest_url = channel_manifest_url_for(toolchain.channel)
    rust_std = fetch_rust_std_component(manifest_url, target) if network else None

    rows: list[dict[str, Any]] = []
    for rlib in rlibs:
        finding = classify_rlib(rlib, count_symbols=count_symbols)
        rows.append(
            {
                # Shared schema (ARCHIVE_SCHEMA in test_system_archive_harvest.py).
                "name": rlib.name,
                "relative_path": rlib.name,
                "source_path": str(rlib),
                "resolved_from": "",
                "size": finding.size,
                "sha256": finding.sha256,
                "package": finding.crate,
                "package_version": toolchain.release,
                "package_architecture": arch,
                "triplet": target,
                "arch": arch,
                "compiler": toolchain.version_line,
                "compiler_driver": "rustc",
                # Rust-specific, additive.
                "variant": f"{toolchain.channel}-{target}",
                "crate": finding.crate,
                "rlib_hash": finding.rlib_hash,
                "channel": toolchain.channel,
                "toolchain": toolchain.name,
                "rustc_release": toolchain.release,
                "rustc_commit_hash": toolchain.commit_hash,
                "rustc_commit_date": toolchain.commit_date,
                "target_triple": target,
                "ar_members": list(finding.members),
                "object_member": finding.object_member,
                "outcome": finding.outcome,
                "text_bytes": finding.text_bytes,
                "llvmbc_bytes": finding.llvmbc_bytes,
                "defined_text_symbols": finding.defined_text_symbols,
                "licence": "MIT OR Apache-2.0",
                "licence_source": (
                    "rust-lang/rust LICENSE-MIT / LICENSE-APACHE "
                    "(the sysroot crates; third-party dependencies vendored "
                    "into the sysroot, e.g. adler2, carry their own "
                    "permissive licence and are not redistributed here)"
                ),
            }
        )
    rows.sort(key=lambda r: str(r["name"]))

    image = {
        "name": key,
        "base": f"rustup:{toolchain.name}",
        "os_id": "rust-sysroot",
        "os_version_id": toolchain.release,
        "target_os": "linux",
        "target_arch": arch,
        "dpkg_architecture": "",
        "uname_machine": "",
        "harvest_method": "sysroot",
    }
    compiler = {
        "driver": "rustc",
        "path": str(toolchain.root / "bin" / "rustc"),
        "version": toolchain.version_line,
        "package": "rustc",
        "package_version": toolchain.release,
    }
    source_block = {
        "backend": "rust-sysroot",
        "toolchain": toolchain.name,
        "channel": toolchain.channel,
        "sysroot_lib_dir": str(lib_dir),
        "rustc_host": toolchain.host,
        "rustc_commit_hash": toolchain.commit_hash,
        "rustc_commit_date": toolchain.commit_date,
        "llvm_version": toolchain.llvm_version,
        "channel_manifest_url": manifest_url,
        "rust_std_component": rust_std or {},
        "fetched_utc": generated,
        "user_agent": USER_AGENT,
    }
    totals = {
        "archives": len(rows),
        "bytes": sum(int(r["size"]) for r in rows),
        **_outcome_totals(rows),
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": generated,
        "triplet": target,
        "arch": arch,
        "image": image,
        "compiler": compiler,
        "compiler_note": (
            "rustc's own -vV output is direct evidence, not a ladder: the "
            "toolchain that ran is the toolchain that built these rlibs."
        ),
        "variant": f"{toolchain.channel}-{target}",
        "source": source_block,
        "archives": rows,
        "outcomes": [{"name": r["name"], "outcome": r["outcome"]} for r in rows],
        "totals": totals,
    }
    image_root = output / key
    write_json(image_root / target / "manifest.json", manifest)

    index = {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": generated,
        "image": image,
        "source": source_block,
        "triplets": [
            {
                "triplet": target,
                "arch": arch,
                "manifest": f"{target}/manifest.json",
                "archives": rows,
                "totals": totals,
            }
        ],
        "totals": totals,
    }
    write_json(image_root / "index.json", index)
    return index


def harvest(
    *,
    rustup_home: Path,
    output: Path,
    toolchains: Sequence[str] = (),
    target: str | None = None,
    network: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Harvest every selected toolchain's sysroot.

    Args:
        rustup_home: The rustup home directory.
        output: Harvest root, shared with the other harvesters.
        toolchains: Substrings selecting toolchain directory names. Empty
            means every installed toolchain.
        target: Rustc target triple to read. Defaults to each toolchain's own
            host triple (cross-target sysroots are not enumerated).
        network: Attempt a channel-manifest fetch per toolchain.
        dry_run: Resolve toolchains and report counts, write nothing.

    Returns:
        A run summary; per-toolchain failures are recorded in it, not
        raised, matching the network harvester's shape.
    """
    names = discover_toolchains(rustup_home, only=toolchains)
    cells: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for name in names:
        toolchain = load_toolchain(rustup_home, name)
        if toolchain is None:
            failures.append({"key": name, "error": "no rustc -vV output"})
            print(f"{name}: FAILED no rustc -vV output", file=sys.stderr, flush=True)
            continue
        this_target = target or toolchain.host
        lib_dir = sysroot_lib_dir(toolchain, this_target)
        if not lib_dir.is_dir():
            failures.append({"key": name, "error": f"no sysroot lib dir at {lib_dir}"})
            print(f"{name}: FAILED no {lib_dir}", file=sys.stderr, flush=True)
            continue
        if dry_run:
            count = len(find_rlibs(lib_dir))
            cells.append(
                {
                    "key": name,
                    "channel": toolchain.channel,
                    "target": this_target,
                    "rlibs": count,
                }
            )
            print(f"{name}: {count} rlibs (dry run)", flush=True)
            continue
        index = harvest_toolchain(
            toolchain, target=this_target, output=output, network=network
        )
        totals = index["totals"]
        cells.append(
            {
                "key": name,
                "channel": toolchain.channel,
                "target": this_target,
                "rustc_release": toolchain.release,
                "rustc_commit_hash": toolchain.commit_hash,
                "totals": totals,
            }
        )
        print(
            f"{name}: {totals['archives']} rlibs, {totals['bytes']} bytes, "
            f"{totals['outcome_metadata_only']} metadata-only",
            flush=True,
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "rustup_home": str(rustup_home),
        "cells": cells,
        "failures": failures,
        "totals": {
            "toolchains": len(cells),
            "rlibs": sum(
                int(c.get("totals", {}).get("archives", c.get("rlibs", 0)))
                for c in cells
            ),
            "failures": len(failures),
        },
    }


# ---------------------------------------------------------------------------
# Build: FLIRT-style libraries from the harvested rlibs.
# ---------------------------------------------------------------------------


def _load_rust_images(
    harvest_root: Path, *, images: Sequence[str] = ()
) -> list[dict[str, Any]]:
    """Read every ``rust-*`` per-image ``index.json`` under a harvest root."""
    found: list[dict[str, Any]] = []
    for child in sorted(harvest_root.iterdir()):
        if not child.is_dir() or not child.name.startswith("rust-"):
            continue
        if images and not any(token in child.name for token in images):
            continue
        index_path = child / "index.json"
        if not index_path.is_file():
            continue
        data = json.loads(index_path.read_text())
        if data.get("schema_version") != SCHEMA_VERSION:
            continue
        found.append(data)
    return found


def build_one(
    archive: Path,
    *,
    library_name: str,
    version: str,
    variant: str,
    arch: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Build one crate's signature library in-process.

    Calls :func:`glaurung.tools.build_flirt_library.build_library_from_archive`
    directly rather than shelling out, since this backend builds from
    in-memory-known rlib paths rather than a subprocess-per-archive matrix.

    Returns:
        ``(report row, library dict or None)``. A build failure is recorded
        in the row and returns ``None`` for the library -- one bad rlib does
        not take the rest of the set down.
    """
    from glaurung.tools.build_flirt_library import build_library_from_archive

    start = time.monotonic()
    try:
        lib = build_library_from_archive(
            archive,
            library_name=library_name,
            version=version,
            variant=variant,
            arch=arch,
        )
    except Exception as exc:  # noqa: BLE001 - one bad rlib must not abort the set.
        elapsed = time.monotonic() - start
        return (
            {
                "error": f"{type(exc).__name__}: {exc}",
                "build_seconds": round(elapsed, 3),
                "raw_signatures": 0,
                "unique_signatures": 0,
                "dropped_ambiguous": 0,
                "signatures_with_masked_bytes": 0,
                "signatures_with_crc": 0,
                "signatures_with_refs": 0,
                "output_bytes": 0,
            },
            None,
        )
    elapsed = time.monotonic() - start
    stats = lib["stats"]
    row = {
        "build_seconds": round(elapsed, 3),
        "raw_signatures": int(stats["raw_signatures"]),
        "unique_signatures": int(stats["unique_signatures"]),
        "dropped_ambiguous": int(stats["dropped_ambiguous"]),
        "signatures_with_masked_bytes": int(stats["signatures_with_masked_bytes"]),
        "signatures_with_crc": int(stats["signatures_with_crc"]),
        "signatures_with_refs": int(stats["signatures_with_refs"]),
        "output_bytes": 0,
    }
    return row, lib


def build_set(
    harvest_root: Path,
    sigs_output: Path,
    *,
    toolchain_images: Sequence[str] = (),
    crates: Sequence[str] = DEFAULT_CRATES,
    merge: bool = True,
) -> dict[str, Any]:
    """Build a library for every matching ``(toolchain, crate)`` pair.

    Physical layout, matching Decision 7's key literally:
    ``<sigs_output>/rust-std/<rustc version>/<channel>-<target>/<arch>/<crate>.flirt.json``.
    The flat ``<sigs_output>/index.json`` this shares with
    ``tools/build_signature_set.py`` gets one row per crate keyed
    ``rust-std/<rustc version>/<channel>-<target>/<arch>/<crate>`` -- the same
    string as the output path, so the key and the file agree by construction.

    Args:
        harvest_root: Where :func:`harvest` wrote its per-toolchain trees.
        sigs_output: Where the ``.flirt.json`` files and shared ``index.json``
            live -- typically the same ``sigs/`` directory
            ``tools/build_signature_set.py`` writes into.
        toolchain_images: Substrings selecting which ``rust-*`` harvest images
            to build. Empty means every one this root has.
        crates: Crate names to build. Defaults to Decision 7's priority list;
            a crate not present in a given toolchain's harvest is skipped,
            not an error, since the sysroot's own crate set differs by
            toolchain (e.g. ``profiler_builtins`` is present on some,
            ``getopts``/``test`` are dev-only and never in ``DEFAULT_CRATES``).
        merge: Keep existing index rows this run does not touch. Without it a
            scoped run's index describes only what it built, exactly the
            failure mode ``build_signature_set.build_set`` documents.

    Returns:
        The summary also written to ``<sigs_output>/index.json``.
    """
    images = _load_rust_images(harvest_root, images=toolchain_images)
    sigs_output.mkdir(parents=True, exist_ok=True)

    carried: list[dict[str, Any]] = []
    index_path = sigs_output / "index.json"
    if merge and index_path.is_file():
        previous = json.loads(index_path.read_text())
        carried = list(previous.get("libraries", []))

    crate_set = set(crates)
    libraries: list[dict[str, Any]] = []
    zero_reasons: list[dict[str, Any]] = []
    for image in images:
        image_dict = image["image"]
        for triplet in image.get("triplets", []):
            for archive_row in triplet.get("archives", []):
                crate = str(archive_row["crate"])
                if crate not in crate_set:
                    continue
                rustc_release = str(archive_row["rustc_release"])
                channel = str(archive_row["channel"])
                target = str(archive_row["target_triple"])
                arch = str(archive_row["arch"])
                variant = f"{channel}-{target}"
                key = f"rust-std/{rustc_release}/{variant}/{arch}/{crate}"
                out_rel = (
                    f"rust-std/{rustc_release}/{variant}/{arch}/{crate}.flirt.json"
                )
                out_path = sigs_output / out_rel
                archive_path = Path(str(archive_row["source_path"]))

                if archive_row.get("outcome") != OUTCOME_ARCHIVE:
                    row = {
                        "returncode": 0,
                        "error": f"harvest outcome {archive_row.get('outcome')!r}, no object member",
                        "build_seconds": 0.0,
                        "raw_signatures": 0,
                        "unique_signatures": 0,
                        "dropped_ambiguous": 0,
                        "signatures_with_masked_bytes": 0,
                        "signatures_with_crc": 0,
                        "signatures_with_refs": 0,
                        "output_bytes": 0,
                    }
                else:
                    row, lib = build_one(
                        archive_path,
                        library_name=crate,
                        version=rustc_release,
                        variant=variant,
                        arch=arch,
                    )
                    row["returncode"] = 0 if "error" not in row else 1
                    if lib is not None:
                        write_json(out_path, lib)
                        row["output_bytes"] = out_path.stat().st_size

                row.update(
                    {
                        "key": key,
                        "image": image_dict["name"],
                        "triplet": target,
                        "arch": arch,
                        "archive": archive_row["name"],
                        "archive_bytes": archive_row["size"],
                        "archive_sha256": archive_row["sha256"],
                        "library_name": crate,
                        "library_version": rustc_release,
                        "variant": variant,
                        "output": out_rel,
                    }
                )
                libraries.append(row)
                if int(row["unique_signatures"]) == 0:
                    zero_reasons.append(
                        {
                            "key": key,
                            "outcome": archive_row.get("outcome"),
                            "defined_text_symbols": archive_row.get(
                                "defined_text_symbols"
                            ),
                            "error": row.get("error", ""),
                        }
                    )
                print(
                    f"{key}: unique={row['unique_signatures']} "
                    f"raw={row['raw_signatures']} "
                    f"ambiguous={row['dropped_ambiguous']} "
                    f"{row['build_seconds']}s",
                    flush=True,
                )

    built_keys = {str(r["key"]) for r in libraries}
    kept = [r for r in carried if str(r.get("key")) not in built_keys]
    libraries.extend(kept)
    libraries.sort(key=lambda r: str(r["key"]))
    summary = {
        "schema_version": "1",
        "libraries": libraries,
        "zero_signature_rlibs": sorted(zero_reasons, key=lambda r: str(r["key"])),
        "totals": {
            "built_this_run": len(built_keys),
            "carried_from_previous_index": len(kept),
            "libraries": len(libraries),
            "with_signatures": sum(1 for r in libraries if r["unique_signatures"]),
            "raw_signatures": sum(int(r["raw_signatures"]) for r in libraries),
            "unique_signatures": sum(int(r["unique_signatures"]) for r in libraries),
            "dropped_ambiguous": sum(int(r["dropped_ambiguous"]) for r in libraries),
            "build_seconds": round(
                sum(float(r["build_seconds"]) for r in libraries), 3
            ),
            "output_bytes": sum(int(r["output_bytes"]) for r in libraries),
            "failures": sum(1 for r in libraries if r.get("returncode")),
        },
    }
    write_json(index_path, summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point with ``harvest`` and ``build`` subcommands."""
    parser = argparse.ArgumentParser(
        prog="harvest_rust_sysroot.py",
        description=(
            "Harvest Rust standard-library .rlib archives from installed "
            "rustup toolchains and build FLIRT-style signature libraries."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    harvest_p = sub.add_parser("harvest", help="Enumerate rlibs per toolchain.")
    harvest_p.add_argument("--output", type=Path, required=True)
    harvest_p.add_argument("--rustup-home", type=Path, default=None)
    harvest_p.add_argument(
        "--toolchain",
        action="append",
        default=[],
        dest="toolchains",
        help="Substring selecting toolchain directory names; repeatable.",
    )
    harvest_p.add_argument(
        "--target", default=None, help="Override the rustc target triple."
    )
    harvest_p.add_argument(
        "--network",
        action="store_true",
        help="Fetch the channel-rust-*.toml manifest for a re-fetch pointer.",
    )
    harvest_p.add_argument("--dry-run", action="store_true")

    build_p = sub.add_parser("build", help="Build signature libraries from a harvest.")
    build_p.add_argument("--harvest-root", type=Path, required=True)
    build_p.add_argument("--sigs-output", type=Path, required=True)
    build_p.add_argument(
        "--toolchain-image",
        action="append",
        default=[],
        dest="toolchain_images",
        help="Substring selecting rust-* harvest images; repeatable.",
    )
    build_p.add_argument(
        "--crate",
        action="append",
        default=[],
        dest="crates",
        help="Crate name to build; repeatable. Default: the priority list.",
    )
    build_p.add_argument("--no-merge", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "harvest":
        rustup_home = (args.rustup_home or default_rustup_home()).expanduser()
        summary = harvest(
            rustup_home=rustup_home,
            output=args.output.expanduser(),
            toolchains=tuple(args.toolchains),
            target=args.target,
            network=args.network,
            dry_run=args.dry_run,
        )
        t = summary["totals"]
        print(
            f"\n{t['toolchains']} toolchains, {t['rlibs']} rlibs, "
            f"{t['failures']} failures"
        )
        return 1 if t["failures"] and not summary["cells"] else 0

    summary = build_set(
        args.harvest_root.expanduser(),
        args.sigs_output.expanduser(),
        toolchain_images=tuple(args.toolchain_images),
        crates=tuple(args.crates) or DEFAULT_CRATES,
        merge=not args.no_merge,
    )
    t = summary["totals"]
    print(
        f"\n{t['libraries']} libraries ({t['built_this_run']} built here, "
        f"{t['carried_from_previous_index']} carried), "
        f"{t['with_signatures']} with signatures, "
        f"{t['unique_signatures']} unique signatures, {t['failures']} failures, "
        f"{t['build_seconds']}s, {t['output_bytes']} bytes"
    )
    if summary["zero_signature_rlibs"]:
        print("\nzero-signature rlibs:")
        for row in summary["zero_signature_rlibs"]:
            print(
                f"  {row['key']}: outcome={row['outcome']} "
                f"defined_text_symbols={row['defined_text_symbols']} {row['error']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
