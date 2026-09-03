#!/usr/bin/env python3
"""Harvest the system static archives a signature library is built from.

A FLIRT-style signature has to be derived from **unlinked** ``.o`` members,
because only a relocatable object carries the relocation table that says which
bytes the linker is going to rewrite. That makes the distribution's ``-dev``
static archives -- ``/usr/lib/<triplet>/libc.a``,
``/usr/lib/gcc/<triplet>/<ver>/libstdc++.a``, ``/usr/<triplet>/lib/libmingwex.a``
and friends -- the real input to
``python -m glaurung.tools.build_flirt_library --archive``.

This script runs *inside* one of the ``samples/docker`` build images, where the
archives and the ``dpkg`` database that describes them are both present. It
copies each archive out and records, per archive, exactly enough provenance to
key a signature library: the owning package and its version and architecture,
the target triplet, the size and SHA-256 of the bytes it read, and the version
of the compiler driver in the image that targets that triplet.

The output layout is::

    <output>/index.json                     every triplet, every archive
    <output>/<triplet>/manifest.json        one triplet's provenance
    <output>/<triplet>/lib/<name>.a         the archives themselves

Nothing here writes outside ``--output``.

Licence note: the archives are distribution packages under their own licences
and are *not* redistributed by this repository. Only the derived signature
files are, and a FLIRT signature file contains no bytes of the library it
describes beyond the symbol names -- the pattern is masked, the variant bytes
are never compared, and the CRC is a hash. See
``docs/reference/function-signature-libraries.md``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "1"

#: A GNU target triplet as Debian spells one in a directory name.
_TRIPLET_RE = re.compile(
    r"^[a-z0-9_]+-(?:linux-gnu[a-z0-9]*|linux-musl[a-z0-9]*|w64-mingw32)$"
)

#: Archives worth a signature library, by basename.
#:
#: An explicit allowlist rather than "every ``.a`` under ``/usr/lib``": the
#: images also carry LLVM, OpenJDK and Mono archives that no analyst is going
#: to want named, and MinGW ships several hundred *import* libraries
#: (``libkernel32.a`` and siblings) that contain no code at all.
ARCHIVE_NAMES: tuple[str, ...] = (
    # glibc / musl
    "libBrokenLocale.a",
    "libanl.a",
    "libc.a",
    "libc_nonshared.a",
    "libcrypt.a",
    "libdl.a",
    "libg.a",
    "libm.a",
    "libmcheck.a",
    "libmvec.a",
    "libnsl.a",
    "libpthread.a",
    "libresolv.a",
    "librt.a",
    "libutil.a",
    # gcc runtime and language runtimes
    "libasan.a",
    "libatomic.a",
    "libcaf_single.a",
    "libgcc.a",
    "libgcc_eh.a",
    "libgcov.a",
    "libgfortran.a",
    "libitm.a",
    "liblsan.a",
    "libquadmath.a",
    "libssp.a",
    "libssp_nonshared.a",
    "libstdc++.a",
    "libstdc++fs.a",
    "libsupc++.a",
    "libtsan.a",
    "libubsan.a",
    # -dev packages
    "libbz2.a",
    "libcrypto.a",
    "libcurl.a",
    "libffi.a",
    "libgmp.a",
    "libgmpxx.a",
    "liblzma.a",
    "libpcre2-8.a",
    "libpcre2-16.a",
    "libpcre2-32.a",
    "libpcre2-posix.a",
    "libsqlite3.a",
    "libssl.a",
    "libxml2.a",
    "libz.a",
    "libzstd.a",
    # MinGW-w64 CRT
    "libdelayimp.a",
    "libmingw32.a",
    "libmingwex.a",
    "libmoldname.a",
    "libmsvcrt.a",
    "libucrt.a",
    "libucrtbase.a",
    "libwinpthread.a",
)

#: Triplet prefix -> the architecture tag ``build_flirt_library --arch`` takes.
_ARCH_BY_PREFIX: tuple[tuple[str, str], ...] = (
    ("x86_64", "x86_64"),
    ("i686", "i386"),
    ("i586", "i386"),
    ("i486", "i386"),
    ("i386", "i386"),
    ("aarch64", "aarch64"),
    ("arm", "arm"),
    ("riscv64", "riscv64"),
    ("powerpc64le", "ppc64le"),
    ("powerpc64", "ppc64"),
    ("powerpc", "ppc"),
    ("s390x", "s390x"),
    ("mips64el", "mips64el"),
    ("mipsel", "mipsel"),
    ("mips", "mips"),
)

#: Extra compiler drivers to try for a triplet that has no ``<triplet>-gcc``.
_DRIVER_ALIASES: dict[str, tuple[str, ...]] = {
    "i386-linux-gnu": ("i686-linux-gnu-gcc", "gcc"),
    "x86_64-linux-gnux32": ("gcc",),
    "x86_64-linux-musl": ("musl-gcc", "x86_64-linux-musl-gcc", "gcc"),
    "i386-linux-musl": ("musl-gcc", "gcc"),
}


def arch_for_triplet(triplet: str) -> str:
    """Return the ``--arch`` tag for a target triplet.

    Args:
        triplet: A GNU triplet, e.g. ``aarch64-linux-gnu``.

    Returns:
        The architecture tag, or ``"unknown"`` when the prefix is not one we
        name. ``x32`` collapses to ``x86_64`` because the instruction set is
        the same and that is what the disassembler is keyed on.
    """
    head = triplet.split("-", 1)[0]
    for prefix, arch in _ARCH_BY_PREFIX:
        if head == prefix:
            return arch
    return "unknown"


def _run(argv: list[str]) -> str:
    """Run a command and return stdout, or ``""`` if it cannot be run."""
    try:
        proc = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
        )
    except (OSError, ValueError):
        return ""
    return proc.stdout


def search_roots() -> list[Path]:
    """Return the directories that may hold harvestable archives.

    Globs rather than a hardcoded list, so the same script works on the amd64,
    arm64, armhf, i386, riscv64 and MinGW images without knowing which one it
    is on.
    """
    roots: list[Path] = []

    def add(p: Path) -> None:
        if p.is_dir() and p not in roots:
            roots.append(p)

    usr = Path("/usr")
    # Multiarch and multilib directories of the native toolchain.
    for child in sorted((usr / "lib").glob("*")):
        if child.is_dir() and _TRIPLET_RE.match(child.name):
            add(child)
    add(usr / "lib32")
    add(usr / "libx32")
    # gcc's own runtime, native and cross, plus its multilib subdirectories.
    for base in (usr / "lib" / "gcc", usr / "lib" / "gcc-cross"):
        for version_dir in sorted(base.glob("*/*")):
            add(version_dir)
            for sub in ("32", "x32", "64"):
                add(version_dir / sub)
    # Cross sysroots: /usr/<triplet>/lib, which is where the *-cross libc and
    # the whole MinGW-w64 CRT live.
    for child in sorted(usr.glob("*")):
        if child.is_dir() and _TRIPLET_RE.match(child.name):
            add(child / "lib")
    return roots


def triplet_for_path(path: Path) -> str:
    """Derive the target triplet an archive belongs to from its path.

    Args:
        path: Absolute path of an archive inside the image.

    Returns:
        The triplet, e.g. ``x86_64-linux-gnu`` or ``x86_64-w64-mingw32``.
        Multilib subdirectories are resolved to the triplet of the ABI they
        actually hold, so ``/usr/lib/gcc/x86_64-linux-gnu/11/32/libstdc++.a``
        is ``i386-linux-gnu`` and not a 32-bit file filed under ``x86_64``.
    """
    parts = path.parts
    base_triplet = ""
    for part in parts:
        if _TRIPLET_RE.match(part):
            base_triplet = part
            break

    parent = path.parent.name
    if parent == "lib32" or (parent == "32" and base_triplet.startswith("x86_64-")):
        return "i386-linux-gnu"
    if parent == "libx32" or (parent == "x32" and base_triplet.startswith("x86_64-")):
        return "x86_64-linux-gnux32"
    if parent in ("32", "x32", "64") and base_triplet:
        return f"{base_triplet}+{parent}"
    if base_triplet:
        return base_triplet
    # Nothing in the path names a triplet: fall back to the host's own.
    return _host_triplet()


def _host_triplet() -> str:
    out = _run(["dpkg-architecture", "-qDEB_HOST_MULTIARCH"]).strip()
    if out:
        return out
    out = _run(["gcc", "-print-multiarch"]).strip()
    return out or "unknown"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def dpkg_owners(paths: list[Path]) -> dict[str, str]:
    """Map archive path -> owning package name via one ``dpkg -S``.

    A path ``dpkg`` does not know about is simply absent from the result; the
    caller records ``"unknown"`` rather than guessing.
    """
    if not paths:
        return {}
    out = _run(["dpkg", "-S", *[str(p) for p in paths]])
    owners: dict[str, str] = {}
    for line in out.splitlines():
        pkg, _, filename = line.partition(": ")
        if not filename:
            continue
        # "libc6-dev:amd64: /usr/lib/.../libc.a" -> package "libc6-dev".
        pkg = pkg.split(":", 1)[0].strip()
        # A diverted or multi-owned path lists several packages; take the first
        # deterministically rather than the last one seen.
        owners.setdefault(filename.strip(), pkg)
    return owners


def dpkg_versions(packages: list[str]) -> dict[str, tuple[str, str]]:
    """Map package name -> (version, architecture) via one ``dpkg-query``."""
    real = sorted({p for p in packages if p and p != "unknown"})
    if not real:
        return {}
    out = _run(
        [
            "dpkg-query",
            "-W",
            "-f=${Package}\\t${Version}\\t${Architecture}\\n",
            *real,
        ]
    )
    versions: dict[str, tuple[str, str]] = {}
    for line in out.splitlines():
        fields = line.split("\t")
        if len(fields) >= 3:
            versions[fields[0]] = (fields[1], fields[2])
    return versions


def compiler_for_triplet(triplet: str) -> dict[str, str]:
    """Describe the image's compiler driver that targets ``triplet``.

    This is the toolchain that *would* build for the target, and for archives
    owned by a ``gcc-*`` or ``libstdc++-*`` package it is also the toolchain
    that did. For a distribution ``-dev`` archive such as ``libssl.a`` the
    builder is whatever the Ubuntu buildd used; ``dpkg`` records the package
    version but not the compiler, so the manifest reports this driver and the
    package version side by side and does not conflate them.
    """
    base = triplet.split("+", 1)[0]
    candidates = [f"{base}-gcc", *_DRIVER_ALIASES.get(base, ()), "gcc"]
    for driver in candidates:
        found = shutil.which(driver)
        if not found:
            continue
        version = _run([driver, "--version"]).splitlines()
        owner = dpkg_owners([Path(os.path.realpath(found))])
        pkg = next(iter(owner.values()), "unknown")
        pkg_version = dpkg_versions([pkg]).get(pkg, ("unknown", "unknown"))[0]
        return {
            "driver": driver,
            "path": found,
            "version": version[0].strip() if version else "unknown",
            "package": pkg,
            "package_version": pkg_version,
        }
    return {
        "driver": "unknown",
        "path": "",
        "version": "unknown",
        "package": "unknown",
        "package_version": "unknown",
    }


def _os_release() -> dict[str, str]:
    fields: dict[str, str] = {}
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return fields
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key:
            fields[key.strip()] = value.strip().strip('"')
    return fields


def discover_archives() -> list[Path]:
    """Return every allowlisted archive present in the image, deduplicated.

    Deterministic: roots are visited in a fixed order and each root's contents
    are sorted, so two harvests of the same image list the same paths in the
    same order.
    """
    seen: set[str] = set()
    found: list[Path] = []
    for root in search_roots():
        for name in ARCHIVE_NAMES:
            candidate = root / name
            if not candidate.is_file():
                continue
            real = os.path.realpath(candidate)
            key = f"{triplet_for_path(candidate)}\t{name}\t{real}"
            if key in seen:
                continue
            seen.add(key)
            found.append(candidate)
    return found


def harvest(
    output: Path,
    *,
    image_base: str,
    image_name: str,
    target_os: str,
    target_arch: str,
) -> dict:
    """Copy every allowlisted archive out and write the manifests.

    Args:
        output: Root of the harvest tree. Created if absent.
        image_base: The Dockerfile's ``FROM`` image, e.g. ``ubuntu:22.04``.
        image_name: A short key for this image, e.g. ``linux-amd64``.
        target_os: ``linux``, ``windows`` or ``darwin`` -- what the image's
            sample builds target, recorded for provenance only.
        target_arch: The image's own architecture tag, e.g. ``amd64``.

    Returns:
        The index dict that was written to ``<output>/index.json``.
    """
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    os_release = _os_release()
    image = {
        "name": image_name,
        "base": image_base,
        "os_id": os_release.get("ID", "unknown"),
        "os_version_id": os_release.get("VERSION_ID", "unknown"),
        "target_os": target_os,
        "target_arch": target_arch,
        "dpkg_architecture": _run(["dpkg", "--print-architecture"]).strip()
        or "unknown",
        "uname_machine": platform.machine(),
    }

    archives = discover_archives()
    owners = dpkg_owners(archives)
    versions = dpkg_versions(list(owners.values()))

    by_triplet: dict[str, list[dict]] = {}
    skipped_duplicates = 0
    for src in archives:
        triplet = triplet_for_path(src)
        rows = by_triplet.setdefault(triplet, [])
        if any(r["name"] == src.name for r in rows):
            skipped_duplicates += 1
            continue
        pkg = owners.get(str(src), "unknown")
        pkg_version, pkg_arch = versions.get(pkg, ("unknown", "unknown"))
        dest_dir = output / triplet / "lib"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name
        shutil.copyfile(src, dest)
        rows.append(
            {
                "name": src.name,
                "relative_path": f"lib/{src.name}",
                "source_path": str(src),
                "size": dest.stat().st_size,
                "sha256": _sha256(dest),
                "package": pkg,
                "package_version": pkg_version,
                "package_architecture": pkg_arch,
                "triplet": triplet,
                "arch": arch_for_triplet(triplet),
            }
        )

    index_triplets: list[dict] = []
    for triplet in sorted(by_triplet):
        rows = sorted(by_triplet[triplet], key=lambda r: r["name"])
        compiler = compiler_for_triplet(triplet)
        for row in rows:
            row["compiler"] = compiler["version"]
            row["compiler_driver"] = compiler["driver"]
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "generated_utc": generated,
            "triplet": triplet,
            "arch": arch_for_triplet(triplet),
            "image": image,
            "compiler": compiler,
            "compiler_note": (
                "`compiler` is the image's driver targeting this triplet. It is "
                "the builder for gcc-owned archives; for a distribution -dev "
                "archive dpkg records the package version but not the compiler, "
                "so the two are reported side by side and never conflated."
            ),
            "archives": rows,
            "totals": {
                "archives": len(rows),
                "bytes": sum(int(r["size"]) for r in rows),
            },
        }
        write_json(output / triplet / "manifest.json", manifest)
        index_triplets.append(
            {
                "triplet": triplet,
                "arch": arch_for_triplet(triplet),
                "manifest": f"{triplet}/manifest.json",
                "archives": rows,
                "totals": manifest["totals"],
            }
        )

    index = {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": generated,
        "image": image,
        "triplets": index_triplets,
        "totals": {
            "triplets": len(index_triplets),
            "archives": sum(int(t["totals"]["archives"]) for t in index_triplets),
            "bytes": sum(int(t["totals"]["bytes"]) for t in index_triplets),
            "skipped_duplicates": skipped_duplicates,
        },
    }
    write_json(output / "index.json", index)
    return index


def write_json(path: Path, payload: dict) -> None:
    """Write ``payload`` deterministically: sorted keys, trailing newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def build_index(root: Path) -> dict:
    """Build a top-level index over a directory of per-image harvests.

    Args:
        root: A directory whose children are image harvest trees, each with
            its own ``index.json``.

    Returns:
        The aggregate index, also written to ``<root>/index.json``.
    """
    images: list[dict] = []
    for child in sorted(root.iterdir()):
        per_image = child / "index.json"
        if not per_image.is_file():
            continue
        data = json.loads(per_image.read_text())
        images.append(
            {
                "image": child.name,
                "index": f"{child.name}/index.json",
                "generated_utc": data.get("generated_utc", "unknown"),
                "base": data.get("image", {}).get("base", "unknown"),
                "triplets": [
                    {
                        "triplet": t["triplet"],
                        "arch": t["arch"],
                        "archives": [
                            {
                                "name": a["name"],
                                "path": f"{child.name}/{t['triplet']}/{a['relative_path']}",
                                "size": a["size"],
                                "sha256": a["sha256"],
                                "package": a["package"],
                                "package_version": a["package_version"],
                            }
                            for a in t["archives"]
                        ],
                        "totals": t["totals"],
                    }
                    for t in data.get("triplets", [])
                ],
                "totals": data.get("totals", {}),
            }
        )
    index = {
        "schema_version": SCHEMA_VERSION,
        "images": images,
        "totals": {
            "images": len(images),
            "archives": sum(int(i["totals"].get("archives", 0)) for i in images),
            "bytes": sum(int(i["totals"].get("bytes", 0)) for i in images),
        },
    }
    write_json(root / "index.json", index)
    return index


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="harvest_system_archives.py",
        description=(
            "Harvest the system static archives a signature library is built "
            "from, with dpkg package provenance. Runs inside a samples/docker "
            "build image."
        ),
    )
    p.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Harvest root. Archives land under <output>/<triplet>/lib/.",
    )
    p.add_argument("--image-base", default="unknown", help="The Dockerfile FROM image.")
    p.add_argument(
        "--image-name", default="unknown", help="Short image key, e.g. linux-amd64."
    )
    p.add_argument("--target-os", default="linux", help="linux, windows or darwin.")
    p.add_argument("--target-arch", default="unknown", help="Image architecture tag.")
    p.add_argument(
        "--index-root",
        type=Path,
        default=None,
        help=(
            "Instead of harvesting, write a top-level index.json over a "
            "directory of per-image harvest trees."
        ),
    )
    args = p.parse_args(argv)

    if args.index_root is not None:
        if not args.index_root.is_dir():
            print(f"error: {args.index_root} is not a directory", file=sys.stderr)
            return 2
        index = build_index(args.index_root)
        t = index["totals"]
        print(
            f"indexed {t['images']} image(s), {t['archives']} archives, "
            f"{t['bytes']} bytes -> {args.index_root / 'index.json'}"
        )
        return 0

    index = harvest(
        args.output,
        image_base=args.image_base,
        image_name=args.image_name,
        target_os=args.target_os,
        target_arch=args.target_arch,
    )
    t = index["totals"]
    print(
        f"harvested {t['archives']} archives across {t['triplets']} triplet(s), "
        f"{t['bytes']} bytes -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
