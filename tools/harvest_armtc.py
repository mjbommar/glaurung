#!/usr/bin/env python3
"""Inventory the ARM GNU Toolchain's static archives, without copying them.

The ARM GNU Toolchain (`arm-none-eabi-gcc`) ships newlib, newlib-nano, libgcc
and libstdc++ pre-built for ~40 Cortex-M/A/R multilibs under
`arm-none-eabi/lib/{arm,thumb}/<cpu-variant>/<float-variant>/` and
`lib/gcc/arm-none-eabi/<gcc-version>/<multilib>/libgcc.a`. Those `.a` archives
are exactly the *unlinked* input `build_flirt_library.py --archive` needs to
derive relocation-masked signatures -- see
`docs/reference/function-signature-libraries.md`.

Unlike `samples/docker/harvest_system_archives.py`, which runs *inside* a
Docker image and copies archives out of an ephemeral container filesystem,
this script points at a toolchain that already lives on a read-only, durable
NAS mount. There is nothing to copy and copying would violate the "never
write under /nas4" rule, so this harvester records **NAS path + sha256**
instead of a local copy: any later reader can re-open the exact bytes at the
recorded path, or verify a re-fetch of the same toolchain release against the
recorded hash.

Output schema (`schema_version: "1"`), written to `--output`::

    {
      "schema_version": "1",
      "generated_utc": "...",
      "toolchain": {
        "root": "<NAS path>",
        "gcc_version_string": "arm-none-eabi-gcc (Arm GNU Toolchain ...) 13.2.1 ...",
        "gcc_version": "13.2.1",
        "newlib_version": "4.3.0",
        "license_file": "<NAS path>/license.txt",
        "license_sha256": "..."
      },
      "archives": [
        {
          "multilib_path": "thumb/v7e-m+fp/hard",   # relative to the lib root
          "lib_root": "arm-none-eabi/lib",           # or "lib/gcc/arm-none-eabi/13.2.1"
          "name": "libc.a",
          "source_path": "<NAS path>/.../libc.a",
          "size": 12345,
          "sha256": "..."
        },
        ...
      ],
      "totals": {"archives": N, "bytes": N}
    }

Usage::

    uv run python tools/harvest_armtc.py \\
        --toolchain-root /nas4/data/binary-analysis/armtc/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-eabi \\
        --output ~/.cache/glaurung/system-libs/armtc-13.2.1/manifest.json

`GLAURUNG_ARMTC` (Python-side only) can supply `--toolchain-root` instead.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "1"

#: Archive basenames worth a signature library. Import-only / stub archives
#: (libgloss variants under some multilibs) are still recorded here -- the
#: builder reports raw=0 for those rather than this harvester guessing.
ARCHIVE_NAMES: tuple[str, ...] = (
    "libc.a",
    "libc_nano.a",
    "libg.a",
    "libg_nano.a",
    "libm.a",
    "libstdc++.a",
    "libstdc++_nano.a",
    "libstdc++exp.a",
    "libsupc++.a",
    "libsupc++_nano.a",
    "libnosys.a",
    "libgcc.a",
    "libgcc_eh.a",
    "libgcov.a",
    "libcaf_single.a",
    "librdimon.a",
    "librdimon_nano.a",
    "librdimon-v2m.a",
    "librdpmon.a",
    "libgfortran.a",
    "libgloss-linux.a",
)

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(argv: list[str]) -> str:
    try:
        proc = subprocess.run(argv, check=False, capture_output=True, text=True)
    except OSError:
        return ""
    return proc.stdout


def toolchain_identity(root: Path) -> dict[str, str]:
    """Read the toolchain's own version identity from its own `bin/`.

    Args:
        root: The toolchain root, e.g.
            ``arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-eabi``.

    Returns:
        A dict with the raw ``gcc --version`` first line, the parsed
        ``x.y.z`` version, the newlib version read from
        ``_newlib_version.h``, and the license file's path and hash.
    """
    gcc = root / "bin" / "arm-none-eabi-gcc"
    version_out = _run([str(gcc), "--version"]).splitlines()
    gcc_version_string = version_out[0].strip() if version_out else "unknown"
    match = _VERSION_RE.search(gcc_version_string)
    gcc_version = match.group(1) if match else "unknown"

    newlib_version = "unknown"
    newlib_header = root / "arm-none-eabi" / "include" / "_newlib_version.h"
    try:
        text = newlib_header.read_text(encoding="utf-8", errors="replace")
        nl_match = re.search(r'_NEWLIB_VERSION\s+"([^"]+)"', text)
        if nl_match:
            newlib_version = nl_match.group(1)
    except OSError:
        pass

    license_file = root / "license.txt"
    license_sha256 = _sha256(license_file) if license_file.is_file() else "unknown"

    return {
        "root": str(root),
        "gcc_version_string": gcc_version_string,
        "gcc_version": gcc_version,
        "newlib_version": newlib_version,
        "license_file": str(license_file),
        "license_sha256": license_sha256,
    }


def _multilib_path(archive: Path, lib_root: Path) -> str:
    """The archive's directory, relative to its lib root, as a `/`-joined str."""
    return archive.parent.relative_to(lib_root).as_posix()


def discover_archives(root: Path) -> list[tuple[Path, Path]]:
    """Find every allowlisted `.a` under the toolchain's multilib trees.

    Returns:
        ``(archive, lib_root)`` pairs, sorted for determinism. ``lib_root`` is
        either ``arm-none-eabi/lib`` (newlib/libstdc++/libsupc++/libnosys) or
        ``lib/gcc/arm-none-eabi/<gcc-version>`` (libgcc), so `multilib_path`
        is comparable across the two trees.
    """
    out: list[tuple[Path, Path]] = []
    newlib_root = root / "arm-none-eabi" / "lib"
    if newlib_root.is_dir():
        for p in sorted(newlib_root.rglob("*.a")):
            if p.name in ARCHIVE_NAMES:
                out.append((p, newlib_root))

    gcc_lib_dir = root / "lib" / "gcc" / "arm-none-eabi"
    if gcc_lib_dir.is_dir():
        for version_dir in sorted(gcc_lib_dir.iterdir()):
            if not version_dir.is_dir():
                continue
            for p in sorted(version_dir.rglob("*.a")):
                if p.name in ARCHIVE_NAMES:
                    out.append((p, version_dir))
    return out


def harvest(root: Path) -> dict:
    """Build the manifest dict for one toolchain root. Reads only, no copies."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    identity = toolchain_identity(root)

    archives: list[dict] = []
    for archive, lib_root in discover_archives(root):
        archives.append(
            {
                "multilib_path": _multilib_path(archive, lib_root),
                "lib_root": str(lib_root.relative_to(root)),
                "name": archive.name,
                "source_path": str(archive),
                "size": archive.stat().st_size,
                "sha256": _sha256(archive),
            }
        )
    archives.sort(key=lambda r: (r["lib_root"], r["multilib_path"], r["name"]))

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": generated,
        "toolchain": identity,
        "archives": archives,
        "totals": {
            "archives": len(archives),
            "bytes": sum(int(a["size"]) for a in archives),
        },
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="harvest_armtc.py",
        description=(
            "Inventory the ARM GNU Toolchain's newlib/libgcc/libstdc++ static "
            "archives by NAS path and sha256, without copying them."
        ),
    )
    p.add_argument(
        "--toolchain-root",
        type=Path,
        default=Path(os.environ.get("GLAURUNG_ARMTC", ""))
        if os.environ.get("GLAURUNG_ARMTC")
        else None,
        help=(
            "Root of one arm-gnu-toolchain-*-arm-none-eabi extraction. "
            "Defaults to $GLAURUNG_ARMTC."
        ),
    )
    p.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to write manifest.json to.",
    )
    args = p.parse_args(argv)

    if args.toolchain_root is None:
        print(
            "error: --toolchain-root is required (or set GLAURUNG_ARMTC)",
            file=sys.stderr,
        )
        return 2
    root = args.toolchain_root.expanduser()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    manifest = harvest(root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    t = manifest["totals"]
    print(
        f"toolchain {manifest['toolchain']['gcc_version']} "
        f"(newlib {manifest['toolchain']['newlib_version']}): "
        f"{t['archives']} archives, {t['bytes']} bytes -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
