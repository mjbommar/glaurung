#!/usr/bin/env python3
"""Build FLIRT-style signature libraries from the ARM GNU Toolchain harvest.

Reads the manifest written by `tools/harvest_armtc.py` (NAS path + sha256 per
archive, no local copies) and drives one
`python -m glaurung.tools.build_flirt_library --archive` per (multilib,
archive) pair for a fixed, meaningful subset of multilibs -- the ones bare-
metal Cortex-M firmware actually links, per
`docs/reference/function-signature-libraries.md` and the validation corpora
on `/nas4/data/binary-analysis/rt-libopencm3/`.

Library keying follows the existing convention, `(name, version, variant,
arch)`:

* ``name``: the component -- ``newlib``, ``libgcc``, ``libstdc++``,
  ``libsupc++``, ``libnosys``.
* ``version``: the component's own version (newlib ``4.3.0``; libgcc,
  libstdc++ and libsupc++ share the compiler's ``13.2.1`` because they are
  built from the GCC tree; libnosys has none upstream, so the toolchain
  release stands in).
* ``variant``: ``arm-gnu-<gcc-version>-<multilib>``, where ``<multilib>`` is
  the manifest's ``multilib_path`` with ``/`` replaced by ``-`` (e.g.
  ``thumb-v7e-m+fp-hard``). No masked scheme crosses a multilib -- the ABI,
  FPU and instruction set all change the code the compiler emits, the same
  reason no masked scheme crosses an optimisation level.
* ``arch``: ``armv7`` for every multilib here (Thumb-2 on an ARMv7-M/ARMv6-M
  core), which is also what `src/flirt/archive.rs::arch_tag` returns for
  ``Architecture::Arm`` -- the "M-profile" split (v6-M vs v7-M vs v7E-M vs
  v8-M) lives in the *variant*, not the arch tag, because `object`'s
  `Architecture` enum does not distinguish ARM profiles.

Usage::

    uv run python tools/build_armtc_signatures.py \\
        --manifest ~/.cache/glaurung/system-libs/armtc-13.2.1/manifest.json \\
        --output ~/.cache/glaurung/system-libs/armtc-13.2.1/sigs
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

#: The multilibs bare-metal Cortex-M firmware actually links (task scope).
#: See docs/reference/function-signature-libraries.md, "Cortex-M (bare metal)".
TARGET_MULTILIBS: tuple[str, ...] = (
    "thumb/v6-m/nofp",
    "thumb/v7-m/nofp",
    "thumb/v7e-m/nofp",
    "thumb/v7e-m+fp/hard",
    "thumb/v7e-m+dp/hard",
    "thumb/v8-m.main/nofp",
)

#: archive basename -> (library name, version-source).
#: version-source is "newlib", "gcc" or "toolchain" -- which field of the
#: manifest's toolchain block supplies the version string.
ARCHIVE_LIBRARY: dict[str, tuple[str, str]] = {
    "libc.a": ("newlib", "newlib"),
    "libc_nano.a": ("newlib-nano", "newlib"),
    "libm.a": ("newlib-libm", "newlib"),
    "libgcc.a": ("libgcc", "gcc"),
    "libstdc++.a": ("libstdc++", "gcc"),
    "libstdc++_nano.a": ("libstdc++-nano", "gcc"),
    "libsupc++.a": ("libsupc++", "gcc"),
    "libnosys.a": ("libnosys", "toolchain"),
}

ARCH_TAG = "armv7"


def variant_for(multilib_path: str, gcc_version: str) -> str:
    """``arm-gnu-<gcc-version>-<multilib>``, multilib slashes turned to dashes."""
    slug = multilib_path.replace("/", "-")
    return f"arm-gnu-{gcc_version}-{slug}"


def build_one(
    archive: Path,
    output: Path,
    *,
    library_name: str,
    library_version: str,
    variant: str,
) -> dict:
    """Run the library builder over one archive; never raises.

    Returns:
        A dict recording the command's outcome, wall time, output size and
        the builder's own ``stats`` block -- or ``returncode != 0`` and an
        ``error`` snippet when the builder itself failed.
    """
    argv = [
        sys.executable,
        "-m",
        "glaurung.tools.build_flirt_library",
        "--archive",
        str(archive),
        "--library-name",
        library_name,
        "--library-version",
        library_version,
        "--variant",
        variant,
        "--arch",
        ARCH_TAG,
        "--output",
        str(output),
    ]
    start = time.monotonic()
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    elapsed = time.monotonic() - start

    row: dict = {
        "returncode": proc.returncode,
        "build_seconds": round(elapsed, 3),
        "raw_signatures": 0,
        "unique_signatures": 0,
        "dropped_ambiguous": 0,
        "signatures_with_masked_bytes": 0,
        "signatures_with_crc": 0,
        "signatures_with_refs": 0,
        "output_bytes": 0,
    }
    if proc.returncode != 0:
        row["error"] = (proc.stderr or proc.stdout).strip()[-400:]
        return row
    if output.is_file():
        row["output_bytes"] = output.stat().st_size
        stats = json.loads(output.read_text()).get("stats", {})
        for key in (
            "raw_signatures",
            "unique_signatures",
            "dropped_ambiguous",
            "signatures_with_masked_bytes",
            "signatures_with_crc",
            "signatures_with_refs",
        ):
            row[key] = int(stats.get(key, 0))
        if row["unique_signatures"] == 0:
            row["zero_reason"] = (
                "archive parsed but yielded no signature clearing "
                "min_fixed_bytes/min_function_len (or is import-only)"
            )
    return row


def build_set(manifest_path: Path, output_dir: Path) -> dict:
    """Build one library per (target multilib, allowlisted archive) pair."""
    manifest = json.loads(manifest_path.read_text())
    toolchain = manifest["toolchain"]
    output_dir.mkdir(parents=True, exist_ok=True)

    by_key: dict[tuple[str, str], dict] = {
        (a["multilib_path"], a["name"]): a for a in manifest["archives"]
    }

    libraries: list[dict] = []
    for multilib in TARGET_MULTILIBS:
        variant = variant_for(multilib, toolchain["gcc_version"])
        for archive_name, (library_name, version_source) in ARCHIVE_LIBRARY.items():
            row = by_key.get((multilib, archive_name))
            if row is None:
                libraries.append(
                    {
                        "key": f"{library_name}.{variant}.{ARCH_TAG}",
                        "multilib": multilib,
                        "archive": archive_name,
                        "returncode": -1,
                        "error": f"no {archive_name} recorded for multilib {multilib}",
                        "unique_signatures": 0,
                        "raw_signatures": 0,
                    }
                )
                continue

            version = {
                "newlib": toolchain["newlib_version"],
                "gcc": toolchain["gcc_version"],
                "toolchain": toolchain["gcc_version"],
            }[version_source]

            key = f"{library_name}.{version}.{variant}.{ARCH_TAG}"
            out = output_dir / f"{key}.flirt.json"
            result = build_one(
                Path(row["source_path"]),
                out,
                library_name=library_name,
                library_version=version,
                variant=variant,
            )
            result.update(
                {
                    "key": key,
                    "multilib": multilib,
                    "archive": archive_name,
                    "archive_sha256": row["sha256"],
                    "archive_bytes": row["size"],
                    "library_name": library_name,
                    "library_version": version,
                    "variant": variant,
                    "arch": ARCH_TAG,
                    "output": f"{key}.flirt.json"
                    if result.get("output_bytes")
                    else None,
                }
            )
            libraries.append(result)
            print(
                f"{key}: raw={result['raw_signatures']} "
                f"unique={result['unique_signatures']} "
                f"ambiguous={result['dropped_ambiguous']} "
                f"masked={result['signatures_with_masked_bytes']} "
                f"{result['build_seconds']}s"
                + (
                    f"  [{result['error']}]" if result.get("returncode", 0) != 0 else ""
                ),
                flush=True,
            )

    summary = {
        "schema_version": "1",
        "toolchain": toolchain,
        "target_multilibs": list(TARGET_MULTILIBS),
        "libraries": libraries,
        "totals": {
            "libraries": len(libraries),
            "with_signatures": sum(1 for r in libraries if r.get("unique_signatures")),
            "zero": sum(1 for r in libraries if not r.get("unique_signatures")),
            "raw_signatures": sum(int(r.get("raw_signatures", 0)) for r in libraries),
            "unique_signatures": sum(
                int(r.get("unique_signatures", 0)) for r in libraries
            ),
            "dropped_ambiguous": sum(
                int(r.get("dropped_ambiguous", 0)) for r in libraries
            ),
            "build_seconds": round(
                sum(float(r.get("build_seconds", 0.0)) for r in libraries), 3
            ),
            "output_bytes": sum(int(r.get("output_bytes", 0)) for r in libraries),
        },
    }
    (output_dir / "index.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="build_armtc_signatures.py",
        description="Build Cortex-M FLIRT libraries from the ARM GNU Toolchain harvest.",
    )
    p.add_argument(
        "--manifest", type=Path, required=True, help="harvest_armtc.py output."
    )
    p.add_argument(
        "--output", type=Path, required=True, help="Directory for .flirt.json files."
    )
    args = p.parse_args(argv)

    manifest = args.manifest.expanduser()
    if not manifest.is_file():
        print(f"error: {manifest} not found", file=sys.stderr)
        return 2

    summary = build_set(manifest, args.output.expanduser())
    t = summary["totals"]
    print(
        f"\n{t['libraries']} libraries, {t['with_signatures']} with signatures, "
        f"{t['zero']} zero, {t['unique_signatures']} unique signatures, "
        f"{t['build_seconds']}s, {t['output_bytes']} bytes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
