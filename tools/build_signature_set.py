#!/usr/bin/env python3
"""Build one FLIRT-style signature library per harvested system archive.

`samples/docker/harvest_system_archives.py` runs inside a `samples/docker`
image and exports the distribution's own static archives with their `dpkg`
provenance. This script is the other half: it walks that harvest and calls
`python -m glaurung.tools.build_flirt_library --archive` once per archive,
keyed exactly as the format requires -- `(name, version, variant, arch)`,
where the name and version are the owning **package** and its version, and the
variant is the distribution plus the compiler that image ships.

One process per archive, deliberately. A malformed or unsupported archive then
fails alone and is recorded as a zero rather than taking the set down, and the
per-library wall time in the index is a real measurement of the same command a
person would type by hand.

Usage:
    uv run python tools/build_signature_set.py \\
        --harvest-root ~/.cache/glaurung/system-libs \\
        --output ~/.cache/glaurung/system-libs/sigs

Reads `<harvest-root>/index.json` (written by
`harvest_system_archives.py --index-root`) and writes `<output>/index.json`
plus one `<output>/<key>.flirt.json` per archive that yielded signatures.

See `docs/reference/function-signature-libraries.md` for what a signature file
holds, and `docs/reference/sample-corpus.md` for the harvest itself.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Sequence

#: The trailing dotted version in a `gcc --version` first line.
_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+)\s*$")


def compiler_tag(compiler: str, driver: str) -> str:
    """Condense a `--version` first line into a variant fragment.

    Args:
        compiler: The full first line, e.g.
            ``gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0``.
        driver: The driver name, e.g. ``gcc`` or ``x86_64-w64-mingw32-gcc``.

    Returns:
        ``gcc-11.4.0``, or just the driver when no version can be read. The
        variant is part of the library key, not metadata about it, so it has
        to be stable across rebuilds of the same image.
    """
    base = driver.rsplit("-", 1)[-1] if driver != "unknown" else "cc"
    match = _VERSION_RE.search(compiler.strip())
    return f"{base}-{match.group(1)}" if match else base


def variant_for(manifest: dict) -> str:
    """Return the `<distro>-<compiler>` variant tag for one triplet manifest.

    A manifest that states its own `variant` is believed. The network harvester
    (`glaurung.tools.harvest_sources`) does, because it knows things this
    function cannot reconstruct: the release *codename* rather than the numeric
    `VERSION_ID`, and which rung of the compiler-evidence ladder produced the
    version -- its `compiler.version` reads `gcc-12.2.0 (libstdcxx-package-
    version)`, from which the regex below would extract nothing and silently key
    the library `debian-12-gcc`. The variant is part of the identity, so a
    silently degraded one is a wrong key, not a cosmetic loss.

    Only the Docker harvester's manifests, which have no `variant` field, fall
    through to reconstruction from the image and the driver.
    """
    stated = manifest.get("variant")
    if isinstance(stated, str) and stated:
        return stated
    image = manifest.get("image", {})
    distro = f"{image.get('os_id', 'unknown')}-{image.get('os_version_id', 'unknown')}"
    compiler = manifest.get("compiler", {})
    return f"{distro}-{compiler_tag(compiler.get('version', ''), compiler.get('driver', 'unknown'))}"


def build_one(
    archive: Path,
    output: Path,
    *,
    library_name: str,
    library_version: str,
    variant: str,
    arch: str,
) -> dict:
    """Run the library builder over one archive and report what it produced.

    Returns:
        A dict with the command's exit status, wall time, output size and the
        builder's own `stats` block. A failure is recorded, never raised: a
        COFF archive currently yields zero signatures and that is a fact about
        the set, not a reason to abandon it.
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
        arch,
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
    return row


def build_set(
    harvest_root: Path,
    output_dir: Path,
    *,
    images: Sequence[str] = (),
    merge: bool = False,
) -> dict:
    """Build a library for every archive named in the harvest index.

    Args:
        harvest_root: Directory holding per-image harvests and their
            `index.json`.
        output_dir: Where the `.flirt.json` files and their index go.
        images: Substrings selecting which harvest images to build. Empty means
            all of them.
        merge: Keep the existing index's rows for keys this run did not build.
            Without it, a scoped run writes an index describing only what it
            built and the rest of the catalogue vanishes from the record while
            its files sit on disk -- which is worse than either building
            everything or building nothing, because nothing says it happened.

    Returns:
        The summary written to `<output_dir>/index.json`.
    """
    index = json.loads((harvest_root / "index.json").read_text())
    output_dir.mkdir(parents=True, exist_ok=True)

    carried: list[dict] = []
    if merge and (output_dir / "index.json").is_file():
        previous = json.loads((output_dir / "index.json").read_text())
        carried = list(previous.get("libraries", []))

    libraries: list[dict] = []
    for image in index.get("images", []):
        if images and not any(token in image["image"] for token in images):
            continue
        image_dir = harvest_root / image["image"]
        for triplet in image.get("triplets", []):
            manifest = json.loads(
                (image_dir / triplet["triplet"] / "manifest.json").read_text()
            )
            variant = variant_for(manifest)
            for archive in triplet.get("archives", []):
                path = harvest_root / archive["path"]
                stem = archive["name"].removesuffix(".a")
                key = f"{image['image']}.{triplet['triplet']}.{stem}"
                out = output_dir / f"{key}.flirt.json"
                row = build_one(
                    path,
                    out,
                    library_name=archive["package"],
                    library_version=archive["package_version"],
                    variant=variant,
                    arch=triplet["arch"],
                )
                row.update(
                    {
                        "key": key,
                        "image": image["image"],
                        "triplet": triplet["triplet"],
                        "arch": triplet["arch"],
                        "archive": archive["name"],
                        "archive_bytes": archive["size"],
                        "archive_sha256": archive["sha256"],
                        "library_name": archive["package"],
                        "library_version": archive["package_version"],
                        "variant": variant,
                        "output": f"{key}.flirt.json",
                    }
                )
                libraries.append(row)
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
            "failures": sum(1 for r in libraries if r["returncode"] != 0),
        },
    }
    (output_dir / "index.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="build_signature_set.py",
        description="Build a FLIRT library per harvested system archive.",
    )
    p.add_argument(
        "--harvest-root",
        type=Path,
        required=True,
        help="Directory holding per-image harvests and their index.json.",
    )
    p.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Directory for the .flirt.json files and their index.json.",
    )
    p.add_argument(
        "--image",
        action="append",
        default=[],
        dest="images",
        help=(
            "Build only harvest images whose name contains this substring; "
            "repeatable. Pair with --merge, or the index will describe only "
            "what this run built."
        ),
    )
    p.add_argument(
        "--merge",
        action="store_true",
        help=(
            "Carry forward the existing index's rows for keys this run did not "
            "build, instead of replacing the whole index."
        ),
    )
    args = p.parse_args(argv)

    root = args.harvest_root.expanduser()
    if not (root / "index.json").is_file():
        print(f"error: {root / 'index.json'} not found", file=sys.stderr)
        return 2

    summary = build_set(
        root,
        args.output.expanduser(),
        images=tuple(args.images),
        merge=args.merge,
    )
    t = summary["totals"]
    print(
        f"\n{t['libraries']} libraries ({t['built_this_run']} built here, "
        f"{t['carried_from_previous_index']} carried), "
        f"{t['with_signatures']} with signatures, "
        f"{t['unique_signatures']} unique signatures, {t['failures']} failures, "
        f"{t['build_seconds']}s, {t['output_bytes']} bytes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
