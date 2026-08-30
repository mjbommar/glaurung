#!/usr/bin/env python3
"""Fetch the DecBench full-config dataset into a materialized evaluation tree.

WHY THIS EXISTS. Glaurung is registered with DecBench as `sample_set_only`, so
its published full-corpus rows (49/34,312 and similar) are a sample-only
submission scored against a full denominator. The full corpus is public --
`noelo-lab/decbench-dataset`, BSD-2, ungated -- and ships both the compiled
binaries AND the Joern-extracted source CFGs, which is everything needed to
score GED and byte_match without re-running their pipeline or a JVM.

REPRODUCIBILITY. The dataset revision is PINNED (`--revision`, default below).
HuggingFace `main` moves; a run that resolves `main` at fetch time cannot be
reproduced later and cannot be compared against an earlier run. Every file is
verified against the manifest's own sha256, so a truncated or substituted
download fails loudly rather than silently scoring different bytes.

LAYOUT. Writes the tree `decbench evaluate-tree` expects, which is also what
`decbench dataset materialize` produces:

    <tree>/<opt>/<project>/compiled/<binary>
    <tree>/<opt>/<project>/source_cfgs/<stem>.json

`tools/decbench_redecompile_tree.py` then fills in `decompiled/`, and
`decbench evaluate-tree` writes `evaluated/` plus the scoreboard.

Usage:
    tools/decbench_fetch_full.py <tree>                  # full config, 803 binaries
    tools/decbench_fetch_full.py <tree> --config sample-set
    tools/decbench_fetch_full.py <tree> --jobs 8
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import pathlib
import sys
import urllib.error
import urllib.request

REPO = "noelo-lab/decbench-dataset"
# Pinned. See REPRODUCIBILITY above before changing.
REVISION = "e5eb576d66ee36793b800a4dd45e291e0add4472"
BASE = "https://huggingface.co/datasets/{repo}/resolve/{rev}/{path}"


def url_for(path: str, revision: str) -> str:
    return BASE.format(repo=REPO, rev=revision, path=path)


def fetch(path: str, revision: str, timeout: int = 180) -> bytes:
    request = urllib.request.Request(
        url_for(path, revision), headers={"User-Agent": "glaurung-decbench-fetch"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_to(path: str, dest: pathlib.Path, revision: str, expect: str | None) -> str:
    """Download one file unless it is already present and correct.

    Returns one of ``cached`` / ``fetched`` / ``failed:<reason>``. A wrong hash
    on disk is re-fetched rather than trusted: a partial download from an
    interrupted run is exactly the case this has to survive.
    """
    if dest.exists() and (expect is None or sha256(dest.read_bytes()) == expect):
        return "cached"
    try:
        data = fetch(path, revision)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return f"failed:{type(exc).__name__}"
    if expect is not None and sha256(data) != expect:
        return "failed:sha256-mismatch"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return "fetched"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tree", type=pathlib.Path, help="Destination tree")
    parser.add_argument(
        "--config", default="full", help="Dataset config (default: full)"
    )
    parser.add_argument(
        "--revision", default=REVISION, help="Dataset revision to pin to"
    )
    parser.add_argument("--jobs", type=int, default=6, help="Parallel downloads")
    parser.add_argument(
        "--limit", type=int, default=0, help="Only the first N binaries"
    )
    args = parser.parse_args()

    print(f"dataset  {REPO}@{args.revision[:12]}")
    print(f"config   {args.config}")

    manifest_path = f"configs/{args.config}/manifest.json"
    try:
        manifest = json.loads(fetch(manifest_path, args.revision))
    except Exception as exc:  # noqa: BLE001
        print(f"could not fetch {manifest_path}: {exc}", file=sys.stderr)
        return 2

    entries = manifest["binaries"]
    if args.limit:
        entries = entries[: args.limit]
    print(
        f"manifest {len(entries)} binaries, "
        f"{manifest.get('function_count')} functions, "
        f"{len(manifest.get('projects', {}))} projects"
    )

    args.tree.mkdir(parents=True, exist_ok=True)
    # Record what produced this tree, beside the tree. A scored tree whose
    # provenance is not written down cannot be defended later.
    (args.tree / "decbench_dataset_provenance.json").write_text(
        json.dumps(
            {
                "repo": REPO,
                "revision": args.revision,
                "config": args.config,
                "binary_count": len(entries),
                "function_count": manifest.get("function_count"),
                "manifest_path": manifest_path,
            },
            indent=2,
        )
        + "\n"
    )

    # The function-level manifest `decbench_redecompile_tree.py` consumes. Same
    # shape as the sample-set kit's `sample_set_manifest.json`, so that tool
    # works against a full-corpus tree unchanged.
    (args.tree / "sample_set_manifest.json").write_text(
        json.dumps(
            {
                "functions": [
                    {
                        "opt": entry["opt"],
                        "project": entry["project"],
                        "binary": entry["binary"],
                        "function": function,
                    }
                    for entry in entries
                    for function in entry["functions"]
                ]
            },
            indent=1,
        )
        + "\n"
    )

    work: list[tuple[str, pathlib.Path, str | None]] = []
    for entry in entries:
        stem = pathlib.Path(entry["binary"]).stem or entry["binary"]
        root = args.tree / entry["opt"] / entry["project"]
        work.append(
            (entry["binary_path"], root / "compiled" / entry["binary"], entry["sha256"])
        )
        # 3 of 803 binaries have no published source CFG; GED simply has no
        # ground truth for those and the metric skips them.
        if entry.get("source_cfg_path"):
            work.append(
                (entry["source_cfg_path"], root / "source_cfgs" / f"{stem}.json", None)
            )

    counts: dict[str, int] = {}
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {
            pool.submit(fetch_to, path, dest, args.revision, expect): path
            for path, dest, expect in work
        }
        for future in concurrent.futures.as_completed(futures):
            status = future.result()
            key = status.split(":")[0]
            counts[key] = counts.get(key, 0) + 1
            if status.startswith("failed"):
                print(f"  FAIL {futures[future]}: {status}", file=sys.stderr)
            done += 1
            if done % 200 == 0:
                print(f"  {done}/{len(work)} files", flush=True)

    print(
        f"\n{len(work)} files: "
        + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    )
    return 1 if counts.get("failed") else 0


if __name__ == "__main__":
    raise SystemExit(main())
