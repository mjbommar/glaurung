#!/usr/bin/env python3
"""Classify every shadow-split script with z3 and keep the corpus honest.

The shadow-split captures under ``tests/corpora/axeyum-qfbv/shadow-splits/``
record queries where exactly one of z3/Axeyum decided.  Until 2026-09-16 that
directory also held 735 scripts the pre-``solver-016`` exporter rendered with
a mis-sized ``concat`` -- z3 itself rejects them (``invalid extract
application`` or a 57-bit sort mismatch) -- and every sweep that counted files
counted those as solver misses.  This tool is the gate that stops that from
happening again:

* every ``*.smt2`` under each capture is run through z3 and classified as
  ``sat`` / ``unsat`` / ``unknown`` / ``timeout`` or **malformed** (z3 prints
  an ``(error ...)`` other than the harmless ``model is not available`` that
  follows ``unsat`` on a script ending in ``(get-model)``);
* ``verdicts.tsv`` at the root is (re)written with one row per valid script:
  ``capture<TAB>sha256<TAB>z3<TAB>axeyum``; the Axeyum column is taken from
  ``--axeyum-results`` (the TSV ``tests/axeyum_shadow_split_verdicts.rs``
  writes when ``GLAURUNG_SHADOW_SPLIT_AXEYUM_OUT`` is set), else preserved from
  the existing file, else ``unmeasured``;
* the exit status depends on the finding: **1** if any malformed script is
  left under the live root, if any valid script has no z3 verdict
  (``unknown``/``timeout``), if a measured Axeyum verdict opposes z3's, or if
  a script whose committed Axeyum column was decided is measured undecided
  (the **regression floor**, solver-034: the pinned solver may not lose a
  script it once decided);
* a script on disk with no committed row is a **new row** -- the capture tier
  (``scripts/shadow-capture.sh``) found a fresh split -- and is reported by
  name on stdout (``NEW: ...``) with z3's and Axeyum's verdicts.  A new row
  Axeyum does not decide is a capability gap, which is a finding, not a
  failure; a committed undecided row Axeyum now decides is reported as
  ``PROMOTED`` and joins the floor.

``--prune-to DIR`` moves each malformed script out of its capture into
``DIR/<capture>/`` (with a ``shadow-splits.tsv`` of just those rows, so
``validate_shadow_splits.py`` still validates the moved set, and a
``malformed.tsv`` carrying z3's error text), rewrites the live capture's
``shadow-splits.tsv``, regenerates ``summary-v1.json`` /
``capture-index-v1.json`` through ``validate_shadow_splits.py``, filters
``manifest-v1.json``, and records the prune in ``capture-v1.json``.  Run it
once; afterwards the default mode is the gate.

``--check`` compares a fresh z3 classification against the committed
``verdicts.tsv`` and writes nothing.
"""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import date
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_shadow_splits  # noqa: E402

VERDICTS = "verdicts.tsv"
MALFORMED_INDEX = "malformed.tsv"
DECIDED = frozenset(("sat", "unsat"))
HARMLESS_GET_MODEL_ERROR = "model is not available"


def z3_version(z3: str) -> str:
    try:
        out = subprocess.run([z3, "--version"], capture_output=True, text=True, check=False)
    except OSError as error:
        raise ValueError(f"cannot run {z3}: {error}") from error
    first = ((out.stdout or out.stderr).strip().splitlines() or ["unknown"])[0]
    return first.replace("\t", " ")


def classify_script(z3: str, timeout: int, path: Path) -> tuple[str, str]:
    """Return ``(class, detail)`` for one script.

    ``class`` is ``sat``/``unsat``/``unknown``/``timeout``/``malformed``;
    ``detail`` is z3's first non-harmless ``(error ...)`` line for a malformed
    script and empty otherwise.
    """
    proc = subprocess.run(
        [z3, f"-T:{timeout}", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = [line for line in (proc.stdout + proc.stderr).splitlines() if line.strip()]
    errors = [
        line
        for line in lines
        if line.startswith("(error") and HARMLESS_GET_MODEL_ERROR not in line
    ]
    if errors:
        return "malformed", errors[0]
    for line in lines:
        if line in ("sat", "unsat", "unknown", "timeout"):
            return line, ""
    return "malformed", "no verdict line: " + " | ".join(lines)[:200]


def captures_under(root: Path) -> list[Path]:
    found = sorted(
        path.parent for path in root.glob("*/shadow-splits.tsv") if path.parent.is_dir()
    )
    if not found:
        raise ValueError(f"no capture directories (with shadow-splits.tsv) under {root}")
    return found


def classify_root(
    root: Path, z3: str, timeout: int, jobs: int
) -> dict[Path, dict[str, tuple[str, str]]]:
    """``{capture: {sha256: (class, detail)}}`` for every script under root."""
    work: list[tuple[Path, Path]] = []
    for capture in captures_under(root):
        scripts = sorted(capture.glob("*.smt2"))
        if not scripts:
            raise ValueError(f"capture {capture.name} holds no *.smt2 scripts")
        work.extend((capture, script) for script in scripts)
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        results = list(
            executor.map(lambda item: classify_script(z3, timeout, item[1]), work)
        )
    classified: dict[Path, dict[str, tuple[str, str]]] = {}
    for (capture, script), result in zip(work, results, strict=True):
        classified.setdefault(capture, {})[script.stem] = result
    return classified


def read_verdicts(path: Path) -> dict[tuple[str, str], tuple[str, str]]:
    """``{(capture, sha256): (z3, axeyum)}`` from an existing verdicts.tsv."""
    rows: dict[tuple[str, str], tuple[str, str]] = {}
    if not path.is_file():
        return rows
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 4:
            raise ValueError(f"{path}:{number}: expected CAPTURE<TAB>SHA256<TAB>Z3<TAB>AXEYUM")
        capture, content_hash, z3_class, axeyum_class = fields
        rows[(capture, content_hash)] = (z3_class, axeyum_class)
    return rows


def read_axeyum_results(path: Path) -> dict[tuple[str, str], str]:
    """``{(capture, sha256): verdict}`` from the Rust replay's output TSV."""
    rows: dict[tuple[str, str], str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 3:
            raise ValueError(f"{path}:{number}: expected CAPTURE<TAB>SHA256<TAB>VERDICT[<TAB>MS]")
        rows[(fields[0], fields[1])] = fields[2]
    return rows


def render_verdicts(
    rows: dict[tuple[str, str], tuple[str, str]], z3_ident: str, timeout: int, axeyum_note: str
) -> str:
    header = [
        "# Shadow-split regression set: every z3-valid script under this directory,",
        "# with the verdict z3 gives it and the verdict the pinned Axeyum gave it.",
        f"# z3: {z3_ident}, -T:{timeout}; classified by tools/axeyum/split_verdicts.py.",
        f"# axeyum: {axeyum_note}",
        "# columns: capture\tsha256\tz3\taxeyum",
    ]
    body = [
        f"{capture}\t{content_hash}\t{z3_class}\t{axeyum_class}"
        for (capture, content_hash), (z3_class, axeyum_class) in sorted(rows.items())
    ]
    return "\n".join(header + body) + "\n"


def prune_capture(
    capture: Path,
    destination_root: Path,
    malformed: dict[str, str],
    today: str,
) -> None:
    """Move ``malformed`` (sha256 -> z3 error) out of ``capture``."""
    destination = destination_root / capture.name
    destination.mkdir(parents=True, exist_ok=False)
    index_path = capture / "shadow-splits.tsv"
    kept: list[str] = []
    moved: list[str] = []
    for line in index_path.read_text(encoding="utf-8").splitlines():
        content_hash = line.split("\t", 1)[0]
        (moved if content_hash in malformed else kept).append(line)
    if len(moved) != len(malformed):
        raise ValueError(
            f"{capture.name}: {len(malformed)} malformed scripts but {len(moved)} index rows"
        )
    for content_hash in sorted(malformed):
        shutil.move(str(capture / f"{content_hash}.smt2"), str(destination / f"{content_hash}.smt2"))
    (destination / "shadow-splits.tsv").write_text(
        "".join(f"{line}\n" for line in moved), encoding="utf-8"
    )
    (destination / MALFORMED_INDEX).write_text(
        "".join(f"{content_hash}\t{malformed[content_hash]}\n" for content_hash in sorted(malformed)),
        encoding="utf-8",
    )
    if not kept:
        raise ValueError(f"{capture.name}: every script is malformed; refusing to empty the capture")
    index_path.write_text("".join(f"{line}\n" for line in kept), encoding="utf-8")

    summary, rows, sizes = validate_shadow_splits.validate_capture(capture, 8)
    (capture / "summary-v1.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    capture_index_path = capture / "capture-index-v1.json"
    capture_meta_path = capture / "capture-v1.json"
    manifest_path = capture / "manifest-v1.json"
    if capture_index_path.is_file():
        previous = json.loads(capture_index_path.read_text(encoding="utf-8"))
        capture_index = validate_shadow_splits.build_capture_index(
            rows, sizes, previous["name"], previous["source"]
        )
        capture_index_path.write_text(json.dumps(capture_index, indent=2) + "\n", encoding="utf-8")
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"] = [
            entry for entry in manifest["files"] if Path(entry["path"]).stem in rows
        ]
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    if capture_meta_path.is_file():
        meta = json.loads(capture_meta_path.read_text(encoding="utf-8"))
        meta["pruned"] = {
            "date": today,
            "malformed_scripts": len(malformed),
            "moved_to": str(destination.relative_to(capture.parent.parent)),
            "reason": "z3 rejects the pre-solver-016 concat export; see solver-032",
            "tool": "tools/axeyum/split_verdicts.py --prune-to",
        }
        capture_meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", type=Path, help="tests/corpora/axeyum-qfbv/shadow-splits")
    parser.add_argument("--z3", default="z3")
    parser.add_argument("--timeout", type=int, default=10, help="z3 -T seconds per script")
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--prune-to", type=Path, help="move malformed scripts under this directory")
    parser.add_argument("--axeyum-results", type=Path, help="TSV from the Rust replay test")
    parser.add_argument("--axeyum-note", default=None, help="provenance line for the axeyum column")
    parser.add_argument("--check", action="store_true", help="compare against verdicts.tsv, write nothing")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.jobs <= 0 or args.timeout <= 0:
        print("split_verdicts.py: ERROR: --jobs and --timeout must be positive", file=sys.stderr)
        return 2
    try:
        z3_ident = z3_version(args.z3)
        classified = classify_root(args.root, args.z3, args.timeout, args.jobs)
    except (OSError, ValueError) as error:
        print(f"split_verdicts.py: ERROR: {error}", file=sys.stderr)
        return 2

    problems: list[str] = []
    today = date.today().isoformat()
    malformed_total = 0
    for capture, scripts in classified.items():
        malformed = {h: detail for h, (cls, detail) in scripts.items() if cls == "malformed"}
        counts = Counter(cls for cls, _ in scripts.values())
        print(f"{capture.name}: {dict(sorted(counts.items()))}")
        if not malformed:
            continue
        malformed_total += len(malformed)
        if args.prune_to is not None and not args.check:
            try:
                prune_capture(capture, args.prune_to, malformed, today)
            except (OSError, ValueError) as error:
                print(f"split_verdicts.py: ERROR: {error}", file=sys.stderr)
                return 2
            print(f"  moved {len(malformed)} malformed scripts to {args.prune_to / capture.name}")
        else:
            first = min(malformed)
            problems.append(
                f"{capture.name}: {len(malformed)} malformed scripts z3 rejects "
                f"(first {first}: {malformed[first]})"
            )

    fresh: dict[tuple[str, str], str] = {}
    for capture, scripts in classified.items():
        for content_hash, (cls, _) in scripts.items():
            if cls != "malformed":
                fresh[(capture.name, content_hash)] = cls
                if cls not in DECIDED:
                    problems.append(f"{capture.name}/{content_hash}: z3 {cls} at -T:{args.timeout}")

    verdicts_path = args.root / VERDICTS
    try:
        existing = read_verdicts(verdicts_path)
        measured = read_axeyum_results(args.axeyum_results) if args.axeyum_results else {}
    except (OSError, ValueError) as error:
        print(f"split_verdicts.py: ERROR: {error}", file=sys.stderr)
        return 2

    if args.check:
        if not existing:
            problems.append(f"--check: {verdicts_path} is missing or empty")
        for key in sorted(set(fresh) | set(existing)):
            z3_now = fresh.get(key)
            committed = existing.get(key)
            if committed is None:
                problems.append(f"{key[0]}/{key[1]}: on disk (z3 {z3_now}) but not in {VERDICTS}")
            elif z3_now is None:
                problems.append(f"{key[0]}/{key[1]}: in {VERDICTS} but not on disk")
            elif committed[0] != z3_now:
                problems.append(f"{key[0]}/{key[1]}: {VERDICTS} says z3 {committed[0]}, z3 now says {z3_now}")
    else:
        rows: dict[tuple[str, str], tuple[str, str]] = {}
        new_rows: list[tuple[str, str]] = []
        promoted: list[tuple[str, str]] = []
        for key, z3_class in sorted(fresh.items()):
            previous = existing.get(key)
            measured_class = measured.get(key)
            axeyum_class = measured_class or (previous[1] if previous else "unmeasured")
            rows[key] = (z3_class, axeyum_class)
            if previous is None:
                new_rows.append(key)
            elif measured_class is not None and previous[1] in DECIDED and measured_class not in DECIDED:
                problems.append(
                    f"{key[0]}/{key[1]}: REGRESSION pinned axeyum {previous[1]} (z3 {z3_class}), "
                    f"now {measured_class}"
                )
            elif measured_class in DECIDED and previous[1] not in DECIDED:
                promoted.append(key)
        note = args.axeyum_note or (
            existing_note(verdicts_path) if not measured else "measured; no --axeyum-note given"
        )
        verdicts_path.write_text(render_verdicts(rows, z3_ident, args.timeout, note), encoding="utf-8")
        print(f"wrote {verdicts_path}: {len(rows)} rows")
        for key in new_rows:
            z3_class, axeyum_class = rows[key]
            print(f"NEW: {key[0]}/{key[1]}\tz3 {z3_class}\taxeyum {axeyum_class}")
        for key in promoted:
            z3_class, axeyum_class = rows[key]
            print(f"PROMOTED: {key[0]}/{key[1]}\tz3 {z3_class}\taxeyum {axeyum_class} (was {existing[key][1]})")
        gaps = sum(1 for key in new_rows if rows[key][1] not in DECIDED)
        print(
            f"new rows: {len(new_rows)} ({gaps} axeyum undecided: capability gaps, not failures); "
            f"promoted into the floor: {len(promoted)}"
        )
        for key, (z3_class, axeyum_class) in rows.items():
            if axeyum_class in DECIDED and z3_class in DECIDED and axeyum_class != z3_class:
                problems.append(f"{key[0]}/{key[1]}: z3 {z3_class} but axeyum {axeyum_class}")

    valid_total = len(fresh)
    print(f"total: {valid_total} valid, {malformed_total} malformed, z3 {z3_ident}")
    if problems:
        for problem in problems:
            print(f"split_verdicts.py: FAIL: {problem}", file=sys.stderr)
        return 1
    return 0


def existing_note(path: Path) -> str:
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("# axeyum: "):
                return line[len("# axeyum: "):]
    return "unmeasured"


if __name__ == "__main__":
    raise SystemExit(main())
