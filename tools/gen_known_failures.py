#!/usr/bin/env python3
"""Measure every decompiler failure the fixture corpus can demonstrate.

Writes `tests/open_defects/known_failures.json`, which
`python/tests/test_known_decompiler_failures.py` turns into one strict xfail
per failure. Regenerate deliberately -- the file is evidence, and the tests
that read it go red when a failure is FIXED, which is the point.

Two axes, both against ground truth rather than against a previous run:

* **types** -- the recovered prototype versus the DWARF the compiler emitted.
  DWARF states the source signature exactly, so any disagreement is a real
  recovery gap rather than a stylistic one.
Each row records the function's VA as well as its name: Rust emits many
functions called `{closure#0}`, so a name alone is not a unique key and a
name-keyed lookup silently resolves to the wrong closure.

* **structure** -- a `goto` in the recovered C for a function whose SOURCE
  contains no `goto` anywhere. The execution differential cannot see this: the
  code behaves identically, it simply is not the control flow the programmer
  wrote.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D

BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"
SRC = ROOT / "tests" / "decompiler_fixtures" / "src"
OUT = ROOT / "tests" / "open_defects" / "known_failures.json"

AXES = ("types", "structure", "returns", "pointers", "unrecovered", "no_body")

#: C type text -> width in bytes. `long` is 8 on every target this corpus
#: builds for; the i386 lane is covered by `arch_baseline.json`, not here.
WIDTHS = {
    "char": 1,
    "short": 2,
    "int": 4,
    "long": 8,
    "long long": 8,
    "float": 4,
    "double": 8,
    "long double": 16,
    "void": 0,
    "_Bool": 1,
    "bool": 1,
}


def classify(text: str) -> dict:
    t = " ".join(text.replace("*", " * ").split())
    is_ptr = "*" in t
    base = t.replace("*", "").replace("const", "").strip()
    signed = not base.startswith("unsigned")
    b = base.replace("unsigned ", "").replace("signed ", "").strip()
    return {
        "w": 8 if is_ptr else WIDTHS.get(b),
        "s": signed,
        "ptr": is_ptr,
        "f": base in ("float", "double", "long double"),
        "raw": base,
    }


def dwarf_classify(p: dict) -> dict:
    if p.get("k") == "ptr":
        return {"w": 8, "s": True, "ptr": True, "f": False, "raw": "ptr"}
    return {
        "w": p.get("w"),
        "s": p.get("s", True),
        "ptr": False,
        "f": p.get("k") == "float",
        "raw": p.get("k", ""),
    }


def recovered_signature(rendered: str | None) -> str | None:
    """Extract a signature from an already recovered body.

    The inventory loop used to call ``D.decompiled_c`` a second time here,
    doubling the most expensive operation in the generator.  Signature text
    is part of the body we already need for every other axis.
    """
    if not rendered:
        return None
    for line in rendered.splitlines():
        if line.startswith("//") or not line.strip():
            continue
        if "(" in line:
            return line.split("{")[0].strip()
    return None


def split_params(sig: str) -> list[str] | None:
    m = re.search(r"\((.*)\)\s*$", sig)
    if not m:
        return None
    inner = m.group(1).strip()
    if inner in ("", "void"):
        return []
    out, depth, cur = [], 0, ""
    for ch in inner:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return [x.strip() for x in out]


def strip_name(decl: str) -> str:
    """Remove a trailing parameter identifier without consuming pointer stars.

    Both ``char *arg0`` and ``char * arg0`` are ordinary C spellings. Splitting
    on whitespace treats ``*arg0`` as one token and turns the first form into
    scalar ``char``, fabricating a pointer-loss defect for every declaration
    rendered with conventional star spacing.
    """
    stripped = re.sub(r"[A-Za-z_]\w*\s*$", "", decl).rstrip()
    return stripped or decl


def sources_without_goto() -> set[str]:
    out = set()
    for f in SRC.iterdir():
        if not f.is_file():
            continue
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        if not re.search(r"\bgoto\b", text):
            out.add(f.name.rsplit(".", 1)[0])
    return out


def language_for_object(name: str) -> str:
    """Return the source-language reporting axis for a fixture object."""
    return "rust" if "-rustc-" in name else "c"


def _content_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def binary_content_identities(paths: list[Path]) -> dict[str, str]:
    """Map object names to identities derived from their real file bytes."""
    return {path.name: _content_digest(path) for path in paths}


def provenance_identity_for_object(name: str) -> str:
    """Return the source-build identity shared by O2 and stripped evidence."""
    return re.sub(r"-O2strip\.dwarf(?=\.so$)", "-O2", name)


def inventory_summaries(
    rows_by_axis: dict[str, list[dict]],
) -> tuple[dict[str, dict[str, int]], dict[str, int], dict[str, dict[str, int]]]:
    """Compute language-split and provenance-deduplicated inventory counts.

    O2 and O2strip are observations of one source-build lane. If their measured
    row facts diverge they remain distinct; matching facts count once even when
    stripped debug sections make the complete object bytes differ. Byte
    identity is measured separately by ``binary_content_identities``.
    """
    by_language = {
        language: {**{axis: 0 for axis in AXES}, "goto_statements": 0}
        for language in ("c", "rust")
    }
    deduplicated = {**{axis: 0 for axis in AXES}, "goto_statements": 0}
    deduplicated_by_language = {
        language: {**{axis: 0 for axis in AXES}, "goto_statements": 0}
        for language in ("c", "rust")
    }

    for axis in AXES:
        seen: set[tuple[str, str]] = set()
        for row in rows_by_axis.get(axis, []):
            language = language_for_object(str(row["obj"]))
            by_language[language][axis] += 1
            if axis == "structure":
                by_language[language]["goto_statements"] += int(row["gotos"])

            row_facts = json.dumps(
                {key: value for key, value in row.items() if key != "obj"},
                sort_keys=True,
                separators=(",", ":"),
            )
            identity = (provenance_identity_for_object(str(row["obj"])), row_facts)
            if identity in seen:
                continue
            seen.add(identity)
            deduplicated[axis] += 1
            deduplicated_by_language[language][axis] += 1
            if axis == "structure":
                gotos = int(row["gotos"])
                deduplicated["goto_statements"] += gotos
                deduplicated_by_language[language]["goto_statements"] += gotos

    return by_language, deduplicated, deduplicated_by_language


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Measure decompiler failures against the fixture corpus."
    )
    parser.add_argument(
        "--language",
        choices=("all", "c", "rust"),
        default="all",
        help="limit the source-language axis (default: all)",
    )
    parser.add_argument(
        "--fixture",
        action="append",
        default=[],
        metavar="GLOB",
        help="limit object basenames by shell-style glob; repeatable",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=min(8, os.cpu_count() or 1),
        help="number of binaries measured concurrently (default: up to 8)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUT,
        help=f"output JSON path (default: {OUT.relative_to(ROOT)})",
    )
    parser.add_argument(
        "--checkpoint",
        type=Path,
        help="append each completed object's rows to this JSONL checkpoint",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="reuse completed objects from --checkpoint",
    )
    parser.add_argument(
        "--progress",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="print completed-object progress to stderr (default: enabled)",
    )
    return parser


def _selected_objects(language: str, fixtures: list[str]) -> list[str]:
    objects = sorted(path.name for path in BUILD.glob("*.so"))
    if language != "all":
        objects = [name for name in objects if language_for_object(name) == language]
    if fixtures:
        objects = [
            name
            for name in objects
            if any(fnmatch.fnmatchcase(name, pattern) for pattern in fixtures)
        ]
    return objects


def measure_object(name: str, goto_free: set[str]) -> dict[str, list[dict]]:
    """Measure one binary after loading and decompiling it exactly once."""
    rows = {axis: [] for axis in AXES}
    path = str(BUILD / name)
    try:
        sigs = D.signatures(path)
    except Exception:
        return rows

    # One ProgramSession-backed native call replaces one CLI process per
    # function (formerly two because recovered_signature decompiled again).
    rendered_by_va = D.decompiled_many_c(path, [int(sig["va"]) for sig in sigs])
    stem = name.split("-")[0]
    for signature in sigs:
        va = int(signature["va"])
        rendered = rendered_by_va.get(va)
        if not rendered:
            rows["no_body"].append({"obj": name, "fn": signature["name"], "va": va})
            continue

        if stem in goto_free:
            count = len(re.findall(r"\bgoto\s+\w+\s*;", rendered))
            if count:
                rows["structure"].append(
                    {
                        "obj": name,
                        "fn": signature["name"],
                        "va": va,
                        "gotos": count,
                    }
                )

        if "unrecovered" in rendered:
            rows["unrecovered"].append(
                {
                    "obj": name,
                    "fn": signature["name"],
                    "va": va,
                    "n": rendered.count("unrecovered"),
                }
            )

        got = recovered_signature(rendered)
        params = split_params(got) if got else None

        if got:
            wanted_return = dwarf_classify(signature.get("ret") or {})
            head = got.split("(")[0]
            recovered_return = classify(head.rsplit(" ", 1)[0]) if " " in head else None
            if (
                recovered_return
                and wanted_return["w"] is not None
                and recovered_return["w"] is not None
            ):
                if wanted_return["ptr"] and not recovered_return["ptr"]:
                    rows["returns"].append(
                        {
                            "obj": name,
                            "fn": signature["name"],
                            "va": va,
                            "kind": "ptr_lost",
                            "want": "pointer",
                            "got": recovered_return["raw"],
                        }
                    )
                elif (
                    not wanted_return["ptr"]
                    and wanted_return["w"] != recovered_return["w"]
                ):
                    rows["returns"].append(
                        {
                            "obj": name,
                            "fn": signature["name"],
                            "va": va,
                            "kind": "width",
                            "want": wanted_return["w"],
                            "got": recovered_return["raw"],
                        }
                    )

        if params is None or len(params) != len(signature["params"]):
            continue
        for index, (wanted, declaration) in enumerate(zip(signature["params"], params)):
            wanted_type = dwarf_classify(wanted)
            recovered_type = classify(strip_name(declaration))
            if recovered_type["w"] is None:
                continue
            if wanted_type["ptr"] and not recovered_type["ptr"]:
                rows["pointers"].append(
                    {
                        "obj": name,
                        "fn": signature["name"],
                        "va": va,
                        "arg": index,
                        "got": recovered_type["raw"],
                    }
                )
                continue
            if wanted_type["ptr"] or not wanted_type["w"] or not recovered_type["w"]:
                continue
            if wanted_type["w"] != recovered_type["w"]:
                rows["types"].append(
                    {
                        "obj": name,
                        "fn": signature["name"],
                        "va": va,
                        "arg": index,
                        "kind": "width",
                        "want": wanted_type["w"],
                        "got": recovered_type["raw"],
                    }
                )
            elif wanted_type["s"] != recovered_type["s"]:
                rows["types"].append(
                    {
                        "obj": name,
                        "fn": signature["name"],
                        "va": va,
                        "arg": index,
                        "kind": "signedness",
                        "want": "signed" if wanted_type["s"] else "unsigned",
                        "got": recovered_type["raw"],
                    }
                )
    return rows


def _load_checkpoint(path: Path) -> dict[str, dict[str, list[dict]]]:
    """Load the last complete record for each object from an append-only file."""
    completed: dict[str, dict[str, list[dict]]] = {}
    if not path.is_file():
        return completed
    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            name = record["object"]
            rows = record["rows"]
            if not isinstance(name, str) or not isinstance(rows, dict):
                raise TypeError
            if any(not isinstance(rows.get(axis), list) for axis in AXES):
                raise TypeError
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise ValueError(
                f"invalid checkpoint record at line {line_number}"
            ) from error
        completed[name] = rows
    return completed


def _append_checkpoint(path: Path, name: str, rows: dict[str, list[dict]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as stream:
        stream.write(json.dumps({"object": name, "rows": rows}, separators=(",", ":")))
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not BUILD.is_dir():
        print(f"{BUILD} absent; build the fixture matrix first", file=sys.stderr)
        return 2
    if args.jobs < 1:
        print("--jobs must be at least 1", file=sys.stderr)
        return 2
    if args.resume and args.checkpoint is None:
        print("--resume requires --checkpoint", file=sys.stderr)
        return 2
    goto_free = sources_without_goto()
    objects = _selected_objects(args.language, args.fixture)
    if not objects:
        print("no fixture objects matched the requested filters", file=sys.stderr)
        return 2
    rows_by_axis = {axis: [] for axis in AXES}
    t0 = time.time()
    checkpoint_rows: dict[str, dict[str, list[dict]]] = {}
    checkpoint = args.checkpoint.resolve() if args.checkpoint else None
    if checkpoint is not None:
        if args.resume:
            try:
                checkpoint_rows = _load_checkpoint(checkpoint)
            except ValueError as error:
                print(str(error), file=sys.stderr)
                return 2
        else:
            checkpoint.parent.mkdir(parents=True, exist_ok=True)
            checkpoint.write_text("")

    for name in objects:
        if name not in checkpoint_rows:
            continue
        for axis in AXES:
            rows_by_axis[axis].extend(checkpoint_rows[name][axis])
    pending = [name for name in objects if name not in checkpoint_rows]
    reused = len(objects) - len(pending)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = {
            executor.submit(measure_object, name, goto_free): name for name in pending
        }
        for completed, future in enumerate(
            concurrent.futures.as_completed(futures), start=reused + 1
        ):
            name = futures[future]
            measured = future.result()
            for axis in AXES:
                rows_by_axis[axis].extend(measured[axis])
            if checkpoint is not None:
                _append_checkpoint(checkpoint, name, measured)
            if args.progress:
                print(
                    f"[{completed}/{len(objects)}] {name}",
                    file=sys.stderr,
                    flush=True,
                )

    for axis in AXES:
        if axis in ("types", "pointers"):
            rows_by_axis[axis].sort(key=lambda row: (row["obj"], row["va"], row["arg"]))
        else:
            rows_by_axis[axis].sort(key=lambda row: (row["obj"], row["va"]))

    by_language, deduplicated, deduplicated_by_language = inventory_summaries(
        rows_by_axis
    )
    payload = {
        "note": "Measured decompiler failures. Regenerate with tools/gen_known_failures.py.",
        "elapsed_seconds": round(time.time() - t0, 1),
        "objects_scanned": len(objects),
        "counts": {
            **{axis: len(rows_by_axis[axis]) for axis in AXES},
            "goto_statements": sum(row["gotos"] for row in rows_by_axis["structure"]),
        },
        "counts_by_language": by_language,
        "deduplicated_counts": deduplicated,
        "deduplicated_counts_by_language": deduplicated_by_language,
        **rows_by_axis,
    }
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=1) + "\n")
    print(
        f"{output}: "
        + ", ".join(f"{v} {k}" for k, v in payload["counts"].items())
        + f" in {payload['elapsed_seconds']}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
