#!/usr/bin/env python3
"""Measure what fraction of an installed system's functions a signature set names.

The question this answers, and the two denominators it insists on
----------------------------------------------------------------

"What percentage of functions does the published signature set name?" has no
single honest answer, because the denominator does most of the work:

``of all functions``
    Named, over **every** function discovery finds in the binary. This is the
    number an analyst feels, and on a dynamically linked Linux userland it is
    small by construction -- a distribution executable's text is its own code,
    with libc living in a `.so` the executable does not contain. A signature
    library cannot name code that is not there.

``of functions that are library code``
    Named, over the functions whose ground-truth name is one a harvested
    library actually carries. This is the number that says whether the
    *matcher* works, and it is the only one a library-building programme can
    move by building more libraries.

Reporting either one alone is misleading in opposite directions, so this tool
always reports both, plus the raw counts either can be recomputed from.

Truth lanes
-----------

Naming is scored against ground truth, never against the tool's own output:

``elf-dbgsym``
    An ELF's separate debug object, found by build ID under one or more
    ``.build-id`` roots (Debian/Ubuntu ``-dbgsym`` layout, and this box's own
    ``/usr/lib/debug``). Truth is that object's symbol table.
``elf-symtab``
    The binary's own symbol table -- for a corpus that ships unstripped.
``addr2name``
    A round-trip corpus's ``addr2name.json`` (``{"<opt>/<stem>": {"<va>":
    "<name>"}}``), as ``/nas4/data/binary-analysis/rt-*`` writes.
``pdb``
    A PE's PDB, resolved out of a Microsoft-style symbol cache by the CodeView
    ``GUID+age`` key, read through ``glaurung.symbols.pdb_symbol_map``.

**Truth is a set of names per address, not one name.** A linked image
routinely carries several symbols at one address -- glibc's ``puts`` and
``_IO_puts``, ARM's ``__aeabi_dadd`` and ``__adddf3`` -- and naming it any of
them is a correct identification of the code that is there. Scoring against an
arbitrarily chosen one manufactures "wrong" verdicts out of correct answers.

Matching
--------

Both schemes in a published set are run, and they are run the way the shipped
matcher runs them:

* **FLIRT** (``flirt-masked-pattern-v1``) through
  ``glaurung.analysis.flirt_match_functions_with_evidence_path``, against the
  set's masked-pattern blobs merged into one library. Merging is what
  ``flirt::library_for_paths`` does for a ``GLAURUNG_SIG_DIR``; it is done here
  through the JSON interchange format because the Python match entry point
  takes one library path.
* **WARP** (``warp-function-guid-v1``) as a plain GUID equality lookup over the
  set's GUID blobs, read with ``glaurung.analysis.warp_library_to_json_str``.
  There is no Rust-side "look this GUID up in a loaded WARP library" Python
  API -- ``siglib.match_warp_library`` goes through a KB -- so the lookup is a
  dict in Python here, with ``build_warp_library.MIN_EVIDENCE_BYTES`` applied
  to both sides exactly as that module's own matcher does.

A GUID or pattern that resolves to more than one name is **ambiguous** and
names nothing; if the two schemes disagree about one address, that is
ambiguous too. No name beats a wrong name, at every level.

Usage
-----

::

    # Linux: this box's own /usr/bin, truth from downloaded -dbgsym packages
    uv run python tools/measure_signature_coverage.py \\
        --sig-dir ~/.cache/glaurung/release/2026.09.2/blobs --arch x86_64 \\
        --truth elf-dbgsym --debug-root /usr/lib/debug \\
        --binaries /usr/bin --json-out usrbin.json --markdown-out usrbin.md

    # Windows: a build tree, truth from the Microsoft symbol cache
    uv run python tools/measure_signature_coverage.py \\
        --sig-dir ~/.cache/glaurung/release/2026.09.2/blobs --arch x86_64 \\
        --truth pdb --pdb-cache /nas4/data/symbol-cache/microsoft \\
        --binaries /nas4/.../windows-11-x64 --glob '*.dll' --glob '*.exe' \\
        --glob '*.sys' --require-truth
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import glaurung as g

from glaurung.tools.build_warp_library import MIN_EVIDENCE_BYTES

FLIRT_SCHEME = "flirt-masked-pattern-v1"
WARP_SCHEME = "warp-function-guid-v1"

#: Symbol types `nm` reports for code: global/local text, weak, and gnu-ifunc.
_TEXT_NM_TYPES = frozenset("TtWwi")


# ---------------------------------------------------------------------------
# The signature set
# ---------------------------------------------------------------------------


@dataclass
class SignatureSet:
    """One directory of signature blobs, split by identity scheme.

    A published set's cache directory holds both schemes side by side, named
    by sha256 with no extension, so which is which is read off each file's own
    ``gsig/1`` header rather than off its name -- the same dispatch
    ``flirt::library_for_paths`` does.
    """

    root: Path
    arch: Optional[str]
    flirt_blobs: List[Path] = field(default_factory=list)
    warp_blobs: List[Path] = field(default_factory=list)
    skipped: List[Tuple[str, str]] = field(default_factory=list)

    @classmethod
    def scan(cls, root: Path, arch: Optional[str] = None) -> "SignatureSet":
        """Classify every blob in ``root``, keeping only ``arch`` if given."""
        out = cls(root=root, arch=arch)
        for path in sorted(p for p in root.iterdir() if p.is_file()):
            if path.name in ("catalog.json", "manifest.json", "manifest.json.minisig"):
                continue
            try:
                info = g.analysis.flirt_library_info_path(str(path))
            except (OSError, ValueError) as exc:
                out.skipped.append((path.name, str(exc)))
                continue
            scheme = info.get("scheme") or FLIRT_SCHEME
            blob_arch = info.get("arch")
            if arch is not None and blob_arch != arch:
                out.skipped.append((path.name, f"arch {blob_arch!r} != {arch!r}"))
                continue
            if scheme == WARP_SCHEME:
                out.warp_blobs.append(path)
            else:
                out.flirt_blobs.append(path)
        return out

    # -- FLIRT ------------------------------------------------------------

    def merged_flirt_library(self, cache_dir: Path) -> Optional[Path]:
        """Merge every masked-pattern blob into one ``gsig/1`` library.

        ``flirt_match_functions_with_evidence_path`` takes one library path,
        so the set's blobs are concatenated the way ``library_for_paths``
        concatenates them: a signature carries its own pattern, mask and CRC,
        so there is nothing to reconcile, and a colliding key is reported
        ambiguous by the matcher rather than resolved here.

        The merged file and its name set are cached, keyed by the input
        blobs' names, so a run over many binaries pays the merge once.
        """
        if not self.flirt_blobs:
            return None
        cache_dir.mkdir(parents=True, exist_ok=True)
        tag = f"{self.arch or 'all'}.{len(self.flirt_blobs)}"
        out = cache_dir / f"merged-flirt.{tag}.gsig"
        names_path = cache_dir / f"merged-flirt.{tag}.names.json"
        if out.is_file() and names_path.is_file():
            return out

        entries: List[dict] = []
        names: Set[str] = set()
        prologue_len: Optional[int] = None
        for blob in self.flirt_blobs:
            lib = json.loads(g.analysis.flirt_library_to_json_str(str(blob)))
            if prologue_len is None:
                prologue_len = int(lib.get("prologue_len", 32))
            elif int(lib.get("prologue_len", 32)) != prologue_len:
                self.skipped.append((blob.name, "prologue_len disagrees"))
                continue
            for entry in lib.get("entries", []):
                entries.append(entry)
                names.add(entry["name"])
                for alt in entry.get("alternatives", []) or []:
                    names.add(alt["name"])
        merged = {
            "schema_version": "2",
            "arch": self.arch or "x86_64",
            "prologue_len": prologue_len or 32,
            "entries": entries,
        }
        g.analysis.flirt_gsig_write_from_json_str(json.dumps(merged), str(out))
        names_path.write_text(json.dumps(sorted(names)) + "\n")
        return out

    def flirt_names(self, cache_dir: Path) -> Set[str]:
        """Every name the masked-pattern blobs carry, alternatives included."""
        self.merged_flirt_library(cache_dir)
        tag = f"{self.arch or 'all'}.{len(self.flirt_blobs)}"
        names_path = cache_dir / f"merged-flirt.{tag}.names.json"
        if not names_path.is_file():
            return set()
        return set(json.loads(names_path.read_text()))

    # -- WARP -------------------------------------------------------------

    def warp_index(self, min_bytes: int = MIN_EVIDENCE_BYTES) -> Dict[str, Set[str]]:
        """``guid -> {name, ...}`` over every GUID blob, floored at ``min_bytes``.

        The floor is applied to the library side here and to the candidate
        side at match time, which is what ``build_warp_library`` does: the
        blob records ``byte_len`` per entry precisely so a consumer can raise
        the bar, and dropping small entries at build time would have destroyed
        the evidence needed to lower it.
        """
        index: Dict[str, Set[str]] = {}
        for blob in self.warp_blobs:
            lib = json.loads(g.analysis.warp_library_to_json_str(str(blob)))
            for entry in lib.get("entries", []):
                if int(entry.get("byte_len", 0)) < min_bytes:
                    continue
                index.setdefault(entry["guid"], set()).add(entry["name"])
        return index


# ---------------------------------------------------------------------------
# Truth
# ---------------------------------------------------------------------------


def _nm_text_symbols(path: Path, nm: str = "nm") -> Dict[int, Set[str]]:
    """``address -> {name, ...}`` for every text symbol ``nm`` reports.

    A set per address, not one name: several symbols routinely share one
    address and naming the code any of them is correct.
    """
    out = subprocess.run(
        [nm, "--defined-only", str(path)],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    truth: Dict[int, Set[str]] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        addr_s, sym_type, name = parts
        if sym_type not in _TEXT_NM_TYPES:
            continue
        try:
            addr = int(addr_s, 16)
        except ValueError:
            continue
        if addr == 0:
            continue
        truth.setdefault(addr, set()).add(name)
    return truth


def build_id_of(path: Path) -> Optional[str]:
    """The ELF's GNU build ID, hex, or None."""
    out = subprocess.run(
        ["readelf", "-n", str(path)], capture_output=True, text=True, check=False
    ).stdout
    m = re.search(r"Build ID: ([0-9a-f]+)", out)
    return m.group(1) if m else None


def index_debug_roots(roots: Sequence[Path]) -> Dict[str, Path]:
    """``build-id -> separate debug object`` over every ``.build-id`` tree.

    ``roots`` may name either the ``.build-id`` directory itself or its parent
    (``/usr/lib/debug``), which is what a ``-dbgsym`` package unpacks to.
    """
    index: Dict[str, Path] = {}
    for root in roots:
        base = root / ".build-id" if (root / ".build-id").is_dir() else root
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.debug")):
            index[p.parent.name + p.stem] = p
    return index


class TruthSource:
    """Ground truth for one corpus, in whatever form that corpus has it."""

    def __init__(self, kind: str, **kw: Any) -> None:
        self.kind = kind
        self.debug_index: Dict[str, Path] = kw.get("debug_index") or {}
        self.addr2name: Dict[str, Dict[str, str]] = kw.get("addr2name") or {}
        self.pdb_cache: Optional[Path] = kw.get("pdb_cache")
        self.nm: str = kw.get("nm") or "nm"

    def key_for(self, binary: Path) -> Optional[str]:
        """The ``addr2name.json`` key for ``binary`` (``<parent>/<stem>``)."""
        return f"{binary.parent.name}/{binary.stem}"

    def for_binary(self, binary: Path) -> Optional[Dict[int, Set[str]]]:
        """``address -> {name, ...}``, or None when this corpus has no truth."""
        if self.kind == "elf-symtab":
            truth = _nm_text_symbols(binary, self.nm)
            return truth or None
        if self.kind == "elf-dbgsym":
            bid = build_id_of(binary)
            if bid is None:
                return None
            debug = self.debug_index.get(bid)
            if debug is None:
                return None
            truth = _nm_text_symbols(debug, self.nm)
            return truth or None
        if self.kind == "addr2name":
            key = self.key_for(binary)
            table = self.addr2name.get(key or "")
            if not table:
                return None
            truth: Dict[int, Set[str]] = {}
            for addr_s, name in table.items():
                addr = int(addr_s) & ~1
                if addr:
                    truth.setdefault(addr, set()).add(name)
            return truth or None
        if self.kind == "pdb":
            if self.pdb_cache is None:
                return None
            try:
                flat = g.symbols.pdb_symbol_map(str(binary), str(self.pdb_cache))
            except (OSError, ValueError):
                return None
            if not flat:
                return None
            return {int(va): {name} for va, name in flat.items()}
        raise ValueError(f"unknown truth kind {self.kind!r}")


# ---------------------------------------------------------------------------
# Scoring one binary
# ---------------------------------------------------------------------------


@dataclass
class BinaryResult:
    """Every count one binary contributes, and nothing derived."""

    path: str
    functions_total: int = 0
    truth_symbols: int = 0
    scored: int = 0
    named: int = 0
    correct: int = 0
    wrong: int = 0
    ambiguous: int = 0
    named_flirt: int = 0
    named_warp: int = 0
    library_functions: int = 0
    library_named: int = 0
    library_correct: int = 0
    error: Optional[str] = None
    wrong_examples: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "functions_total": self.functions_total,
            "truth_symbols": self.truth_symbols,
            "scored": self.scored,
            "named": self.named,
            "correct": self.correct,
            "wrong": self.wrong,
            "ambiguous": self.ambiguous,
            "named_flirt": self.named_flirt,
            "named_warp": self.named_warp,
            "library_functions": self.library_functions,
            "library_named": self.library_named,
            "library_correct": self.library_correct,
            "error": self.error,
            "wrong_examples": self.wrong_examples,
        }


def discovered_entry_vas(binary: Path) -> List[int]:
    """Entry VAs of the functions the matcher's own discovery finds.

    ``analyze_functions_path``'s defaults are ``Budgets::default()``
    field for field, which is what ``flirt_match_functions_with_evidence_path``
    and ``warp_function_guids_path`` construct internally -- so this is the
    same discovery, not a second opinion about it.
    """
    functions, _callgraph = g.analysis.analyze_functions_path(str(binary))
    return sorted(int(f.entry_point.value) for f in functions)


def _flirt_verdicts(binary: Path, library: Optional[Path]) -> Dict[int, Optional[str]]:
    """``entry VA -> name`` from FLIRT; ``None`` marks an ambiguous verdict."""
    if library is None:
        return {}
    out: Dict[int, Optional[str]] = {}
    for m in g.analysis.flirt_match_functions_with_evidence_path(
        str(binary), str(library)
    ):
        va = int(m["entry_va"])
        if m["ambiguous"] or not m["names"]:
            out[va] = None
        else:
            out[va] = m["names"][0]
    return out


def _warp_verdicts(
    binary: Path, index: Dict[str, Set[str]], min_bytes: int
) -> Tuple[Dict[int, Optional[str]], int]:
    """``entry VA -> name`` from GUID equality, plus the function count seen.

    Returns ``(verdicts, functions_seen)``; ``functions_seen`` is 0 when the
    architecture has no WARP masking rule, which is not an error -- the scheme
    simply does not apply to that image.
    """
    if not index:
        return {}, 0
    try:
        functions = g.analysis.warp_function_guids_path(str(binary))
    except (OSError, ValueError):
        return {}, 0
    out: Dict[int, Optional[str]] = {}
    for fn in functions:
        if int(fn.byte_len) < min_bytes:
            continue
        names = index.get(str(fn.guid))
        if not names:
            continue
        out[int(fn.entry_va)] = next(iter(names)) if len(names) == 1 else None
    return out, len(functions)


def combine(
    flirt: Dict[int, Optional[str]], warp: Dict[int, Optional[str]]
) -> Dict[int, Optional[str]]:
    """One verdict per address across both schemes.

    Two schemes agreeing is one name; two schemes disagreeing is ambiguous,
    for the same reason a single scheme's collision is: a confidently wrong
    name outranks the correct one downstream, so nothing is applied.
    """
    out: Dict[int, Optional[str]] = dict(flirt)
    for va, name in warp.items():
        if va not in out:
            out[va] = name
        elif out[va] is None or name is None:
            out[va] = None
        elif out[va] != name:
            out[va] = None
    return out


def score_binary(
    binary: Path,
    *,
    flirt_library: Optional[Path],
    warp_index: Dict[str, Set[str]],
    truth_source: TruthSource,
    library_names: Set[str],
    min_bytes: int = MIN_EVIDENCE_BYTES,
) -> BinaryResult:
    """Discover, match, then grade -- in that order, truth read last."""
    result = BinaryResult(path=str(binary))
    try:
        vas = discovered_entry_vas(binary)
    except (OSError, ValueError) as exc:
        result.error = f"discovery: {exc}"
        return result
    result.functions_total = len(vas)

    flirt = _flirt_verdicts(binary, flirt_library)
    warp, _seen = _warp_verdicts(binary, warp_index, min_bytes)
    result.named_flirt = sum(1 for n in flirt.values() if n is not None)
    result.named_warp = sum(1 for n in warp.values() if n is not None)
    verdicts = combine(flirt, warp)

    truth = truth_source.for_binary(binary)
    if truth is None:
        result.error = "no truth"
        # Naming still counted: "of all functions" needs no ground truth.
        result.named = sum(1 for va in vas if verdicts.get(va) is not None)
        result.ambiguous = sum(
            1 for va in vas if va in verdicts and verdicts[va] is None
        )
        return result
    result.truth_symbols = len(truth)

    for va in vas:
        verdict = verdicts.get(va, "\0missing")
        names = truth.get(va)
        is_library = bool(names) and bool(names & library_names)
        if is_library:
            result.library_functions += 1
        if verdict == "\0missing":
            continue
        if verdict is None:
            result.ambiguous += 1
            continue
        result.named += 1
        if is_library:
            result.library_named += 1
        if names is None:
            continue
        if verdict in names:
            result.correct += 1
            if is_library:
                result.library_correct += 1
        else:
            result.wrong += 1
            if len(result.wrong_examples) < 5:
                truth_name = "|".join(sorted(names))
                result.wrong_examples.append(
                    f"{va:#x}: got {verdict!r}, truth {truth_name!r}"
                )
    # `scored` must count every truth-named discovered function, matched or
    # not -- it is the population on which correct and wrong can be told
    # apart, not the population a name happened to be applied to.
    result.scored = sum(1 for va in vas if va in truth)
    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def aggregate(rows: Sequence[BinaryResult]) -> Dict[str, Any]:
    """Sums plus the two denominators, computed once, from the sums."""
    total = {
        k: sum(getattr(r, k) for r in rows)
        for k in (
            "functions_total",
            "truth_symbols",
            "scored",
            "named",
            "correct",
            "wrong",
            "ambiguous",
            "named_flirt",
            "named_warp",
            "library_functions",
            "library_named",
            "library_correct",
        )
    }
    total["binaries"] = len(rows)
    total["binaries_with_truth"] = sum(1 for r in rows if r.error is None)
    total["of_all_functions"] = _ratio(total["named"], total["functions_total"])
    total["of_library_functions"] = _ratio(
        total["library_named"], total["library_functions"]
    )
    total["precision"] = _ratio(total["correct"], total["correct"] + total["wrong"])
    total["recall_of_scored"] = _ratio(total["correct"], total["scored"])
    return total


def _ratio(num: int, den: int) -> float:
    return round(num / den, 6) if den else 0.0


def markdown_table(
    rows: Sequence[BinaryResult],
    totals: Dict[str, Any],
    label: str,
    max_rows: int = 40,
) -> str:
    """A per-binary table plus the aggregate row, deterministic ordering.

    A corpus of thousands of binaries makes a per-row table useless as prose,
    so beyond ``max_rows`` only the largest by function count are listed and
    the table says so. Every row is in the JSON regardless -- the table is a
    reading aid, not the result.
    """
    ordered = sorted(rows, key=lambda r: r.path)
    shown = ordered
    elided = 0
    if len(ordered) > max_rows:
        shown = sorted(
            sorted(ordered, key=lambda r: -r.functions_total)[:max_rows],
            key=lambda r: r.path,
        )
        elided = len(ordered) - len(shown)
    lines = [
        f"### {label}",
        "",
        "| binary | functions | truth | scored | named | correct | wrong | ambiguous "
        "| library fns | library named |",
        "|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|",
    ]
    for r in shown:
        lines.append(
            f"| `{Path(r.path).name}` | {r.functions_total} | {r.truth_symbols} "
            f"| {r.scored} | {r.named} | {r.correct} | {r.wrong} | {r.ambiguous} "
            f"| {r.library_functions} | {r.library_named} |"
        )
    if elided:
        lines.append(
            f"| *({elided} smaller binaries not listed; all rows are in the JSON)* "
            "| | | | | | | | | |"
        )
    lines.append(
        f"| **total ({totals['binaries']} binaries)** | {totals['functions_total']} "
        f"| {totals['truth_symbols']} | {totals['scored']} | {totals['named']} "
        f"| {totals['correct']} | {totals['wrong']} | {totals['ambiguous']} "
        f"| {totals['library_functions']} | {totals['library_named']} |"
    )
    lines += [
        "",
        f"* **of all functions**: {totals['named']} / {totals['functions_total']} "
        f"= **{totals['of_all_functions']:.4%}** "
        f"(all {totals['binaries']} binaries; naming needs no ground truth)",
        f"* **of functions that are library code**: {totals['library_named']} / "
        f"{totals['library_functions']} = **{totals['of_library_functions']:.4%}** "
        f"(the {totals['binaries_with_truth']} binaries a truth source names; "
        "the other rows contribute 0/0 to this denominator)",
        f"* precision on the scored population: {totals['correct']} / "
        f"{totals['correct'] + totals['wrong']} = {totals['precision']:.4%}",
        f"* recall over the {totals['scored']} discovered functions truth names: "
        f"{totals['correct']} = {totals['recall_of_scored']:.4%}",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def collect_binaries(
    roots: Sequence[Path], globs: Sequence[str], recursive: bool
) -> List[Path]:
    """Every candidate input, sorted, deduplicated, symlinks resolved once."""
    seen: Dict[Path, None] = {}
    for root in roots:
        if root.is_file():
            seen[root] = None
            continue
        if not root.is_dir():
            continue
        for pattern in globs or ["*"]:
            it: Iterable[Path] = (
                root.rglob(pattern) if recursive else root.glob(pattern)
            )
            for p in it:
                if p.is_file() and not p.is_symlink():
                    seen[p] = None
    return sorted(seen)


def object_format(path: Path) -> Optional[str]:
    """``"elf"``, ``"pe"``, or None -- by magic, never by suffix.

    Which format an input is decides which scheme's names form its
    "library code" denominator: a Windows PE's library code is what the WARP
    GUID libraries carry, an ELF's is what the masked-pattern libraries carry,
    and pooling the two would let a Microsoft symbol name count an ELF
    function as library code (or the reverse).
    """
    try:
        head = path.open("rb").read(2)
    except OSError:
        return None
    if head == b"\x7fE":
        return "elf"
    if head == b"MZ":
        return "pe"
    return None


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sig-dir", type=Path, required=True)
    p.add_argument("--arch", default=None, help="Keep only blobs of this arch.")
    p.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("~/.cache/glaurung/sig-coverage").expanduser(),
    )
    p.add_argument(
        "--truth",
        required=True,
        choices=["elf-dbgsym", "elf-symtab", "addr2name", "pdb"],
    )
    p.add_argument("--debug-root", type=Path, action="append", default=None)
    p.add_argument("--addr2name", type=Path, default=None)
    p.add_argument("--pdb-cache", type=Path, default=None)
    p.add_argument("--nm", default="nm")
    p.add_argument("--binaries", type=Path, action="append", default=None)
    p.add_argument(
        "--binaries-from",
        type=Path,
        default=None,
        help="A file of newline-separated paths. Use it when the population "
        "is a pre-filtered subset (e.g. the PEs whose PDB is actually in the "
        "cache), so discovery is not paid for inputs that cannot be scored.",
    )
    p.add_argument("--glob", action="append", default=None)
    p.add_argument("--recursive", action="store_true")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument(
        "--require-truth",
        action="store_true",
        help="Report only binaries a truth source names; the honest default "
        "for a corpus where truth is the binding constraint.",
    )
    p.add_argument("--min-bytes", type=int, default=MIN_EVIDENCE_BYTES)
    p.add_argument("--label", default="coverage")
    p.add_argument("--json-out", type=Path, default=None)
    p.add_argument("--markdown-out", type=Path, default=None)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    if not args.binaries and not args.binaries_from:
        p.error("one of --binaries or --binaries-from is required")

    started = time.time()
    sigset = SignatureSet.scan(args.sig_dir.expanduser(), args.arch)
    cache_dir = args.cache_dir.expanduser()
    if not args.quiet:
        print(
            f"signature set: {len(sigset.flirt_blobs)} FLIRT blobs, "
            f"{len(sigset.warp_blobs)} WARP blobs "
            f"({len(sigset.skipped)} skipped)",
            file=sys.stderr,
        )
    flirt_library = sigset.merged_flirt_library(cache_dir)
    warp_index = sigset.warp_index(args.min_bytes)
    warp_names: Set[str] = set()
    # For PE, a PDB name counts as "library code" if any WARP library carries
    # it -- the fallback the design asks for, because no PDB API exposed here
    # reports a symbol's source file, and a CRT/STL source path is what the
    # first-choice test would need.
    for names in warp_index.values():
        warp_names |= names
    library_names_by_format = {
        "elf": sigset.flirt_names(cache_dir),
        "pe": sigset.flirt_names(cache_dir) | warp_names,
    }
    if not args.quiet:
        print(
            f"library names: elf={len(library_names_by_format['elf'])} "
            f"pe={len(library_names_by_format['pe'])}; "
            f"WARP GUIDs: {len(warp_index)}; "
            f"merged FLIRT library: {flirt_library}",
            file=sys.stderr,
        )

    truth_source = TruthSource(
        args.truth,
        debug_index=index_debug_roots(
            [r.expanduser() for r in (args.debug_root or [Path("/usr/lib/debug")])]
        )
        if args.truth == "elf-dbgsym"
        else {},
        addr2name=json.loads(args.addr2name.read_text()) if args.addr2name else {},
        pdb_cache=args.pdb_cache.expanduser() if args.pdb_cache else None,
        nm=args.nm,
    )

    roots = [r.expanduser() for r in (args.binaries or [])]
    if args.binaries_from:
        roots += [
            Path(line.strip()).expanduser()
            for line in args.binaries_from.read_text().splitlines()
            if line.strip()
        ]
    candidates: List[Tuple[Path, str]] = []
    for b in collect_binaries(roots, args.glob or [], args.recursive):
        fmt = object_format(b)
        if fmt is not None:
            candidates.append((b, fmt))
    if not args.quiet:
        print(f"candidates: {len(candidates)}", file=sys.stderr)

    rows: List[BinaryResult] = []
    skipped_no_truth = 0
    for binary, fmt in candidates:
        if args.limit and len(rows) >= args.limit:
            break
        r = score_binary(
            binary,
            flirt_library=flirt_library,
            warp_index=warp_index,
            truth_source=truth_source,
            library_names=library_names_by_format[fmt],
            min_bytes=args.min_bytes,
        )
        if args.require_truth and r.error is not None:
            skipped_no_truth += 1
            continue
        rows.append(r)
        if not args.quiet:
            print(
                f"{binary.name:40.40s} fns={r.functions_total:6d} "
                f"truth={r.truth_symbols:6d} named={r.named:6d} "
                f"correct={r.correct:6d} wrong={r.wrong:4d} "
                f"amb={r.ambiguous:5d} lib={r.library_named}/{r.library_functions}"
                + (f"  [{r.error}]" if r.error else ""),
                file=sys.stderr,
            )

    totals = aggregate(rows)
    totals["candidates"] = len(candidates)
    totals["skipped_no_truth"] = skipped_no_truth
    totals["elapsed_s"] = round(time.time() - started, 2)
    report = {
        "label": args.label,
        "sig_dir": str(args.sig_dir),
        "arch": args.arch,
        "truth": args.truth,
        "min_bytes": args.min_bytes,
        "flirt_blobs": len(sigset.flirt_blobs),
        "warp_blobs": len(sigset.warp_blobs),
        "library_names_elf": len(library_names_by_format["elf"]),
        "library_names_pe": len(library_names_by_format["pe"]),
        "warp_guids": len(warp_index),
        "rows": [r.to_dict() for r in sorted(rows, key=lambda r: r.path)],
        "totals": totals,
    }
    md = markdown_table(rows, totals, args.label)
    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if args.markdown_out:
        args.markdown_out.write_text(md + "\n")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
