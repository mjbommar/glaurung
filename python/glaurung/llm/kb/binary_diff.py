"""Function-level binary diff (#184).

Pair two binaries function-by-function and report per-function status:
``same`` / ``changed`` / ``removed`` / ``added``. Foundation for the
patch-analysis demo conversation in the Phase 3 plan: agent says
"v1.1 changed `validate_token` to add a length check before
`memcmp` — likely fixing a CVE-class OOB read."

v1 implementation:
  - Run analyze_functions_path on both binaries.
  - Hash each function's first N instruction bytes (truncated body
    hash) for structural fingerprinting.
  - Match by name first; if both binaries have a function with the
    same name, diff their hashes — same → same, different → changed.
  - Functions present in only one side become added/removed.

Hash scheme: sha256 of the function's primary chunk bytes
(`f.range.start..f.range.start+f.range.size`). Truncated to 8 hex
chars for compact output. Two functions with identical bodies in
different files produce the same hash.

What v1 does NOT do (filed for v2):
  - Function matching by structural similarity when names don't
    match (BSim-style, depends on #186).
  - Per-instruction diff (which bytes changed); v1 reports whole-
    function status only.
  - Cross-architecture diff.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class FunctionFingerprint:
    """One function's identity in a diff context."""
    name: str
    entry_va: int
    size: int
    body_hash: str  # 16-hex-char truncated sha256 of primary chunk bytes


@dataclass
class FunctionDiff:
    """One row in the diff result."""
    name: str
    status: str  # "same" | "changed" | "added" | "removed"
    a: Optional[FunctionFingerprint] = None
    b: Optional[FunctionFingerprint] = None
    # Public PDB symbol (Microsoft-authoritative) for each side's entry VA
    # when a `--pdb-cache` resolved to a matching PDB. None when no cache
    # was provided, the PE has no CodeView record, or the PDB has no
    # symbol at that VA. Phase F2 / A3 extension.
    public_name_pre: Optional[str] = None
    public_name_post: Optional[str] = None


@dataclass
class BinaryDiff:
    binary_a: str
    binary_b: str
    functions_a: int = 0
    functions_b: int = 0
    same: int = 0
    changed: int = 0
    added: int = 0
    removed: int = 0
    rows: List[FunctionDiff] = field(default_factory=list)

    def summary_line(self) -> str:
        return (
            f"{self.same} same / {self.changed} changed / "
            f"{self.added} added / {self.removed} removed "
            f"(a={self.functions_a} b={self.functions_b})"
        )

    def changed_rows(self) -> List[FunctionDiff]:
        return [r for r in self.rows if r.status == "changed"]


def fingerprint_function(raw: bytes, func) -> Optional[FunctionFingerprint]:
    """Extract a structural fingerprint for one function. Reads the
    function's primary chunk bytes from `raw` (the binary's full bytes)
    and hashes them. Returns None when the chunk doesn't resolve to a
    valid byte range."""
    try:
        import glaurung as g
        rng = func.range
        if rng is None or rng.size == 0:
            return None
        off = g.analysis.va_to_file_offset_path(
            "", int(rng.start.value), 100_000_000, 100_000_000,
        )
    except Exception:
        # Fall back to in-memory translation via the func's chunks; if
        # that fails too, skip.
        return None
    # `va_to_file_offset_path` is path-based — for in-process diff we
    # need a different bridge. Use `g.symbol_address_map` style:
    # callers pass us the `binary_path` so we can call directly.
    return None  # _fingerprint_function_via_path is the real entry; see below.


def _hash_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def _fingerprint_via_path(binary_path: str, func) -> Optional[FunctionFingerprint]:
    """Real fingerprint helper that has access to the binary path so
    it can resolve VA → file offset and read the chunk."""
    import glaurung as g
    rng = func.range
    if rng is None or rng.size == 0:
        return None
    try:
        off = g.analysis.va_to_file_offset_path(
            str(binary_path), int(rng.start.value),
            100_000_000, 100_000_000,
        )
    except Exception:
        return None
    if off is None:
        return None
    off = int(off)
    size = int(rng.size)
    try:
        with open(binary_path, "rb") as f:
            f.seek(off)
            buf = f.read(size)
    except OSError:
        return None
    if not buf:
        return None
    return FunctionFingerprint(
        name=func.name,
        entry_va=int(func.entry_point.value),
        size=size,
        body_hash=_hash_bytes(buf),
    )


def diff_binaries(
    binary_a: str,
    binary_b: str,
    *,
    skip_anonymous: bool = True,
    pdb_cache: Optional[str] = None,
) -> BinaryDiff:
    """Pair every function in `binary_a` with the same-named function
    in `binary_b` and report per-function status.

    `skip_anonymous=True` (default) drops `sub_<hex>` placeholder
    names from the diff — they're discovery artifacts whose VAs
    routinely shift between builds and would dominate the report
    with spurious "removed/added" entries that aren't real changes.

    `pdb_cache` is an optional Microsoft-style symbol-cache directory.
    When supplied, each row carries `public_name_pre` / `public_name_post`
    fields populated from the PDB public-symbol table at each side's
    entry VA. Cuts LLM-naming hallucination for nameable functions.
    Phase F2 / A3 extension.
    """
    import glaurung as g

    funcs_a, _ = g.analysis.analyze_functions_path(str(binary_a))
    funcs_b, _ = g.analysis.analyze_functions_path(str(binary_b))

    # Pre-resolve VA -> PDB symbol once per binary (the PDB parse is the
    # expensive step; the lookup is cheap). Empty dict when no cache
    # configured so the lookup below is a no-op fall-through.
    pdb_map_a = _resolve_pdb_symbol_map(str(binary_a), pdb_cache)
    pdb_map_b = _resolve_pdb_symbol_map(str(binary_b), pdb_cache)

    def _index(funcs, path: str) -> Dict[str, FunctionFingerprint]:
        out: Dict[str, FunctionFingerprint] = {}
        for f in funcs:
            if skip_anonymous and f.name.startswith("sub_"):
                continue
            fp = _fingerprint_via_path(path, f)
            if fp is None:
                continue
            # If the same name appears multiple times (rare — usually a
            # `<fn>` and a `<fn>.cold` that didn't get folded), the
            # first wins; #156 should already have merged most.
            out.setdefault(f.name, fp)
        return out

    idx_a = _index(funcs_a, binary_a)
    idx_b = _index(funcs_b, binary_b)

    diff = BinaryDiff(
        binary_a=str(binary_a),
        binary_b=str(binary_b),
        functions_a=len(idx_a),
        functions_b=len(idx_b),
    )

    all_names = sorted(set(idx_a) | set(idx_b))
    for name in all_names:
        fa = idx_a.get(name)
        fb = idx_b.get(name)
        pn_a = pdb_map_a.get(fa.entry_va) if fa else None
        pn_b = pdb_map_b.get(fb.entry_va) if fb else None
        if fa and fb:
            if fa.body_hash == fb.body_hash:
                diff.same += 1
                diff.rows.append(
                    FunctionDiff(
                        name=name,
                        status="same",
                        a=fa,
                        b=fb,
                        public_name_pre=pn_a,
                        public_name_post=pn_b,
                    )
                )
            else:
                diff.changed += 1
                diff.rows.append(
                    FunctionDiff(
                        name=name,
                        status="changed",
                        a=fa,
                        b=fb,
                        public_name_pre=pn_a,
                        public_name_post=pn_b,
                    )
                )
        elif fa:
            diff.removed += 1
            diff.rows.append(
                FunctionDiff(
                    name=name,
                    status="removed",
                    a=fa,
                    public_name_pre=pn_a,
                )
            )
        else:
            diff.added += 1
            diff.rows.append(
                FunctionDiff(
                    name=name,
                    status="added",
                    b=fb,
                    public_name_post=pn_b,
                )
            )
    return diff


def _resolve_pdb_symbol_map(binary_path: str, pdb_cache: Optional[str]) -> Dict[int, str]:
    """Build VA -> PDB public-symbol dict for one binary. Empty when the
    cache is missing or the binary has no matching PDB. Never raises --
    we'd rather diff without PDB names than fail the whole diff."""
    if not pdb_cache:
        return {}
    try:
        import glaurung as g
        return dict(g.symbols.pdb_symbol_map(str(binary_path), str(pdb_cache)))
    except Exception:  # pragma: no cover - best-effort PDB lookup
        return {}


def render_diff_markdown(diff: BinaryDiff, *, max_rows: int = 64) -> str:
    """Pretty-print a BinaryDiff as Markdown — used by the CLI and
    safe to drop into the chat UI verbatim."""
    lines: List[str] = []
    lines.append(f"# Binary diff — {Path(diff.binary_a).name} ↔ {Path(diff.binary_b).name}")
    lines.append("")
    lines.append(diff.summary_line())
    lines.append("")
    if diff.changed:
        lines.append("## Changed functions")
        lines.append("")
        lines.append("| function | a hash | b hash | a size | b size |")
        lines.append("|---|---|---|---:|---:|")
        for r in diff.changed_rows()[:max_rows]:
            lines.append(
                f"| `{r.name}` | `{r.a.body_hash}` | `{r.b.body_hash}` "
                f"| {r.a.size} | {r.b.size} |"
            )
        if diff.changed > max_rows:
            lines.append(f"_… {diff.changed - max_rows} more_")
        lines.append("")
    if diff.added or diff.removed:
        lines.append("## Added / removed")
        lines.append("")
        for r in diff.rows:
            if r.status == "added":
                lines.append(f"- **+** `{r.name}` (new in b, size={r.b.size})")
            elif r.status == "removed":
                lines.append(f"- **−** `{r.name}` (gone from b, was size={r.a.size})")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def to_json(diff: BinaryDiff) -> str:
    """JSON serialization. Stable schema; never remove fields.

    `public_name_pre` and `public_name_post` are present on every row.
    They are `null` when no `pdb_cache` was supplied to `diff_binaries`
    or when the PDB has no public symbol at the row's entry VA. Added
    in Phase F2 / A3."""
    payload = {
        "schema_version": "1",
        "binary_a": diff.binary_a,
        "binary_b": diff.binary_b,
        "functions_a": diff.functions_a,
        "functions_b": diff.functions_b,
        "summary": {
            "same": diff.same, "changed": diff.changed,
            "added": diff.added, "removed": diff.removed,
        },
        "rows": [
            {
                "name": r.name, "status": r.status,
                "a": asdict(r.a) if r.a else None,
                "b": asdict(r.b) if r.b else None,
                "public_name_pre": r.public_name_pre,
                "public_name_post": r.public_name_post,
            }
            for r in diff.rows
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
