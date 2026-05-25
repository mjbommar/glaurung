"""Function-level binary diff (#184).

Pair two binaries function-by-function and report per-function status:
``same`` / ``changed`` / ``removed`` / ``added``. Foundation for the
patch-analysis demo conversation in the Phase 3 plan: agent says
"v1.1 changed `validate_token` to add a length check before
`memcmp` — likely fixing a CVE-class OOB read."

v2 (current) implementation:
  - Run analyze_functions_path on both binaries.
  - For each function compute *both* a raw byte ``body_hash`` AND a
    ``structural_hash`` (see ``structural_fingerprint.py``). The
    structural hash masks VA-shift noise (direct call targets,
    rip-relative globals, register identity, stack-displacement
    constants) so relinked binaries don't produce thousands of
    spurious "changed" rows.
  - Match by name first; when both binaries carry a function with the
    same name, the row's ``status`` is determined by the structural
    hash:
      * ``structural_hash_a == structural_hash_b`` → ``same`` (even
        when ``body_hash`` differs — that's the relink-noise case).
      * Different structural hashes → ``changed``. A Jaccard
        similarity score over per-block token-hash multisets is
        included so the CLI can sort by "how big a change" — single-
        block patches surface at the top of the list.
  - Functions present in only one side become added/removed.

v1 hash scheme (preserved on rows for diagnostics): sha256 of the
function's primary chunk bytes, truncated to 16 hex chars.

What this still does NOT do (filed for v3):
  - Function matching by structural similarity when *names* don't
    match (BSim-style across-name re-matching).
  - Per-instruction diff (which instruction lines changed); we report
    whole-function status only.
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
    """One function's identity in a diff context.

    Carries *two* hashes:

    * ``body_hash`` — raw SHA256 of the function's bytes. Flips on any
      VA shift (the relink-noise case). Kept for forensic diagnostics
      and JSON-schema continuity.

    * ``structural_hash`` — the BinDiff/Diaphora-style fingerprint
      that masks VA-shift noise. Two structurally identical functions
      share the same value across builds.  Empty string when
      structural lifting failed (e.g. function had zero blocks).

    Equality of structural_hash is the v2 "same" oracle.
    """

    name: str
    entry_va: int
    size: int
    body_hash: str        # 16-hex truncated sha256 of primary chunk bytes
    structural_hash: str  # 16-hex structural fingerprint (see structural_fingerprint.py)


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
    # Jaccard similarity over per-block structural token-hash multisets,
    # in [0.0, 1.0]. 1.0 means every block matched. Populated when both
    # sides resolved to a structural fingerprint; ``None`` otherwise
    # (e.g. one-sided rows or blocks-less thunks). Phase F5 extension.
    similarity: Optional[float] = None


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


def _fingerprint_via_path(
    binary_path: str,
    func,
    *,
    iat_by_va: Optional[Dict[int, str]] = None,
    structures: Optional[Dict[str, "FunctionStructure"]] = None,
    data: Optional[bytes] = None,
    va_table: Optional[List[Tuple[int, int, int]]] = None,
    disassembler=None,
) -> Optional[FunctionFingerprint]:
    """Real fingerprint helper that has access to the binary path so
    it can resolve VA → file offset and read the chunk.

    Computes both the raw ``body_hash`` and the structural fingerprint
    (when ``iat_by_va`` is supplied). The structural fingerprint is the
    v2 same/changed oracle; the body hash is kept for diagnostics. If
    ``structures`` is non-None we cache the FunctionStructure under the
    function's entry VA so the caller can reach the per-block token
    hashes for the similarity score later.

    When ``data`` + ``va_table`` + ``disassembler`` are supplied (the
    fast path) we read the function's bytes from the already-mmap'd
    buffer and pass them to the in-process disassembler. Otherwise we
    fall back to a per-block ``disassemble_window_at`` (slow but
    correct for non-PE inputs).
    """
    import glaurung as g
    from .structural_fingerprint import va_to_offset

    rng = func.range
    if rng is None or rng.size == 0:
        return None

    size = int(rng.size)
    start_va = int(rng.start.value)
    buf: Optional[bytes] = None

    if data is not None and va_table is not None:
        off = va_to_offset(va_table, start_va)
        if off is not None and 0 <= off < len(data):
            buf = bytes(data[off : off + size])
    if buf is None:
        try:
            off = g.analysis.va_to_file_offset_path(
                str(binary_path), start_va, 100_000_000, 100_000_000,
            )
        except Exception:
            return None
        if off is None:
            return None
        off = int(off)
        try:
            with open(binary_path, "rb") as f:
                f.seek(off)
                buf = f.read(size)
        except OSError:
            return None
    if not buf:
        return None

    structural = ""
    if iat_by_va is not None:
        from .structural_fingerprint import structural_fingerprint

        try:
            fs = structural_fingerprint(
                func=func,
                path=binary_path,
                iat_by_va=iat_by_va,
                data=data,
                va_table=va_table,
                disassembler=disassembler,
            )
        except Exception:
            fs = None
        if fs is not None:
            structural = fs.fingerprint
            if structures is not None:
                structures[func.name] = fs

    return FunctionFingerprint(
        name=func.name,
        entry_va=int(func.entry_point.value),
        size=size,
        body_hash=_hash_bytes(buf),
        structural_hash=structural,
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
    from .structural_fingerprint import (
        FunctionStructure, build_va_table, resolve_iat_map, similarity_score,
    )

    funcs_a, _ = g.analysis.analyze_functions_path(str(binary_a))
    funcs_b, _ = g.analysis.analyze_functions_path(str(binary_b))

    # Pre-resolve VA -> PDB symbol once per binary (the PDB parse is the
    # expensive step; the lookup is cheap). Empty dict when no cache
    # configured so the lookup below is a no-op fall-through.
    pdb_map_a = _resolve_pdb_symbol_map(str(binary_a), pdb_cache)
    pdb_map_b = _resolve_pdb_symbol_map(str(binary_b), pdb_cache)

    # IAT lookup powers the "call qword ptr [rip+disp] -> import name"
    # substitution in the structural fingerprint. For non-PE inputs the
    # call returns an empty map and we silently fall back to "global"
    # tokens for rip-relative memory.
    iat_a = resolve_iat_map(str(binary_a))
    iat_b = resolve_iat_map(str(binary_b))

    # Read each binary once into a bytes buffer + section table so the
    # structural fingerprint doesn't re-read the file per basic block.
    # On non-PE inputs build_va_table returns ``([], 0)`` and the
    # fingerprint silently falls back to the slow path-based read.
    try:
        with open(binary_a, "rb") as _fa:
            data_a = _fa.read()
    except OSError:
        data_a = b""
    try:
        with open(binary_b, "rb") as _fb:
            data_b = _fb.read()
    except OSError:
        data_b = b""
    va_table_a, _ = build_va_table(data_a)
    va_table_b, _ = build_va_table(data_b)
    try:
        disasm_a = g.disasm.disassembler_for_path(str(binary_a)) if va_table_a else None
    except Exception:
        disasm_a = None
    try:
        disasm_b = g.disasm.disassembler_for_path(str(binary_b)) if va_table_b else None
    except Exception:
        disasm_b = None

    # Cache of FunctionStructure objects, keyed by function name, so the
    # similarity score doesn't re-disassemble.
    structures_a: Dict[str, FunctionStructure] = {}
    structures_b: Dict[str, FunctionStructure] = {}

    def _index(
        funcs,
        path: str,
        iat_by_va: Dict[int, str],
        data: bytes,
        va_table,
        disassembler,
        pdb_map: Dict[int, str],
    ) -> Tuple[Dict[str, FunctionFingerprint], Dict[str, FunctionStructure]]:
        """Index functions by *effective name* — the PDB public symbol
        when one resolves at the entry VA, otherwise the discoverer's
        name (which is ``sub_<hex>`` for anonymous functions).

        This is what fixes the relinked-PE noise: every RR parser in
        dnsapi shifts its anonymous ``sub_<hex>`` slot by ~10 bytes
        between builds, but the PDB symbol pins each one to a stable
        identity (``Opt_RecordRead``, ``A_RecordRead``, ...). Matching
        on the PDB name pairs them across builds — the linker noise
        evaporates from the diff entirely.

        Returns ``(fingerprint-by-effective-name, structures-by-effective-name)``.
        """
        out_fp: Dict[str, FunctionFingerprint] = {}
        out_struct: Dict[str, FunctionStructure] = {}
        # Two passes: PDB-named functions first (they shadow any
        # later anonymous collision at the same effective name).
        ordered = sorted(
            funcs,
            key=lambda f: 0 if pdb_map.get(int(f.entry_point.value)) else 1,
        )
        # We need the structures dict to survive across _fingerprint_via_path
        # calls (it caches the FunctionStructure for similarity scoring),
        # but we key it by EFFECTIVE name not source name. The simplest
        # approach is a small wrapper: stash the structure under the
        # function's own name during the fingerprint call, then rename.
        scratch: Dict[str, FunctionStructure] = {}
        for f in ordered:
            entry_va = int(f.entry_point.value)
            pdb_name = pdb_map.get(entry_va)
            effective_name = pdb_name or f.name
            if skip_anonymous and not pdb_name and f.name.startswith("sub_"):
                continue
            if effective_name in out_fp:
                # First-wins for duplicates; usually a cold-section copy.
                continue
            fp = _fingerprint_via_path(
                path, f,
                iat_by_va=iat_by_va,
                structures=scratch,
                data=data if va_table else None,
                va_table=va_table or None,
                disassembler=disassembler,
            )
            if fp is None:
                continue
            out_fp[effective_name] = FunctionFingerprint(
                name=effective_name,
                entry_va=fp.entry_va,
                size=fp.size,
                body_hash=fp.body_hash,
                structural_hash=fp.structural_hash,
            )
            fs = scratch.pop(f.name, None)
            if fs is not None:
                out_struct[effective_name] = fs
        return out_fp, out_struct

    idx_a, structures_a = _index(
        funcs_a, binary_a, iat_a, data_a, va_table_a, disasm_a, pdb_map_a,
    )
    idx_b, structures_b = _index(
        funcs_b, binary_b, iat_b, data_b, va_table_b, disasm_b, pdb_map_b,
    )

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
            sim: Optional[float] = None
            sa, sb = structures_a.get(name), structures_b.get(name)
            if sa is not None and sb is not None:
                sim = similarity_score(sa, sb)
            # Structural equality is the v2 "same" oracle. We accept
            # body-hash equality as a fallback (e.g. for thunks where
            # the structural lifter produced an empty fingerprint).
            structural_match = bool(
                fa.structural_hash
                and fb.structural_hash
                and fa.structural_hash == fb.structural_hash
            )
            body_match = fa.body_hash == fb.body_hash
            if structural_match or body_match:
                diff.same += 1
                diff.rows.append(
                    FunctionDiff(
                        name=name,
                        status="same",
                        a=fa,
                        b=fb,
                        public_name_pre=pn_a,
                        public_name_post=pn_b,
                        similarity=sim if sim is not None else 1.0,
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
                        similarity=sim,
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


def render_diff_markdown(diff: BinaryDiff, *, max_rows: int = 0) -> str:
    """Pretty-print a BinaryDiff as Markdown — used by the CLI and
    safe to drop into the chat UI verbatim. ``max_rows=0`` (the default)
    emits every changed row; set a positive value to truncate.

    Changed rows are sorted by ``similarity`` ascending (smallest score
    first) so the most invasive patches surface at the top of the
    table. Single-block patches (similarity ≈ 1 - 1/blocks) bubble up
    just below whole-function rewrites (similarity ≈ 0)."""
    lines: List[str] = []
    lines.append(f"# Binary diff — {Path(diff.binary_a).name} ↔ {Path(diff.binary_b).name}")
    lines.append("")
    lines.append(diff.summary_line())
    lines.append("")
    if diff.changed:
        lines.append("## Changed functions")
        lines.append("")
        lines.append("| similarity | function | a struct | b struct | a size | b size |")
        lines.append("|---:|---|---|---|---:|---:|")
        rows = sorted(
            diff.changed_rows(),
            key=lambda r: (r.similarity if r.similarity is not None else -1.0, r.name),
        )
        shown = rows if max_rows <= 0 else rows[:max_rows]
        for r in shown:
            sim_str = "—" if r.similarity is None else f"{r.similarity:.3f}"
            sa = (r.a.structural_hash or "—") if r.a else "—"
            sb = (r.b.structural_hash or "—") if r.b else "—"
            lines.append(
                f"| {sim_str} | `{r.name}` | `{sa}` | `{sb}` "
                f"| {r.a.size} | {r.b.size} |"
            )
        if max_rows > 0 and diff.changed > max_rows:
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

    Schema 2 (Phase F5): adds per-row ``similarity`` (Jaccard over
    per-block token-hash multisets, in [0,1], or ``null`` for one-
    sided rows / lift failures) and embeds ``structural_hash`` inside
    each side's fingerprint payload.

    Backwards compat: schema 1 readers that ignore unknown fields will
    still work — every previously-emitted field name is preserved.

    ``public_name_pre`` and ``public_name_post`` (Phase F2 / A3) are
    still present on every row, ``null`` when no PDB cache is wired."""
    payload = {
        "schema_version": "2",
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
                "similarity": r.similarity,
            }
            for r in diff.rows
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
