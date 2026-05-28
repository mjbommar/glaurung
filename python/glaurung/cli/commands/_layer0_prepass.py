"""F4 -- Layer-0 atomic-labeler pre-pass for ``glaurung explain``.

Runs three Layer-0 tools across a function's pseudocode and assembles
the ``variable_names`` / ``string_names`` / ``constant_labels`` tables
that ``rewrite_function_idiomatic`` (Tool #14) consumes:

    1. Tool #5  ``name_local_variable``  -> ``variable_names``
    2. Tool #3  ``name_string_literal``  -> ``string_names``
    3. Tool #2  ``classify_constant``    -> ``constant_labels``

The module is imported lazily by ``ExplainCommand`` only when the
``--with-layer0`` flag is set, because the pre-pass adds 10-30 LLM
calls per function (~$0.20-$0.50 at gpt-5.4-mini-flex).

Each individual Layer-0 call is content-addressed against the A7
cache under the ``layer0/<glaurung_version>/<sha256(binary)>/`` tree
so the same call across CVE months hits the cache.

The pre-pass NEVER raises -- any tool exception is logged at WARNING
and silently dropped from the output tables. This keeps the explain
pipeline robust on partial inputs.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .. import cache as _cache

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Extractors -- pure-regex pulls over the raw pseudocode text. These are
# intentionally permissive: false positives are filtered on the next
# layer (e.g. PE-boilerplate strings) and the Layer-0 tools themselves
# tolerate trivial inputs without hitting the LLM.
# ---------------------------------------------------------------------------

# %var0, var0, arg0, stack_0, t7 -- the canonical local-id shapes the
# Rust lifter emits. The leading '%' is optional because we see both
# forms across the codebase (raw IR vs cosmetic render).
_LOCAL_RE = re.compile(
    r"%?\b((?:var|arg|t)\d+|stack_\d+)\b"
)

# String literal in pseudocode. Decompiled output uses double-quoted
# strings for embedded constants; we tolerate \" escapes inside.
_STRING_RE = re.compile(r'"((?:\\.|[^"\\])*)"')

# Numeric constants -- hex and decimal forms. We drop the trivial set
# below so we don't burn LLM calls on 0/1/page-size/etc.
_HEX_CONST_RE = re.compile(r"\b(0x[0-9a-fA-F]+)\b")

# Trivial constants the pre-pass refuses to send to Tool #2. These are
# the constants the rewriter does NOT need symbolic forms for (and the
# constant-classifier wouldn't produce useful output for either).
_TRIVIAL_CONSTANTS: frozenset[int] = frozenset({
    # arithmetic identities + small integers used as counters
    0, 1, -1, 2, 3,
    # word sizes
    4, 8, 16, 32, 64,
    # common widths / alignments
    128, 256, 512,
    # page size (the table in classify_constant.py already labels this,
    # so calling the tool is just a slow table lookup)
    0x1000,
})


def _extract_locals(pseudocode: str) -> list[str]:
    """Return distinct local-variable identifiers in encounter order."""
    seen: dict[str, None] = {}
    for m in _LOCAL_RE.finditer(pseudocode or ""):
        seen.setdefault(m.group(1), None)
    return list(seen.keys())


def _extract_strings(pseudocode: str) -> list[str]:
    """Return distinct string literals in encounter order, with PE / CRT
    / WIL boilerplate stripped.

    Reuses the F1 boilerplate filter from
    :mod:`glaurung.llm.tools.suggest_function_name` so we never burn an
    LLM call on the DOS-stub, Rich-header, or wil_details_* helpers
    that ship in every Windows PE.
    """
    # Lazy import: avoid pulling pydantic_ai on plain --no-with-layer0
    # invocations.
    from glaurung.llm.tools.suggest_function_name import _is_pe_boilerplate

    seen: dict[str, None] = {}
    for m in _STRING_RE.finditer(pseudocode or ""):
        raw = m.group(1)
        if not raw or len(raw) < 2:
            # Single-char strings are usually scratch ('\n' separators);
            # below the LLM-naming threshold.
            continue
        if _is_pe_boilerplate(raw):
            continue
        seen.setdefault(raw, None)
    return list(seen.keys())


def _extract_constants(pseudocode: str) -> list[int]:
    """Return distinct unusual numeric constants in encounter order.

    Only hex literals (``0x...``) are considered -- decimal ``42`` in
    the pseudocode is usually a struct offset / array index produced
    by the lifter, not a semantically-meaningful value worth burning
    an LLM call on.
    """
    seen: dict[int, None] = {}
    for m in _HEX_CONST_RE.finditer(pseudocode or ""):
        try:
            val = int(m.group(1), 16)
        except ValueError:
            continue
        if val in _TRIVIAL_CONSTANTS:
            continue
        # Drop values that fit in a byte and look like ASCII -- those
        # are character comparisons, which classify_constant's table
        # layer handles deterministically (no LLM call needed unless
        # the surrounding context flags it).
        if 0 <= val < 0x100 and val in _TRIVIAL_CONSTANTS:
            continue
        seen.setdefault(val, None)
    return list(seen.keys())


def _def_use_slice(pseudocode: str, ident: str, max_lines: int = 8) -> list[str]:
    """Return up to ``max_lines`` lines from ``pseudocode`` that mention
    ``ident``. Order preserved; trimmed at both ends of whitespace."""
    if not pseudocode:
        return []
    needle = re.compile(rf"%?\b{re.escape(ident)}\b")
    out: list[str] = []
    for line in pseudocode.splitlines():
        if needle.search(line):
            stripped = line.strip()
            if stripped:
                out.append(stripped)
            if len(out) >= max_lines:
                break
    return out


def _use_sites_for_string(pseudocode: str, text: str, max_lines: int = 4) -> list[str]:
    """Return pseudocode lines that quote ``text``. Cheap context for #3."""
    if not pseudocode:
        return []
    quoted = f'"{text}"'
    out: list[str] = []
    for line in pseudocode.splitlines():
        if quoted in line:
            stripped = line.strip()
            if stripped:
                out.append(stripped)
            if len(out) >= max_lines:
                break
    return out


def _const_snippet(pseudocode: str, value: int, max_lines: int = 4) -> str:
    """Return a short multi-line snippet around ``value`` for #2 context."""
    if not pseudocode:
        return ""
    needle = f"0x{value:x}"
    out: list[str] = []
    for line in pseudocode.splitlines():
        if needle.lower() in line.lower():
            stripped = line.strip()
            if stripped:
                out.append(stripped)
            if len(out) >= max_lines:
                break
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Result + audit shape
# ---------------------------------------------------------------------------


@dataclass
class Layer0Pair:
    """One (input -> output) Layer-0 decision for the audit log."""

    input: str
    output: str
    source: str  # 'llm' | 'heuristic' | 'table' | 'cache' | 'error'
    confidence: float = 0.0
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "input": self.input,
            "output": self.output,
            "source": self.source,
            "confidence": float(self.confidence),
            "rationale": self.rationale,
        }


@dataclass
class Layer0Result:
    """Populated Layer-0 tables + audit trail.

    The three dict fields are what ``RewriteFunctionArgs`` consumes;
    the per-category audit lists are what the ``--json`` output writes
    out so an operator can see which ``var0`` got renamed to what.
    """

    variable_names: dict[str, str] = field(default_factory=dict)
    string_names: dict[str, str] = field(default_factory=dict)
    constant_labels: dict[str, str] = field(default_factory=dict)
    variables_audit: list[Layer0Pair] = field(default_factory=list)
    strings_audit: list[Layer0Pair] = field(default_factory=list)
    constants_audit: list[Layer0Pair] = field(default_factory=list)
    # Tallies for the operator-facing summary line.
    llm_calls: int = 0
    cache_hits: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "variables": [p.to_dict() for p in self.variables_audit],
            "strings": [p.to_dict() for p in self.strings_audit],
            "constants": [p.to_dict() for p in self.constants_audit],
            "stats": {
                "variables_resolved": len(self.variable_names),
                "strings_resolved": len(self.string_names),
                "constants_resolved": len(self.constant_labels),
                "llm_calls": self.llm_calls,
                "cache_hits": self.cache_hits,
            },
        }


# ---------------------------------------------------------------------------
# A7 cache plumbing -- per-Layer-0-call cache entries keyed on
# (binary_sha, va, kind, input_key, model).
# ---------------------------------------------------------------------------


def _layer0_cache_paths(
    *,
    cache_dir: Optional[Path],
    binary_sha: str,
    va: int,
    kind: str,
    input_key: str,
    model_name: str,
) -> Optional[_cache.CachePaths]:
    """Return cache paths for one Layer-0 call, or None when disabled.

    ``input_key`` is the (already-shortened) identifier that uniquely
    names the call within the (binary, va, kind) namespace -- the
    local-id for variables, a SHA prefix of the string text for
    strings, the decimal value for constants.
    """
    if cache_dir is None:
        return None
    try:
        flags = _cache.canonical_flag_dict(
            [
                ("kind", kind),
                ("input", input_key),
                ("model", model_name),
                ("schema", 1),
            ]
        )
        return _cache.build_paths(
            cache_dir,
            namespace="layer0",
            binary_sha256=binary_sha,
            va=va,
            flags=flags,
            suffix=f".{kind}.json",
        )
    except OSError as exc:
        log.warning("layer0 cache: setup failed (%s); skipping cache", exc)
        return None


def _read_cached(paths: Optional[_cache.CachePaths]) -> Optional[dict[str, Any]]:
    if paths is None:
        return None
    raw = _cache.read_text(paths)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        log.warning("layer0 cache: corrupt entry %s (recomputing)", paths.file)
        return None


def _write_cached(paths: Optional[_cache.CachePaths], payload: dict[str, Any]) -> None:
    if paths is None:
        return
    _cache.write_text(paths, json.dumps(payload, indent=2))


# ---------------------------------------------------------------------------
# Per-category drivers. Each runs one Layer-0 tool against an
# already-populated MemoryContext. Errors are caught + dropped so the
# pre-pass never aborts mid-pipeline.
# ---------------------------------------------------------------------------


def _run_name_local_variable(
    *,
    ctx: Any,
    ident: str,
    def_use_slice: list[str],
    timeout_ms: int,
    use_llm: bool,
    role_hint: str,
) -> Optional[dict[str, Any]]:
    """Run Tool #5 once. Returns dict payload or None on failure."""
    from glaurung.llm.tools.name_local_variable import (
        NameLocalVariableArgs,
        NameLocalVariableTool,
    )

    tool = NameLocalVariableTool()
    try:
        result = tool.run(
            ctx,
            ctx.kb,
            NameLocalVariableArgs(
                current_id=ident,
                recovered_type="int",
                def_use_slice=def_use_slice,
                role_hint=role_hint,  # type: ignore[arg-type]
                use_llm=use_llm,
            ),
        )
    except Exception as exc:  # pragma: no cover - tool internal failure
        log.warning("name_local_variable failed for %s: %s", ident, exc)
        return None
    return {
        "name": result.named.name,
        "confidence": float(result.named.confidence),
        "rationale": result.named.rationale,
        "source": result.source,
    }


def _run_name_string_literal(
    *,
    ctx: Any,
    text: str,
    use_sites: list[str],
    use_llm: bool,
) -> Optional[dict[str, Any]]:
    from glaurung.llm.tools.name_string_literal import (
        NameStringLiteralArgs,
        NameStringLiteralTool,
    )

    tool = NameStringLiteralTool()
    try:
        result = tool.run(
            ctx,
            ctx.kb,
            NameStringLiteralArgs(
                text=text,
                use_sites=use_sites,
                use_llm=use_llm,
            ),
        )
    except Exception as exc:  # pragma: no cover - tool internal failure
        log.warning(
            "name_string_literal failed for %r: %s", text[:32], exc
        )
        return None
    return {
        "name": result.named.symbolic_name,
        "confidence": float(result.named.confidence),
        "rationale": result.named.rationale,
        "source": result.source,
    }


def _run_classify_constant(
    *,
    ctx: Any,
    value: int,
    snippet: str,
    use_llm: bool,
) -> Optional[dict[str, Any]]:
    from glaurung.llm.tools.classify_constant import (
        ClassifyConstantArgs,
        ClassifyConstantTool,
    )

    tool = ClassifyConstantTool()
    try:
        result = tool.run(
            ctx,
            ctx.kb,
            ClassifyConstantArgs(
                value=int(value),
                context_snippet=snippet,
                use_llm=use_llm,
            ),
        )
    except Exception as exc:  # pragma: no cover - tool internal failure
        log.warning("classify_constant failed for %#x: %s", value, exc)
        return None
    return {
        "symbolic": result.label.symbolic,
        "kind": result.label.kind,
        "confidence": float(result.label.confidence),
        "rationale": result.label.rationale,
        "source": result.source,
    }


# ---------------------------------------------------------------------------
# Top-level driver
# ---------------------------------------------------------------------------


def _short_sha(text: str) -> str:
    """Short SHA-256 prefix used as a stable cache key for free-form
    strings (the full literal can be hundreds of bytes long)."""
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def run_layer0_prepass(
    *,
    file_path: str,
    va: int,
    pseudocode: str,
    artifact: Any,
    timeout_ms: int,
    use_llm: bool = True,
    cache_dir_arg: Optional[str] = None,
    max_variables: int = 24,
    max_strings: int = 12,
    max_constants: int = 12,
) -> Layer0Result:
    """Run the three Layer-0 atomic labelers across one function.

    Parameters
    ----------
    file_path: absolute path to the binary
    va: function-entry VA
    pseudocode: pre-fetched decompile output (shared by other stages)
    artifact: triage artifact (already computed by the caller)
    timeout_ms: per-tool LLM timeout
    use_llm: pass-through to each Layer-0 tool; ``False`` forces the
        heuristic fallback path for every call (no API key required)
    cache_dir_arg: ``--cache-dir`` value as passed by the operator;
        ``None`` falls back to ``$GLAURUNG_CACHE_DIR`` then disables
        caching entirely
    max_variables / max_strings / max_constants: bounded fan-out so a
        single very-large function cannot run away with LLM cost

    Returns
    -------
    :class:`Layer0Result` -- the three dicts go straight into
    ``RewriteFunctionArgs``; the audit lists feed ``--json`` output.
    """
    from glaurung.llm.config import LLMConfig
    from glaurung.llm.context import Budgets, MemoryContext

    result = Layer0Result()
    if not pseudocode:
        return result

    # Resolve A7 cache directory + binary SHA for cache keys. Failures
    # silently disable caching; the prepass still runs live.
    cache_dir = _cache.resolve_cache_dir(cache_dir_arg)
    binary_sha = ""
    if cache_dir is not None:
        try:
            binary_sha = _cache.sha256_file(Path(file_path))
        except OSError as exc:
            log.warning("layer0 cache: sha256 failed (%s); disabling cache", exc)
            cache_dir = None

    # Resolve model name for the cache key. We pin it because changing
    # models materially changes the output we cache.
    try:
        model_name = LLMConfig().preferred_model()
    except Exception:  # pragma: no cover - LLM not configured
        model_name = "offline"

    # Build one MemoryContext we reuse across all Layer-0 calls -- the
    # tools take ctx + kb but only the budget timeout actually matters
    # for the heuristic-or-LLM branch they take.
    ctx = MemoryContext(
        file_path=file_path,
        artifact=artifact,
        budgets=Budgets(timeout_ms=max(timeout_ms, 2000)),
    )

    # ---------------------------------------------------------------
    # 1. variable_names via Tool #5
    # ---------------------------------------------------------------
    locals_ids = _extract_locals(pseudocode)[:max_variables]
    for ident in locals_ids:
        slice_lines = _def_use_slice(pseudocode, ident)
        # Cache key: the identifier is already short + stable
        cp = _layer0_cache_paths(
            cache_dir=cache_dir,
            binary_sha=binary_sha,
            va=va,
            kind="var",
            input_key=ident,
            model_name=model_name,
        )
        cached = _read_cached(cp)
        if cached is not None:
            result.cache_hits += 1
            name = str(cached.get("name") or ident)
            conf = float(cached.get("confidence") or 0.0)
            # Skip cached identity / low-confidence results. The fresh
            # LLM path further down already skips identity (line ~562);
            # the cache path needs the same guard or every prior failed
            # session's "couldn't name -- echoed ident" result leaks
            # forward forever. Treat conf < 0.30 OR identity as junk and
            # re-run the LLM. This is what poisoned the AfdConnect run
            # on 2026-05-26.
            if name == ident or conf < 0.30:
                result.variables_audit.append(
                    Layer0Pair(
                        input=ident,
                        output=name,
                        source="cache_skipped",
                        confidence=conf,
                        rationale=str(cached.get("rationale") or "")
                        + " | cache-hit skipped: identity-or-low-confidence",
                    )
                )
                # Don't `continue` -- fall through so the fresh LLM
                # call below recomputes and re-caches.
            else:
                result.variable_names[ident] = name
                result.variables_audit.append(
                    Layer0Pair(
                        input=ident,
                        output=name,
                        source="cache",
                        confidence=conf,
                        rationale=str(cached.get("rationale") or ""),
                    )
                )
                continue

        # Cheap role hint: arg* -> 'parameter', everything else local.
        role_hint = "parameter" if ident.startswith("arg") else "local"
        payload = _run_name_local_variable(
            ctx=ctx,
            ident=ident,
            def_use_slice=slice_lines,
            timeout_ms=timeout_ms,
            use_llm=use_llm,
            role_hint=role_hint,
        )
        if payload is None:
            result.variables_audit.append(
                Layer0Pair(
                    input=ident, output=ident, source="error",
                    rationale="tool execution failed",
                )
            )
            continue
        if payload.get("source") == "llm":
            result.llm_calls += 1
        name = str(payload.get("name") or ident)
        # Skip when the heuristic just echoed the original id; nothing
        # gained by writing 'var0 -> var0' into the substitution table.
        if name == ident:
            result.variables_audit.append(
                Layer0Pair(
                    input=ident, output=name,
                    source=str(payload.get("source") or "heuristic"),
                    confidence=float(payload.get("confidence") or 0.0),
                    rationale=str(payload.get("rationale") or ""),
                )
            )
            _write_cached(cp, payload)
            continue
        result.variable_names[ident] = name
        result.variables_audit.append(
            Layer0Pair(
                input=ident, output=name,
                source=str(payload.get("source") or "heuristic"),
                confidence=float(payload.get("confidence") or 0.0),
                rationale=str(payload.get("rationale") or ""),
            )
        )
        _write_cached(cp, payload)

    # ---------------------------------------------------------------
    # 2. string_names via Tool #3
    # ---------------------------------------------------------------
    strings = _extract_strings(pseudocode)[:max_strings]
    for text in strings:
        use_sites = _use_sites_for_string(pseudocode, text)
        cp = _layer0_cache_paths(
            cache_dir=cache_dir,
            binary_sha=binary_sha,
            va=va,
            kind="str",
            input_key=_short_sha(text),
            model_name=model_name,
        )
        cached = _read_cached(cp)
        if cached is not None:
            result.cache_hits += 1
            name = str(cached.get("name") or "")
            conf = float(cached.get("confidence") or 0.0)
            # Same cache-poison guard as the variables path (iter 3 on
            # 2026-05-26). Empty / identity / low-confidence cached
            # results force a fresh LLM call.
            if not name or conf < 0.30:
                result.strings_audit.append(
                    Layer0Pair(
                        input=text, output=name, source="cache_skipped",
                        confidence=conf,
                        rationale=str(cached.get("rationale") or "")
                        + " | cache-hit skipped: empty-or-low-confidence",
                    )
                )
                # Fall through to fresh LLM call below.
            else:
                result.string_names[text] = name
                result.strings_audit.append(
                    Layer0Pair(
                        input=text, output=name, source="cache",
                        confidence=conf,
                        rationale=str(cached.get("rationale") or ""),
                    )
                )
                continue

        payload = _run_name_string_literal(
            ctx=ctx, text=text, use_sites=use_sites, use_llm=use_llm,
        )
        if payload is None:
            result.strings_audit.append(
                Layer0Pair(
                    input=text, output="", source="error",
                    rationale="tool execution failed",
                )
            )
            continue
        if payload.get("source") == "llm":
            result.llm_calls += 1
        name = str(payload.get("name") or "")
        if name:
            result.string_names[text] = name
        result.strings_audit.append(
            Layer0Pair(
                input=text, output=name,
                source=str(payload.get("source") or "heuristic"),
                confidence=float(payload.get("confidence") or 0.0),
                rationale=str(payload.get("rationale") or ""),
            )
        )
        _write_cached(cp, payload)

    # ---------------------------------------------------------------
    # 3. constant_labels via Tool #2
    # ---------------------------------------------------------------
    constants = _extract_constants(pseudocode)[:max_constants]
    for val in constants:
        snippet = _const_snippet(pseudocode, val)
        cp = _layer0_cache_paths(
            cache_dir=cache_dir,
            binary_sha=binary_sha,
            va=va,
            kind="const",
            input_key=f"{val:x}",
            model_name=model_name,
        )
        cached = _read_cached(cp)
        if cached is not None:
            result.cache_hits += 1
            symbolic = str(cached.get("symbolic") or "")
            const_key = f"0x{val:x}"
            conf = float(cached.get("confidence") or 0.0)
            # Same cache-poison guard as the variables and strings
            # paths. Empty / identity / low-confidence cached results
            # force a fresh LLM call.
            if not symbolic or symbolic == const_key or conf < 0.30:
                result.constants_audit.append(
                    Layer0Pair(
                        input=const_key, output=symbolic, source="cache_skipped",
                        confidence=conf,
                        rationale=str(cached.get("rationale") or "")
                        + " | cache-hit skipped: empty-identity-or-low-confidence",
                    )
                )
                # Fall through to fresh LLM call below.
            else:
                result.constant_labels[const_key] = symbolic
                result.constants_audit.append(
                    Layer0Pair(
                        input=const_key, output=symbolic, source="cache",
                        confidence=conf,
                        rationale=str(cached.get("rationale") or ""),
                    )
                )
                continue

        payload = _run_classify_constant(
            ctx=ctx, value=val, snippet=snippet, use_llm=use_llm,
        )
        if payload is None:
            result.constants_audit.append(
                Layer0Pair(
                    input=f"0x{val:x}", output="", source="error",
                    rationale="tool execution failed",
                )
            )
            continue
        if payload.get("source") == "llm":
            result.llm_calls += 1
        symbolic = str(payload.get("symbolic") or "")
        const_key = f"0x{val:x}"
        if symbolic and symbolic != const_key:
            result.constant_labels[const_key] = symbolic
        result.constants_audit.append(
            Layer0Pair(
                input=const_key, output=symbolic,
                source=str(payload.get("source") or "heuristic"),
                confidence=float(payload.get("confidence") or 0.0),
                rationale=str(payload.get("rationale") or ""),
            )
        )
        _write_cached(cp, payload)

    return result
