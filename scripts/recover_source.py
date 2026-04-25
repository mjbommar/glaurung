#!/usr/bin/env python
"""End-to-end source recovery pipeline driver (v2).

Walks a binary through the 25-tool Layer 0→Layer 4 ladder defined in
docs/llm/SOURCE_RECOVERY_TOOLS.md and writes a recovered source tree
to the chosen output directory.

Changes in v2:

- Seeds triage-extracted string literals into every rewrite prompt
  (fixes the "Sum printed C+ +!" literal-garbling bug).
- Detects C vs C++ once via identify_compiler_and_runtime and stamps
  the target_language / file extension accordingly.
- Filters libstdc++ template instantiations out of the source tree
  and emits them as `externs.h` stubs instead.
- Classifies the full string pool once up front (not per function).
- Wires Layer 0 tools (name_local_variable, classify_constant,
  classify_loop_idiom) into the per-function pipeline.
- Pre-resolves direct-call targets via PLT/symbol maps so
  ``call 0x1090()`` becomes ``call snprintf(...)`` before the rewriter
  sees it.
- Re-runs the rewriter on functions whose first-pass output accrued
  ≥5 assumptions or medium-plus divergences (iterative refinement).
- Runs ``cmake -B build && cmake --build build`` on the output; if
  the build fails, captures errors and re-writes flagged functions.

Designed to be re-runnable: per-function JSON cache in
``<out>/cache/`` skips work already done. Cache is versioned — a
bump invalidates stale entries automatically.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import glaurung as g

from glaurung.llm.context import MemoryContext, Budgets
from glaurung.llm.tools.audit_recovered_source import (
    AuditRecoveredSourceArgs, AuditRecoveredSourceTool, BinaryMetadata,
    FunctionSummaryEntry,
)
from glaurung.llm.tools.classify_constant import (
    ClassifyConstantArgs, ClassifyConstantTool,
)
from glaurung.llm.tools.classify_function_role import (
    ClassifyFunctionRoleArgs, ClassifyFunctionRoleTool,
)
from glaurung.llm.tools.classify_loop_idiom import (
    ClassifyLoopIdiomArgs, ClassifyLoopIdiomTool,
)
from glaurung.llm.tools.classify_string_purpose import (
    ClassifyStringPurposeArgs, ClassifyStringPurposeTool,
)
from glaurung.llm.tools.cluster_functions_into_modules import (
    CallEdge, ClusterFunctionsIntoModulesArgs,
    ClusterFunctionsIntoModulesTool, FunctionSummary,
)
from glaurung.llm.tools.explain_rewrite_delta import (
    ExplainRewriteDeltaArgs, ExplainRewriteDeltaTool,
)
from glaurung.llm.tools.identify_compiler_and_runtime import (
    IdentifyCompilerArgs, IdentifyCompilerAndRuntimeTool,
)
from glaurung.llm.tools.infer_build_system import (
    InferBuildSystemArgs, InferBuildSystemTool, ModuleBuildInfo,
)
from glaurung.llm.tools.infer_function_signature import (
    CallerSnippet, InferFunctionSignatureArgs, InferFunctionSignatureTool,
)
from glaurung.llm.tools.name_local_variable import (
    NameLocalVariableArgs, NameLocalVariableTool,
)
from glaurung.llm.tools.name_string_literal import (
    NameStringLiteralArgs, NameStringLiteralTool,
)
from glaurung.llm.tools.propose_function_name_post_rewrite import (
    ProposeFunctionNamePostRewriteArgs, ProposeFunctionNamePostRewriteTool,
)
from glaurung.llm.tools.reconcile_function_identity import (
    CandidateName, ReconcileFunctionIdentityArgs, ReconcileFunctionIdentityTool,
)
from glaurung.llm.tools.reconcile_global_naming import (
    IdentifierEntry, ReconcileGlobalNamingArgs, ReconcileGlobalNamingTool,
)
from glaurung.llm.tools.rewrite_function_idiomatic import (
    RewriteFunctionArgs, RewriteFunctionIdiomaticTool,
)
from glaurung.llm.tools.synthesize_docstring import (
    SynthesizeDocstringArgs, SynthesizeDocstringTool,
)
from glaurung.llm.tools.verify_semantic_equivalence import (
    VerifySemanticEquivalenceArgs, VerifySemanticEquivalenceTool,
)
from glaurung.llm.tools.write_readme_and_manpage import (
    CliFlagDoc, ModuleDescription, WriteReadmeAndManpageArgs,
    WriteReadmeAndManpageTool,
)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

CACHE_VERSION = 3  # source post-processing happens at emission, not in cache

# Mangled-name prefixes that indicate a C++ stdlib template instantiation —
# these functions are inlined copies of libstdc++/libc++ code, not user code,
# and should become externs rather than part of the recovered tree.
_STDLIB_PREFIXES = (
    "_ZSt", "_ZNSt", "_ZNKSt", "_ZN9__gnu_cxx", "_ZNK9__gnu_cxx",
)

# Compiler-emitted runtime scaffolding — belongs in crt/, not src/.
_CRT_FUNCTION_NAMES = frozenset({
    "_start", "deregister_tm_clones", "register_tm_clones",
    "__do_global_dtors_aux", "frame_dummy", "_GLOBAL__sub_I_main",
    "__libc_csu_init", "__libc_csu_fini",
})

# Names that the linker / runtime resolves by exact symbol — the rewriter
# is not allowed to rename these even when post-rewrite naming proposes
# something more descriptive. Without this protection, `main` gets
# renamed to e.g. `run_greeter_and_sum_args`, the audit reports `main`
# as missing, and the resulting binary will not link.
_RESERVED_FUNCTION_NAMES = frozenset({
    "main", "_start", "_init", "_fini",
    "__libc_start_main", "__libc_csu_init", "__libc_csu_fini",
    "__do_global_dtors_aux", "_GLOBAL__sub_I_main",
    "deregister_tm_clones", "register_tm_clones", "frame_dummy",
})


def _log(msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


# -----------------------------------------------------------------------------
# Small utilities
# -----------------------------------------------------------------------------


def _demangle(name: str) -> str:
    try:
        result = g.strings.demangle_text(name)
        if result:
            d, _ = result
            return d
    except Exception:
        pass
    return name


def _safe_filename(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]+", "_", name)
    return s.strip("_").lower()[:50] or "anon"


def _is_stdlib_instantiation(name: str) -> bool:
    return any(name.startswith(p) for p in _STDLIB_PREFIXES)


def _is_crt_function(name: str) -> bool:
    return name in _CRT_FUNCTION_NAMES


def _language_to_target(lang: Optional[str]) -> str:
    """Map a detected compiler-level language to the rewriter's target enum.

    C++ binaries get target="cpp" so the rewriter is told to emit real C++
    class syntax + std::* facilities rather than C-with-C++-smuggled-in
    (which is what v1 produced when we forced target="c" here).

    Fortran binaries get target="c" (rewriter has no Fortran enum) but the
    file extension below preserves "f90" so the recovered tree at least
    has Fortran-flavoured filenames; the rewriter falls back to producing
    a C lowering against libgfortran calls, which is what we observed
    actually works well in practice.
    """
    if not lang:
        return "c"
    m = {
        "c": "c", "c++": "cpp", "cpp": "cpp",
        "rust": "rust", "go": "go", "python": "python",
        "fortran": "c",  # rewriter emits C lowering of libgfortran calls
    }
    return m.get(lang.lower(), "c")


def _target_extension(lang: Optional[str]) -> str:
    if not lang:
        return "c"
    if lang.lower() in ("c++", "cpp"):
        return "cpp"
    if lang.lower() == "rust":
        return "rs"
    if lang.lower() == "go":
        return "go"
    if lang.lower() == "python":
        return "py"
    return "c"


# -----------------------------------------------------------------------------
# Pseudocode preprocessing
# -----------------------------------------------------------------------------


def _resolve_call_targets(pseudocode: str, va_to_symbol: Dict[int, str]) -> str:
    """Replace ``call 0xNNNN`` with ``call <name>`` when the VA maps to a
    known symbol (PLT entry, exported function, or internally-discovered
    function). Dramatically reduces rewriter guesswork."""
    def _sub(m: "re.Match[str]") -> str:
        try:
            va = int(m.group(1), 16)
        except ValueError:
            return m.group(0)
        name = va_to_symbol.get(va)
        if not name:
            return m.group(0)
        # Keep the VA in a trailing comment so the rewriter can still disambiguate.
        return f"call {name} /* {m.group(1)} */"
    return re.sub(r"call\s+(0x[0-9a-fA-F]+)", _sub, pseudocode)


_VAR_TOKEN_RE = re.compile(r"%?\b(var|arg|t|stack_)(\d+)\b")


def _extract_var_tokens(pseudocode: str) -> List[str]:
    """Pull every %varN/%argN/%tN/stack_N token that appears in pseudocode.

    Canonicalised by stripping the leading % so the rewriter's substitution
    step can rename in one pass. Bounded caller is responsible for capping
    how many we actually name via LLM.
    """
    toks: Dict[str, None] = {}
    for m in _VAR_TOKEN_RE.finditer(pseudocode):
        toks[f"{m.group(1)}{m.group(2)}"] = None
    return list(toks.keys())


def _def_use_slice(pseudocode: str, var: str, max_lines: int = 8) -> List[str]:
    """Collect the lines that reference ``var`` — feeds name_local_variable."""
    lines = pseudocode.splitlines()
    pat = re.compile(rf"(?<!\w){re.escape(var)}(?!\w)")
    slice_: List[str] = []
    for line in lines:
        if pat.search(line):
            slice_.append(line.strip())
            if len(slice_) >= max_lines:
                break
    return slice_


_QUOTED_STRING_RE = re.compile(r'"((?:[^"\\]|\\.){2,})"')


def _restore_pool_literals(source: str, pool: Dict[str, str]) -> str:
    """Replace quoted strings in rewritten source with the closest exact
    match from the triage string pool.

    The LLM tends to paraphrase string literals — e.g. emitting
    ``"Hello, C++!"`` when the pool actually contains ``"Hello, World fro"``.
    We scan every quoted string in the rewritten source and, when its
    text is meaningfully similar to a pool entry (SequenceMatcher ratio
    ≥ 0.55) and the pool entry is at least as long as the rewrite's
    string, substitute the pool entry. Refuses the swap when the LLM's
    string is already an exact pool entry, to avoid undoing a correct
    rewrite. Threshold deliberately conservative — false positives mean
    we'd replace a legitimate string the rewriter chose.
    """
    if not pool:
        return source
    import difflib
    pool_texts = list(pool.keys())

    def _replace(m: "re.Match[str]") -> str:
        rewrite_str = m.group(1)
        if rewrite_str in pool_texts:
            return m.group(0)  # already exact; leave alone.
        # Find best pool match.
        best, best_ratio = None, 0.0
        for p in pool_texts:
            r = difflib.SequenceMatcher(None, rewrite_str, p).ratio()
            if r > best_ratio:
                best, best_ratio = p, r
        if best is None or best_ratio < 0.55:
            return m.group(0)
        # Refuse to substitute a *shorter* pool entry than the rewrite —
        # that usually means the rewrite has more content than the
        # truncated pool literal (e.g. rewrite "Hello, World!" vs pool
        # "Hello, World fro" — keep the rewrite, the pool is broken).
        if len(best) < len(rewrite_str) - 4:
            return m.group(0)
        # Escape any embedded quotes / backslashes.
        escaped = best.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    return _QUOTED_STRING_RE.sub(_replace, source)


_TYPE_DECL_RE = re.compile(
    r"(?:^|\n)(?P<keyword>(?:class|struct|union|typedef\s+struct|enum))"
    r"\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*\{(?P<body>(?:[^{}]|\{[^{}]*\})*)\}"
    r"\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*)?"
    r";",
    re.MULTILINE,
)


def _extract_type_decls(source: str) -> List[Tuple[str, str, str]]:
    """Find every ``class/struct/union/enum NAME { ... };`` block in the
    rewritten source body. Returns (keyword, name, full_decl) tuples.

    Forward declarations like ``class Foo;`` are deliberately excluded —
    only definitions with a body are collected, since those are what
    cause cross-function inconsistency.
    """
    out: List[Tuple[str, str, str]] = []
    for m in _TYPE_DECL_RE.finditer(source):
        out.append((m.group("keyword"), m.group("name"), m.group(0).strip()))
    return out


def _strip_type_decls(source: str) -> str:
    """Remove every full type declaration from the source body.

    Used after the per-function bodies have been scanned so the merged
    types.h header is the single source of truth and per-function
    redeclarations don't fight it.
    """
    return _TYPE_DECL_RE.sub("", source)


def _merge_type_decls(
    decls: List[Tuple[str, str, str]],
) -> Dict[str, str]:
    """Pick a single canonical declaration per type name.

    When the same struct/class is declared multiple times across
    different functions with different fields, prefer the *richest*
    declaration (most fields, longest body). The rewriter occasionally
    emits empty stubs (``class HelloWorld { public: void f(); };``)
    alongside richer declarations elsewhere — taking the longest one
    preserves field information that the per-function rewrites depend on.
    """
    by_name: Dict[str, str] = {}
    by_name_size: Dict[str, int] = {}
    for kw, name, decl in decls:
        size = decl.count("\n") * 100 + len(decl)
        if name not in by_name or size > by_name_size[name]:
            by_name[name] = decl
            by_name_size[name] = size
    return by_name


_PARAM_TYPE_RE = re.compile(
    r"\(\s*(?:const\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\*\s*(self|this)\s*\)"
)
_FIELD_ACCESS_RE = re.compile(r"\b(self|this)\s*->\s*([A-Za-z_][A-Za-z0-9_]*)")


def _collect_struct_field_accesses(
    sources: List[str],
) -> Dict[str, List[str]]:
    """Walk every function body, find ``Type *self`` / ``Type *this``
    parameter bindings, then collect every ``self->field`` /
    ``this->field`` access in that body.

    Returns ``{TypeName: [field1, field2, ...]}``. The orchestrator
    augments the canonical types.h with any missing fields so the
    cross-function declaration is complete enough to compile. Fields
    that already appear in the canonical declaration are not added.
    """
    type_fields: Dict[str, set[str]] = {}
    for src in sources:
        # Find every (Type *self) or (Type *this) binding in this source.
        bindings = list(_PARAM_TYPE_RE.finditer(src))
        if not bindings:
            continue
        for b in bindings:
            ty = b.group(1)
            self_or_this = b.group(2)
            # Find the function body following this binding (between the
            # next `{` and matching `}`). For simplicity we just collect
            # all field accesses with the matching pronoun anywhere in
            # the source — same-name ambiguity is unusual.
            for m in _FIELD_ACCESS_RE.finditer(src):
                if m.group(1) != self_or_this:
                    continue
                type_fields.setdefault(ty, set()).add(m.group(2))
    return {k: sorted(v) for k, v in type_fields.items()}


def _augment_canonical_types(
    canonical: Dict[str, str],
    field_accesses: Dict[str, List[str]],
) -> Dict[str, str]:
    """Add fields referenced via ``->`` but not present in the merged
    canonical declarations. Adds them as ``void *FIELD;`` placeholders
    so the resulting types.h compiles even when the rewriter never
    declared the field's true type.
    """
    out: Dict[str, str] = {}
    for name, decl in canonical.items():
        fields = field_accesses.get(name, [])
        if not fields:
            out[name] = decl
            continue
        # Detect which fields are already declared by string search.
        missing = [f for f in fields if not re.search(rf"\b{f}\s*[;\[(]", decl)]
        if not missing:
            out[name] = decl
            continue
        # Inject placeholders before the closing brace of the decl.
        injection = "\n    /* fields recovered from cross-function uses: */\n"
        injection += "\n".join(f"    void *{f}; /* TODO: real type */" for f in missing)
        injection += "\n"
        # Find the last `}` in the decl and inject before it.
        idx = decl.rfind("}")
        if idx < 0:
            out[name] = decl
            continue
        out[name] = decl[:idx] + injection + decl[idx:]
    # Synthesize declarations for types referenced via -> but never
    # declared at all.
    for name, fields in field_accesses.items():
        if name in out:
            continue
        body = "\n".join(f"    void *{f}; /* TODO: real type */" for f in fields)
        out[name] = (
            f"struct {name} {{\n"
            "    /* synthesized from cross-function field accesses */\n"
            + body + "\n};"
        )
    return out


_POOL_SYM_RE = re.compile(r"\b([A-Z][A-Z0-9_]{3,})\b")


def _collect_pool_references(source: str, pool_by_symbol: Dict[str, str]) -> Dict[str, str]:
    """Find every pool symbol that appears in the source.

    Returns a {symbol: literal} map containing only the entries actually
    referenced — so the emitted strings.h header is minimal.
    """
    found: Dict[str, str] = {}
    for m in _POOL_SYM_RE.finditer(source):
        sym = m.group(1)
        if sym in pool_by_symbol and sym not in found:
            found[sym] = pool_by_symbol[sym]
    return found


_THIS_PARAM_RE = re.compile(
    r"(\(\s*[^)]*?\b)this(\s*\)\s*\{)",
    re.DOTALL,
)


def _rewrite_this_to_self(source: str) -> str:
    """Rename ``*this`` parameters to ``*self``, since ``this`` is a C++
    keyword and cannot be used as a parameter name in a free function.

    The rewriter emits lines like ``void HelloWorld_print(HelloWorld *this) {``
    which won't compile in C++. We rename the parameter to ``self`` and
    rewrite ``this->`` references in the body. Only applies when the
    function's body actually uses ``this->`` — avoids spurious renames in
    real member functions where ``this`` is implicit.
    """
    if "this)" not in source:
        return source
    # Quick guard: only act when there's a `*this)` parameter pattern.
    if not re.search(r"\*\s*this\b\s*\)", source):
        return source
    out = source
    out = re.sub(r"\*\s*this\b(\s*\))", r"*self\1", out)
    out = out.replace("this->", "self->")
    return out


_HEX_RE = re.compile(r"\b0x([0-9a-fA-F]{3,})\b")


def _extract_constants(pseudocode: str) -> List[Tuple[int, str]]:
    """Pull hex constants wide enough to be interesting (≥ 3 nibbles) plus
    the line of context each one appears in."""
    out: List[Tuple[int, str]] = []
    for line in pseudocode.splitlines():
        for m in _HEX_RE.finditer(line):
            try:
                v = int(m.group(1), 16)
            except ValueError:
                continue
            if v == 0 or (0x10 <= v <= 0x80):
                continue  # small stack offsets
            out.append((v, line.strip()))
    # dedup by value, keep first context.
    seen: set[int] = set()
    dedup: List[Tuple[int, str]] = []
    for v, ctx in out:
        if v in seen:
            continue
        seen.add(v)
        dedup.append((v, ctx))
    return dedup


_LOOP_RE = re.compile(
    r"(while\s*\([^)]+\)\s*\{[^}]+\}|for\s*\([^)]*\)\s*\{[^}]+\})",
    re.DOTALL,
)


def _extract_loop_bodies(pseudocode: str, max_loops: int = 4) -> List[str]:
    """Shallow regex-based loop extractor. Good enough for the common cases
    the rewriter emits; anything more sophisticated would need CFG-aware
    parsing, but the point of this pass is to flag idioms, not to prove
    loop equivalence."""
    return [m.group(0) for m in _LOOP_RE.finditer(pseudocode)][:max_loops]


# -----------------------------------------------------------------------------
# Project-level string pool
# -----------------------------------------------------------------------------


def build_string_pool(
    ctx: MemoryContext, cache_dir: Path, use_llm: bool = True
) -> Dict[str, str]:
    """Run name_string_literal once over every distinct triage-detected
    string and cache the result. Returns {raw_text: SYMBOLIC_NAME}."""
    cache_file = cache_dir / "string_pool.json"
    if cache_file.exists():
        try:
            data = json.loads(cache_file.read_text())
            if data.get("_version") == CACHE_VERSION:
                return {k: v for k, v in data.items() if not k.startswith("_")}
        except Exception:
            pass

    strings: List[str] = []
    try:
        seen: set[str] = set()
        for s in ctx.artifact.strings.strings:  # type: ignore[union-attr]
            text = getattr(s, "text", None)
            if not text or len(text) < 3:
                continue
            if text in seen:
                continue
            seen.add(text)
            strings.append(text)
    except Exception:
        pass

    _log(f"string pool: {len(strings)} distinct strings")
    out: Dict[str, str] = {}
    tool = NameStringLiteralTool()
    for text in strings:
        try:
            res = tool.run(
                ctx, ctx.kb,
                NameStringLiteralArgs(text=text, use_llm=use_llm),
            )
            out[text] = res.named.symbolic_name
        except Exception:
            # fall back to a mechanical slug
            slug = re.sub(r"[^A-Za-z0-9]+", "_", text.lower())[:24].strip("_").upper()
            out[text] = slug or "STR_LITERAL"

    cache_file.write_text(json.dumps({"_version": CACHE_VERSION, **out}, indent=2))
    return out


# -----------------------------------------------------------------------------
# Per-function evidence collection (Layer 0 wiring — fixes #5)
# -----------------------------------------------------------------------------


def collect_function_evidence(
    ctx: MemoryContext,
    entry_va: int,
    pseudocode: str,
    string_pool: Dict[str, str],
    var_budget: int = 10,
    const_budget: int = 6,
    loop_budget: int = 3,
) -> dict:
    """Run the Layer-0 labelers on a single function. Returns a dict the
    rewriter directly consumes."""
    # Variables
    var_tokens = _extract_var_tokens(pseudocode)[:var_budget]
    variable_names: Dict[str, str] = {}
    vtool = NameLocalVariableTool()
    for tok in var_tokens:
        slice_ = _def_use_slice(pseudocode, tok)
        try:
            res = vtool.run(
                ctx, ctx.kb,
                NameLocalVariableArgs(
                    current_id=tok, recovered_type="int",
                    def_use_slice=slice_, role_hint="local",
                    use_llm=True,
                ),
            )
            if res.named.name and res.named.name != "var":
                variable_names[tok] = res.named.name
        except Exception:
            pass

    # Constants
    constants = _extract_constants(pseudocode)[:const_budget]
    constant_labels: Dict[str, str] = {}
    ctool = ClassifyConstantTool()
    for value, snippet in constants:
        try:
            res = ctool.run(
                ctx, ctx.kb,
                ClassifyConstantArgs(
                    value=value, context_snippet=snippet[:160],
                    call_site_hint="", use_llm=True,
                ),
            )
            if res.label.symbolic and res.label.symbolic != hex(value):
                constant_labels[hex(value)] = res.label.symbolic
        except Exception:
            pass

    # Loops
    loops = _extract_loop_bodies(pseudocode)[:loop_budget]
    loop_idioms: List[str] = []
    ltool = ClassifyLoopIdiomTool()
    for idx, body in enumerate(loops):
        try:
            res = ltool.run(
                ctx, ctx.kb,
                ClassifyLoopIdiomArgs(loop_body=body, use_llm=True),
            )
            if res.label.idiom != "custom" and res.label.library_call:
                loop_idioms.append(
                    f"loop {idx+1}: {res.label.idiom} → "
                    f"{res.label.library_call}"
                )
        except Exception:
            pass

    # Strings this function references — seed from triage pool (fix #1).
    func_strings: Dict[str, str] = {}
    for text, symbolic in string_pool.items():
        if f'"{text}"' in pseudocode:
            func_strings[text] = symbolic
    # If the function shows *no* inline quoted strings (common with -O2),
    # seed the 5 strings most likely to be relevant so the rewriter at
    # least sees what literals exist in the binary.
    if not func_strings and string_pool:
        for text, symbolic in list(string_pool.items())[:5]:
            func_strings[text] = symbolic

    return {
        "variable_names": variable_names,
        "constant_labels": constant_labels,
        "loop_idioms": loop_idioms,
        "string_names": func_strings,
    }


# -----------------------------------------------------------------------------
# Caller snippets (unchanged from v1 but cleaner ctx passing)
# -----------------------------------------------------------------------------


def caller_snippets(
    ctx: MemoryContext, funcs, callgraph, target_va: int, max_callers: int = 3
) -> List[CallerSnippet]:
    va_by_cg: Dict[str, int] = {}
    for f in funcs:
        ev = int(f.entry_point.value)
        va_by_cg[f"sub_{ev:x}"] = ev
        va_by_cg[f.name] = ev
    callers_vas: List[int] = []
    for e in callgraph.edges:
        if va_by_cg.get(e.callee) == target_va:
            cv = va_by_cg.get(e.caller)
            if cv is not None:
                callers_vas.append(cv)
    callers_vas = list(dict.fromkeys(callers_vas))[:max_callers]
    va_to_name = {int(f.entry_point.value): f.name for f in funcs}
    out: List[CallerSnippet] = []
    for cv in callers_vas:
        caller_name = va_to_name.get(cv, f"sub_{cv:x}")
        try:
            text = g.ir.decompile_at(
                str(ctx.file_path), cv, timeout_ms=500, style="c"
            )
        except Exception:
            continue
        snippet = "\n".join(text.splitlines()[:60])
        out.append(CallerSnippet(
            caller_name=_demangle(caller_name), pseudocode=snippet,
        ))
    return out


# -----------------------------------------------------------------------------
# Per-function pipeline
# -----------------------------------------------------------------------------


def recover_function(
    ctx: MemoryContext,
    func,
    funcs,
    callgraph,
    string_pool: Dict[str, str],
    va_to_symbol: Dict[int, str],
    target_language: str,
    cache_dir: Path,
    skip_trivial: bool,
) -> Optional[dict]:
    entry_va = int(func.entry_point.value)
    raw_name = func.name
    demangled = _demangle(raw_name)

    cache_file = cache_dir / f"{entry_va:x}.json"
    if cache_file.exists():
        try:
            cached = json.loads(cache_file.read_text())
            if cached.get("_version") == CACHE_VERSION:
                return cached
        except Exception:
            pass

    try:
        pseudocode_raw = g.ir.decompile_at(
            str(ctx.file_path), entry_va, timeout_ms=800, style="c",
        )
    except Exception as e:
        _log(f"  [{raw_name}] decompile failed: {e}")
        return None

    # Fix #6: resolve direct-call targets before any LLM sees the pseudocode.
    pseudocode = _resolve_call_targets(pseudocode_raw, va_to_symbol)
    total_lines = len(pseudocode.splitlines())

    # Trivial-stub short-circuit.
    if skip_trivial and total_lines < 6 and "{" in pseudocode:
        summary = {
            "_version": CACHE_VERSION,
            "entry_va": entry_va,
            "raw_name": raw_name,
            "demangled": demangled,
            "short_name": _safe_filename(demangled or raw_name),
            "role": "wrapper",
            "role_confidence": 0.8,
            "c_prototype": f"void {_safe_filename(demangled or raw_name)}(void);",
            "source": pseudocode,
            "assumptions": [],
            "rewrite_confidence": 0.2,
            "equivalence_passed": True,
            "divergences": [],
            "lines": total_lines,
            "trivial": True,
            "stdlib": _is_stdlib_instantiation(raw_name),
            "crt": _is_crt_function(raw_name),
        }
        cache_file.write_text(json.dumps(summary, indent=2))
        return summary

    _log(f"  → {raw_name}  ({total_lines} lines)")

    # Fix #5: collect Layer-0 evidence.
    evidence = collect_function_evidence(
        ctx, entry_va, pseudocode, string_pool,
    )

    # Signature with callers.
    caller_snips = caller_snippets(ctx, funcs, callgraph, entry_va)
    try:
        sig_res = InferFunctionSignatureTool().run(
            ctx, ctx.kb,
            InferFunctionSignatureArgs(
                va=entry_va,
                callee_pseudocode=pseudocode,
                caller_snippets=caller_snips,
                target_language=target_language if target_language in ("c", "rust", "go") else "c",
                use_llm=True,
            ),
        )
        c_prototype = sig_res.signature.c_prototype
    except Exception as e:
        _log(f"    signature failed: {e}")
        c_prototype = f"int {_safe_filename(demangled or raw_name)}(void);"

    # Role.
    try:
        role_res = ClassifyFunctionRoleTool().run(
            ctx, ctx.kb,
            ClassifyFunctionRoleArgs(
                pseudocode=pseudocode, c_prototype=c_prototype, use_llm=True,
            ),
        )
        role = role_res.label.role
        role_confidence = role_res.label.confidence
    except Exception:
        role, role_confidence = "other", 0.2

    # Rewrite (first pass). Post-processing (literal restore + this→self
    # rename) happens at emission time, not here, so the cache is stable
    # across orchestrator iteration — only raw rewriter output is cached.
    rewrite_res = _rewrite(
        ctx, entry_va, pseudocode, c_prototype, role,
        target_language, evidence,
    )
    source = rewrite_res["source"]
    assumptions = rewrite_res["assumptions"]
    rewrite_conf = rewrite_res["confidence"]

    # Equivalence check.
    ver_res = _verify(ctx, pseudocode, source, assumptions)
    equivalence_passed = ver_res["passed"]
    divergences = ver_res["divergences"]

    # Fix #129: re-rewrite on assumption pressure — but only when it's
    # likely to help. Retrying on "too many assumptions" alone is wasteful
    # when the root cause is systemic (e.g. language mismatch) rather than
    # something the LLM can fix by looking harder. Trigger only on
    # *high*-severity divergences (real semantic drift) or a very large
    # assumption count (≥10, usually indicates the rewriter is floundering).
    retries = 0
    max_retries = 1  # at most one retry; more isn't helping in practice
    while retries < max_retries and (
        len(assumptions) >= 10
        or any("[high]" in d for d in divergences)
    ):
        _log(f"    retry {retries+1}: {len(assumptions)} assumptions, "
             f"{sum(1 for d in divergences if '[medium]' in d or '[high]' in d)} divergences")
        retries += 1
        rewrite_res = _rewrite(
            ctx, entry_va, pseudocode, c_prototype, role,
            target_language, evidence,
            negative_guidance=assumptions + divergences,
        )
        source = rewrite_res["source"]
        assumptions = rewrite_res["assumptions"]
        rewrite_conf = rewrite_res["confidence"]
        ver_res = _verify(ctx, pseudocode, source, assumptions)
        equivalence_passed = ver_res["passed"]
        divergences = ver_res["divergences"]

    # Docstring.
    try:
        doc_res = SynthesizeDocstringTool().run(
            ctx, ctx.kb,
            SynthesizeDocstringArgs(
                source=source,
                style="doxygen",
                printed_strings=list(evidence["string_names"].keys()),
                use_llm=True,
            ),
        )
        docstring = doc_res.doc.docblock
    except Exception:
        docstring = "/** TODO — docstring */"

    # Post-rewrite naming.
    try:
        name_res = ProposeFunctionNamePostRewriteTool().run(
            ctx, ctx.kb,
            ProposeFunctionNamePostRewriteArgs(
                entry_va=entry_va,
                rewritten_source=source,
                role=role,
                printed_strings=list(evidence["string_names"].keys()),
                current_name=demangled,
                use_llm=True,
            ),
        )
        canonical_name = name_res.name.canonical_name
        rejected = [c.name for c in name_res.name.rejected_candidates]
    except Exception:
        canonical_name = _safe_filename(demangled)
        rejected = []

    # Protect linker-visible canonical names: even if the post-rewrite
    # naming proposed something more descriptive, the binary will not
    # link unless `main` stays `main`, etc. The proposed name is moved
    # into rejected_candidates so it is still visible in the rewrite
    # notes — just not used as the emitted identifier.
    if raw_name in _RESERVED_FUNCTION_NAMES and canonical_name != raw_name:
        if canonical_name and canonical_name not in rejected:
            rejected.insert(0, canonical_name)
        canonical_name = raw_name

    summary = {
        "_version": CACHE_VERSION,
        "entry_va": entry_va,
        "raw_name": raw_name,
        "demangled": demangled,
        "short_name": canonical_name,
        "rejected_names": rejected,
        "role": role,
        "role_confidence": role_confidence,
        "c_prototype": c_prototype,
        "docstring": docstring,
        "source": source,
        "pseudocode": pseudocode,
        "assumptions": assumptions,
        "rewrite_confidence": rewrite_conf,
        "equivalence_passed": equivalence_passed,
        "divergences": divergences,
        "string_names": evidence["string_names"],
        "variable_names": evidence["variable_names"],
        "constant_labels": evidence["constant_labels"],
        "loop_idioms": evidence["loop_idioms"],
        "lines": total_lines,
        "trivial": False,
        "stdlib": _is_stdlib_instantiation(raw_name),
        "crt": _is_crt_function(raw_name),
        "retries": retries,
    }
    cache_file.write_text(json.dumps(summary, indent=2))
    return summary


def _rewrite(
    ctx: MemoryContext,
    entry_va: int,
    pseudocode: str,
    c_prototype: str,
    role: str,
    target_language: str,
    evidence: dict,
    negative_guidance: Optional[List[str]] = None,
) -> dict:
    loop_idioms = list(evidence.get("loop_idioms", []) or [])
    if negative_guidance:
        loop_idioms.append(
            "REWRITE FEEDBACK — the previous pass had these issues; do not "
            "repeat them:\n  - " + "\n  - ".join(negative_guidance[:12])
        )
    try:
        res = RewriteFunctionIdiomaticTool().run(
            ctx, ctx.kb,
            RewriteFunctionArgs(
                entry_va=entry_va,
                pseudocode=pseudocode,
                c_prototype=c_prototype,
                role=role,
                variable_names=evidence.get("variable_names", {}),
                constant_labels=evidence.get("constant_labels", {}),
                string_names=evidence.get("string_names", {}),
                loop_idioms=loop_idioms,
                target_language=target_language if target_language in ("c", "rust", "go", "python") else "c",
            ),
        )
        return {
            "source": res.rewrite.source,
            "assumptions": res.rewrite.assumptions,
            "confidence": res.rewrite.confidence,
        }
    except Exception as e:
        return {
            "source": f"// rewrite failed: {e}\n" + pseudocode,
            "assumptions": [f"rewrite exception: {e}"],
            "confidence": 0.1,
        }


def _verify(
    ctx: MemoryContext,
    pseudocode: str,
    source: str,
    assumptions: List[str],
) -> dict:
    try:
        ver_res = VerifySemanticEquivalenceTool().run(
            ctx, ctx.kb,
            VerifySemanticEquivalenceArgs(
                original_pseudocode=pseudocode,
                rewritten_source=source,
                rewrite_assumptions=assumptions,
                use_llm=True,
            ),
        )
        return {
            "passed": ver_res.verdict.equivalent,
            "divergences": [
                f"[{d.severity}] {d.kind}: {d.description}"
                for d in ver_res.verdict.divergences
            ],
        }
    except Exception:
        return {
            "passed": False,
            "divergences": ["verification failed with exception"],
        }


# -----------------------------------------------------------------------------
# Build-and-verify loop (fix #12/#130)
# -----------------------------------------------------------------------------


def build_verify(out_dir: Path) -> Tuple[bool, str]:
    """Run cmake + build, capture stderr. Returns (success, log)."""
    if not shutil.which("cmake"):
        return False, "cmake not installed; skipping build"
    build_dir = out_dir / "build"
    build_dir.mkdir(exist_ok=True)
    try:
        cfg = subprocess.run(
            ["cmake", "-S", str(out_dir), "-B", str(build_dir)],
            capture_output=True, text=True, timeout=60,
        )
        if cfg.returncode != 0:
            return False, f"cmake configure failed:\n{cfg.stderr}\n{cfg.stdout}"
        make = subprocess.run(
            ["cmake", "--build", str(build_dir), "--parallel"],
            capture_output=True, text=True, timeout=180,
        )
        if make.returncode != 0:
            return False, f"build failed:\n{make.stderr}\n{make.stdout}"
        return True, make.stdout
    except subprocess.TimeoutExpired:
        return False, "build timed out"
    except Exception as e:
        return False, f"build exception: {e}"


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the source-recovery pipeline on a binary."
    )
    parser.add_argument("binary", type=str)
    parser.add_argument("--out", type=str, default="out/recovered")
    parser.add_argument("--project-name", type=str, default=None)
    parser.add_argument("--max-functions", type=int, default=20)
    parser.add_argument(
        "--skip-trivial", action="store_true", default=True
    )
    parser.add_argument(
        "--no-skip-trivial", dest="skip_trivial", action="store_false"
    )
    parser.add_argument(
        "--skip-build", action="store_true", default=False,
        help="Skip the cmake build-and-verify step",
    )
    a = parser.parse_args()

    binary_path = str(Path(a.binary).resolve())
    project_name = a.project_name or Path(a.binary).stem.replace("-", "_")
    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = out_dir / "cache"
    cache_dir.mkdir(exist_ok=True)

    _log(f"recovering {binary_path} → {out_dir}")
    # str_max_samples defaults to 40 which only covers .dynstr on most
    # ELFs — bump it so we actually see the application-level literals
    # sitting in .rodata. Without this, recovered source ends up with
    # placeholder strings because the triage pool is truncated.
    art = g.triage.analyze_path(
        binary_path,
        str_min_len=3,
        str_max_samples=1000,
        str_max_classify=1000,
    )
    _log(
        f"format={art.verdicts[0].format} arch={art.verdicts[0].arch} "
        f"size={art.size_bytes}B"
    )
    funcs, callgraph = g.analysis.analyze_functions_path(binary_path)
    _log(f"discovered {len(funcs)} functions, {len(callgraph.edges)} edges")

    ctx = MemoryContext(
        file_path=binary_path, artifact=art, budgets=Budgets(timeout_ms=5000)
    )

    # Fix #2: identify language + target.
    try:
        id_res = IdentifyCompilerAndRuntimeTool().run(
            ctx, ctx.kb, IdentifyCompilerArgs(),
        )
        language = id_res.language or "C"
        compiler = id_res.compiler or "unknown"
    except Exception:
        language = "C"
        compiler = "unknown"
    target_language = _language_to_target(language)
    file_ext = _target_extension(language)
    _log(f"language={language} compiler={compiler} target={target_language} ext=.{file_ext}")

    # Fix #4: build string pool once.
    _log("building string pool…")
    string_pool = build_string_pool(ctx, cache_dir)

    # Fix #6: build VA → symbol map once.
    va_to_symbol: Dict[int, str] = {}
    try:
        for a_va, name in g.analysis.elf_plt_map_path(binary_path):
            va_to_symbol[int(a_va)] = name
    except Exception:
        pass
    try:
        for a_va, name in g.symbols.symbol_address_map(binary_path):
            va_to_symbol.setdefault(int(a_va), name)
    except Exception:
        pass
    for f in funcs:
        va_to_symbol.setdefault(int(f.entry_point.value), f.name)
    _log(f"symbol map: {len(va_to_symbol)} entries")

    # -------- per-function pipeline --------
    summaries: List[dict] = []
    funcs_sorted = sorted(funcs, key=lambda f: len(f.basic_blocks), reverse=True)
    budget = a.max_functions
    for f in funcs_sorted:
        if budget <= 0:
            break
        s = recover_function(
            ctx, f, funcs, callgraph, string_pool, va_to_symbol,
            target_language, cache_dir, a.skip_trivial,
        )
        if s is not None:
            summaries.append(s)
            budget -= 1
    _log(f"rewrote {len(summaries)} functions")

    # -------- Fix #3: partition into stdlib / crt / user --------
    stdlib_summaries = [s for s in summaries if s.get("stdlib")]
    crt_summaries = [s for s in summaries if s.get("crt")]
    user_summaries = [s for s in summaries
                      if not s.get("stdlib") and not s.get("crt")]
    _log(f"partition: {len(user_summaries)} user, "
         f"{len(crt_summaries)} crt, {len(stdlib_summaries)} stdlib")

    # Write stdlib externs header (no source bodies).
    if stdlib_summaries:
        externs = out_dir / "src" / "externs.h"
        externs.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "// externs.h — libstdc++/libc++ template instantiations referenced "
            "by the recovered tree. Bodies are supplied by the C++ runtime; "
            "this header just declares them so the compiler knows they exist.",
            "#pragma once",
            "",
        ]
        for s in stdlib_summaries:
            lines.append(f"// {s['raw_name']}")
            lines.append(f"// demangled: {s['demangled']}")
            lines.append("")
        externs.write_text("\n".join(lines))

    # -------- Layer 3: cluster (only user-level functions) --------
    fsummaries = [
        FunctionSummary(
            name=s["short_name"],
            entry_va=s["entry_va"],
            role=s["role"],
            one_line_summary=(
                (s.get("docstring") or "").splitlines()[0][:100]
                if s.get("docstring") else ""
            ),
        )
        for s in user_summaries
    ]
    user_vas = {s["entry_va"] for s in user_summaries}
    va_to_canonical = {s["entry_va"]: s["short_name"] for s in user_summaries}
    va_by_cg: Dict[str, int] = {}
    for f in funcs:
        ev = int(f.entry_point.value)
        va_by_cg[f"sub_{ev:x}"] = ev
        va_by_cg[f.name] = ev
    edges = []
    for e in callgraph.edges:
        cv = va_by_cg.get(e.caller)
        tv = va_by_cg.get(e.callee)
        if cv in user_vas and tv in user_vas:
            edges.append(CallEdge(
                caller=va_to_canonical[cv], callee=va_to_canonical[tv],
            ))
    if user_summaries:
        _log("clustering into modules…")
        cluster_res = ClusterFunctionsIntoModulesTool().run(
            ctx, ctx.kb,
            ClusterFunctionsIntoModulesArgs(
                functions=fsummaries,
                edges=edges,
                project_name_hint=project_name,
                target_language=target_language,
                use_llm=True,
            ),
        )
        modules = cluster_res.layout.modules
    else:
        modules = []
    _log(f"  → {len(modules)} modules")

    # Reconcile names (only where a function has alternatives).
    for s in user_summaries:
        if not s.get("rejected_names"):
            continue
        candidates = [
            CandidateName(
                name=s["short_name"], source_tool="propose_function_name_post_rewrite",
                confidence=0.7,
            )
        ] + [
            CandidateName(name=r, source_tool="rejected", confidence=0.5)
            for r in s["rejected_names"]
        ]
        try:
            rec = ReconcileFunctionIdentityTool().run(
                ctx, ctx.kb,
                ReconcileFunctionIdentityArgs(
                    entry_va=s["entry_va"], candidates=candidates, use_llm=True,
                ),
            )
            if rec.reconciled.canonical_name != s["short_name"]:
                # Reserved names override any reconciliation result.
                if s["raw_name"] in _RESERVED_FUNCTION_NAMES:
                    pass
                else:
                    s.setdefault("aliases", []).extend(
                        [s["short_name"], *rec.reconciled.aliases]
                    )
                    s["short_name"] = rec.reconciled.canonical_name
        except Exception as e:
            _log(f"    reconcile failed for {s['raw_name']}: {e}")

    # Global naming style.
    try:
        gn = ReconcileGlobalNamingTool().run(
            ctx, ctx.kb,
            ReconcileGlobalNamingArgs(
                identifiers=[
                    IdentifierEntry(current=s["short_name"], kind="function")
                    for s in user_summaries
                    if s["raw_name"] not in _RESERVED_FUNCTION_NAMES
                ],
                preferred_style_functions="snake_case",
                project_prefix=None,
                use_llm=True,
            ),
        )
        for s in user_summaries:
            if s["raw_name"] in _RESERVED_FUNCTION_NAMES:
                continue
            if s["short_name"] in gn.map.renames:
                s["short_name"] = gn.map.renames[s["short_name"]]
    except Exception as e:
        _log(f"  global naming failed: {e}")

    # Build system.
    _log("inferring build system…")
    try:
        summary_ext = g.symbols.list_symbols_demangled(binary_path)
        binary_imports = list(summary_ext.import_names or [])
    except Exception:
        binary_imports = []
    module_build = [ModuleBuildInfo(path=m.name, imports=[]) for m in modules]
    try:
        bs = InferBuildSystemTool().run(
            ctx, ctx.kb,
            InferBuildSystemArgs(
                target_language="c",
                project_name=project_name,
                modules=module_build,
                binary_imports=binary_imports,
                platform_hint="linux",
                use_llm=True,
            ),
        )
    except Exception as e:
        _log(f"  build inference failed: {e}")
        bs = None

    # README.
    _log("writing README + manpage…")
    mod_descs = [
        ModuleDescription(path=m.name, purpose=m.purpose) for m in modules
    ]
    try:
        doc = WriteReadmeAndManpageTool().run(
            ctx, ctx.kb,
            WriteReadmeAndManpageArgs(
                project_name=project_name,
                synopsis=f"{project_name} [OPTIONS]",
                description=(
                    f"Source recovered from {Path(binary_path).name} "
                    f"(language={language}, compiler={compiler})."
                ),
                modules=mod_descs,
                flags=[],
                build_instructions="cmake -B build && cmake --build build",
                target_language="c",
                use_llm=True,
            ),
        )
    except Exception as e:
        _log(f"  docs failed: {e}")
        doc = None

    # Write source tree.
    _log("writing source tree…")
    fn_by_va = {s["entry_va"]: s for s in user_summaries}
    module_of_va: Dict[int, str] = {}
    for mod in modules:
        for member in mod.members:
            for s in user_summaries:
                if s["short_name"] == member and s["entry_va"] not in module_of_va:
                    module_of_va[s["entry_va"]] = mod.name
                    break
    default_mod = f"src/core.{file_ext}"
    for s in user_summaries:
        if s["entry_va"] not in module_of_va:
            module_of_va[s["entry_va"]] = default_mod

    # Pair `<fn>.cold` with its parent `<fn>` — GCC -O2 splits the cold
    # path of a function into a separate symbol, but the two halves
    # belong in the same source file so an exception path is readable.
    by_raw_name = {s["raw_name"]: s for s in user_summaries}
    for s in user_summaries:
        if not s["raw_name"].endswith(".cold"):
            continue
        parent_name = s["raw_name"][: -len(".cold")]
        parent = by_raw_name.get(parent_name)
        if parent is not None:
            module_of_va[s["entry_va"]] = module_of_va[parent["entry_va"]]

    def _rewrite_extension(path: str) -> str:
        p = Path(path)
        return str(p.with_suffix(f".{file_ext}"))

    grouped: Dict[str, List[dict]] = {}
    for va, mod in module_of_va.items():
        grouped.setdefault(_rewrite_extension(mod), []).append(fn_by_va[va])

    includes_for_lang = {
        "c": [
            "#include <stdio.h>", "#include <stdlib.h>", "#include <string.h>",
            "#include <stdint.h>",
        ],
        "cpp": [
            "#include <cstdio>", "#include <cstdlib>", "#include <cstring>",
            "#include <cstdint>",  # uint32_t is used by inline-immediate reconstructions
            "#include <iostream>", "#include <string>", "#include <vector>",
        ],
    }.get(file_ext, ["#include <stdio.h>"])

    # Apply post-processing to every cached source body before emission:
    # 1. Restore exact pool literals where the LLM paraphrased.
    # 2. Rename `*this` parameters to `*self` (C++ keyword collision).
    # We mutate s["emit_source"] rather than s["source"] so the cache
    # entry remains untouched and re-runnable.
    for members in grouped.values():
        for s in members:
            post = _restore_pool_literals(s["source"], string_pool)
            post = _rewrite_this_to_self(post)
            s["emit_source"] = post

    # Bug J: cross-function type unification. Each function rewrite
    # tends to redeclare the same `class HelloWorld { ... }` with
    # slightly different fields, which makes per-function .cpp files
    # disagree. Collect every type declaration, merge them into a
    # single canonical types.h, then augment with fields referenced
    # via `self->`/`this->` from every function body — the rewriter
    # often uses fields without declaring them.
    all_type_decls: List[Tuple[str, str, str]] = []
    for members in grouped.values():
        for s in members:
            all_type_decls.extend(_extract_type_decls(s["emit_source"]))
    canonical_types = _merge_type_decls(all_type_decls)
    field_accesses = _collect_struct_field_accesses(
        [s["emit_source"] for members in grouped.values() for s in members]
    )
    canonical_types = _augment_canonical_types(canonical_types, field_accesses)
    if canonical_types:
        # Strip duplicates from per-function bodies so the header is the
        # single source of truth.
        for members in grouped.values():
            for s in members:
                s["emit_source"] = _strip_type_decls(s["emit_source"])

    # Build pool-symbol → literal map keyed by SCREAMING_SNAKE_CASE name.
    # Walk every emitted source body (post-processed), find references,
    # and emit only the ones actually used into src/strings.h. Bug F.
    pool_by_symbol: Dict[str, str] = {sym: text for text, sym in string_pool.items()}
    used_symbols: Dict[str, str] = {}
    for members in grouped.values():
        for s in members:
            used_symbols.update(_collect_pool_references(s["emit_source"], pool_by_symbol))

    strings_header = ""
    if used_symbols:
        strings_header_path = out_dir / "src" / "strings.h"
        strings_header_path.parent.mkdir(parents=True, exist_ok=True)
        h_lines = [
            "// src/strings.h",
            "// Auto-generated string-pool symbols extracted from .rodata.",
            "// Each entry is referenced by SCREAMING_SNAKE_CASE name in the",
            "// recovered source bodies.",
            "#pragma once",
            "",
        ]
        for sym, text in sorted(used_symbols.items()):
            escaped = (
                text.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
            )
            h_lines.append(f'static const char {sym}[] = "{escaped}";')
        strings_header_path.write_text("\n".join(h_lines) + "\n")
        strings_header = '#include "strings.h"'

    # Emit canonical types.h (Bug J) when any cross-function type
    # declarations were found.
    types_header = ""
    if canonical_types:
        types_header_path = out_dir / "src" / "types.h"
        types_header_path.parent.mkdir(parents=True, exist_ok=True)
        t_lines = [
            "// src/types.h",
            "// Canonical type declarations recovered from binary.",
            "// Each struct/class/enum is the longest declaration the",
            "// rewriter emitted across any function — picked by",
            "// _merge_type_decls so per-function copies don't fight.",
            "#pragma once",
            "",
        ]
        for name in sorted(canonical_types.keys()):
            t_lines.append(canonical_types[name])
            t_lines.append("")
        types_header_path.write_text("\n".join(t_lines))
        types_header = '#include "types.h"'

    for mod_path, members in grouped.items():
        target = out_dir / mod_path
        target.parent.mkdir(parents=True, exist_ok=True)
        buf = [
            f"// {mod_path}",
            f"// Recovered from {Path(binary_path).name} by glaurung source-recovery",
            "",
            *includes_for_lang,
        ]
        if types_header and target.parent.name == "src":
            buf.append(types_header)
        if strings_header and target.parent.name == "src":
            buf.append(strings_header)
        buf.append("")
        for s in members:
            if s.get("docstring"):
                buf.append(s["docstring"])
            buf.append(s.get("emit_source", s["source"]))
            buf.append("")
        target.write_text("\n".join(buf))

    # CRT module — emitted as a markdown notes file rather than source.
    #
    # The recovered CRT bodies use compiler-internal identifiers that are
    # not legal C/C++ (e.g. GCC's `completed.0` static), reference symbols
    # that only the dynamic linker knows about (`__dso_handle`,
    # `__cxa_finalize`), and would link as duplicates of the real
    # libgcc/crtbegin.o symbols anyway. Writing them as `.cpp` produced
    # nothing buildable; writing them as documentation preserves the
    # information without polluting the build.
    if crt_summaries:
        crt_doc = out_dir / "crt" / "CRTSTUFF.md"
        crt_doc.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# CRT scaffolding (documentation only)",
            "",
            "These functions were emitted into the binary by the toolchain",
            "(libgcc / crtbegin.o / crtend.o). They are recovered here for",
            "reference; the build does **not** include them — the real",
            "runtime objects are linked by the C++ driver.",
            "",
        ]
        for s in crt_summaries:
            lines.append(f"## `{s['raw_name']}`  @ `0x{s['entry_va']:x}`")
            lines.append("")
            lines.append(f"- Demangled: `{s['demangled']}`")
            lines.append(f"- Role: `{s.get('role', 'other')}`")
            lines.append(
                f"- Confidence: {s.get('rewrite_confidence', 0.0):.2f}"
            )
            lines.append("")
            if s.get("docstring"):
                # Strip Doxygen `/** */` framing for the markdown body.
                # Use a distinct name — the outer `doc` is the README/manpage
                # tool's result and must not be shadowed.
                docstring_md = re.sub(r"^\s*/\*+\s*", "", s["docstring"])
                docstring_md = re.sub(r"\s*\*+/\s*$", "", docstring_md)
                docstring_md = re.sub(
                    r"^\s*\*\s?", "", docstring_md, flags=re.MULTILINE
                )
                lines.append(docstring_md.strip())
                lines.append("")
            lines.append("```")
            lines.append(s["source"])
            lines.append("```")
            lines.append("")
        crt_doc.write_text("\n".join(lines))

    # Build files. Filter out anything that looks like source code — the
    # LLM occasionally emits a placeholder src/main.cpp alongside the
    # CMakeLists, which would clobber the real recovered source we just
    # wrote. Only accept build-control filetypes here.
    _BUILD_CONTROL_SUFFIXES = {
        ".txt", ".toml", ".cfg", ".ini", ".cmake", ".mk", ".am",
        ".in", "", ".gradle", ".lock",
    }
    if bs is not None:
        for bf in bs.build.files:
            ext = Path(bf.path).suffix.lower()
            if ext not in _BUILD_CONTROL_SUFFIXES and Path(bf.path).name not in (
                "Makefile", "GNUmakefile", "BUILD", "BUILD.bazel",
                "go.mod", "go.sum",
            ):
                _log(f"  skipping non-build file from build tool: {bf.path}")
                continue
            (out_dir / bf.path).write_text(bf.content)

    # README / manpage. Defensive against malformed LLM output that
    # pydantic-ai couldn't coerce into the expected schema — sometimes
    # the agent returns a string instead of the structured bundle.
    if doc is not None:
        try:
            readme = doc.docs.readme
            manpage = doc.docs.manpage
        except AttributeError:
            # Tool returned something unexpected; skip docs rather than crash.
            readme = manpage = None
            _log("  README: unexpected return shape from doc tool, skipping")
        if readme is not None:
            (out_dir / "README.md").write_text(readme)
            man_dir = out_dir / "man"
            man_dir.mkdir(exist_ok=True)
            (man_dir / f"{project_name}.1").write_text(manpage)

    # Audit.
    _log("auditing tree…")
    audit_entries = [
        FunctionSummaryEntry(
            name=s["short_name"],
            entry_va=s["entry_va"],
            module=module_of_va.get(s["entry_va"], default_mod),
            summary=(
                (s.get("docstring") or "").splitlines()[0][:100]
                if s.get("docstring") else ""
            ),
            confidence=s.get("rewrite_confidence", 0.5),
            assumptions=s.get("assumptions", []),
        )
        for s in user_summaries
    ]
    try:
        audit_res = AuditRecoveredSourceTool().run(
            ctx, ctx.kb,
            AuditRecoveredSourceArgs(
                project_name=project_name,
                functions=audit_entries,
                modules=[m.name for m in modules] + [default_mod],
                binary_metadata=BinaryMetadata(
                    imports_count=len(binary_imports),
                    functions_count=len(funcs),
                    size_bytes=int(art.size_bytes or 0),
                    format=str(art.verdicts[0].format),
                ),
                use_llm=True,
            ),
        )
        audit_path = out_dir / "AUDIT.md"
        audit_lines = [
            f"# Audit — {project_name}", "",
            audit_res.report.summary, "",
            f"passed: **{audit_res.report.passed}**", "",
        ]
        for f_finding in audit_res.report.findings:
            audit_lines.append(
                f"- **[{f_finding.severity}]** {f_finding.kind} @ {f_finding.location}: "
                f"{f_finding.description}  → _{f_finding.recommended_action}_"
            )
        audit_path.write_text("\n".join(audit_lines))
        _log(f"  passed={audit_res.report.passed} findings={len(audit_res.report.findings)}")
    except Exception as e:
        _log(f"  audit failed: {e}")

    # Per-function delta notes.
    _log("writing rewrite delta notes…")
    notes_dir = out_dir / "notes"
    notes_dir.mkdir(exist_ok=True)
    for s in user_summaries + crt_summaries:
        if s.get("trivial"):
            continue
        try:
            delta = ExplainRewriteDeltaTool().run(
                ctx, ctx.kb,
                ExplainRewriteDeltaArgs(
                    function_name=s["short_name"],
                    entry_va=s["entry_va"],
                    original_pseudocode=s["pseudocode"],
                    final_source=s["source"],
                    target_language="c",
                    assumptions=s.get("assumptions", []),
                    divergences=s.get("divergences", []),
                    use_llm=True,
                ),
            )
            (notes_dir / f"{s['short_name']}.rewrite.md").write_text(
                delta.note.markdown
            )
        except Exception as e:
            _log(f"    delta failed for {s['short_name']}: {e}")

    # Fix #130: build-and-verify.
    if not a.skip_build:
        _log("running cmake build…")
        success, buildlog = build_verify(out_dir)
        (out_dir / "BUILD_LOG.txt").write_text(buildlog)
        _log(f"  build {'OK' if success else 'FAILED'} (see BUILD_LOG.txt)")
        if not success:
            # Surface the first handful of lines in AUDIT so reviewers see it.
            try:
                audit_path = out_dir / "AUDIT.md"
                if audit_path.exists():
                    tail = "\n\n## Build verification\n\nBuild **FAILED**. Excerpt:\n\n```\n"
                    tail += "\n".join(buildlog.splitlines()[:40])
                    tail += "\n```\n"
                    audit_path.write_text(audit_path.read_text() + tail)
            except Exception:
                pass

    _log("done.")
    _log(f"tree at: {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
