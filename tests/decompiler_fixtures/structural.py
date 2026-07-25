"""Static structural analysis of decompiler output for the structural lane.

Some correctness properties cannot be checked by executing the recompiled C
(the execution gate in ``diff_decompile.py``): switch discriminants/case values,
indirect-call targets, intrinsic/volatile memory effects, unresolved local
gotos, and — for C++ — vtable calls and exception-cleanup regions. Those live in
functions the manifest marks ``skip_exec`` or in render styles that are never
recompiled. This module decompiles a fixture ONCE per render style and exposes
cheap textual predicates the structural lane asserts against a committed
baseline (so known-broken output stays visible while regressions fail closed).

The one hard, non-baselined invariant is *control-flow closure*: every
``goto LABEL;`` must have a matching ``LABEL:`` and braces must balance. A
decompilation that emits a jump to a label it never defines is not valid C and
cannot be reasoned about — that is a structural bug regardless of execution.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

STYLES = ("plain", "c", "decbench")

# `plain`/`c`:  function NAME @ 0xVA {      decbench:  // glaurung: NAME @ 0xVA
_HDR = re.compile(
    r"(?m)^(?:// glaurung: (?P<a>\S+) @ 0x[0-9a-fA-F]+\s*$"
    r"|function (?P<b>\S+) @ 0x[0-9a-fA-F]+ \{)"
)
_GOTO = re.compile(r"\bgoto\s+([A-Za-z_]\w*)\s*;")
_LABEL = re.compile(r"(?m)^\s*([A-Za-z_]\w*)\s*:(?!:)")


def decompile_all(so: str | Path, style: str, timeout: int = 180) -> dict[str, str]:
    """Decompile every function in ``so`` at ``style`` in a single analysis pass.

    Returns {function_name: full_text_block}. Raises on a failed CLI run so the
    structural lane fails closed rather than silently seeing zero functions.
    """
    p = subprocess.run(
        ["glaurung", "decompile", str(so), "--all", "--limit", "1000",
         "--style", style, "--no-color"],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    if p.returncode != 0:
        raise RuntimeError(f"glaurung decompile failed ({style}): {p.stderr.strip()[-200:]}")
    out = p.stdout
    parts = list(_HDR.finditer(out))
    funcs: dict[str, str] = {}
    for i, m in enumerate(parts):
        end = parts[i + 1].start() if i + 1 < len(parts) else len(out)
        funcs[m.group("a") or m.group("b")] = out[m.start():end]
    return funcs


def _strip_comments(block: str) -> str:
    return "\n".join(l for l in block.splitlines() if not l.strip().startswith("//"))


def closure_status(block: str) -> str:
    """`closed`, or a description of the first closure violation found."""
    body = _strip_comments(block)
    gotos = set(_GOTO.findall(body))
    labels = set(_LABEL.findall(body))
    missing = sorted(gotos - labels)
    if missing:
        return "goto_no_label:" + ",".join(missing)
    if body.count("{") != body.count("}"):
        return f"brace_imbalance:{body.count('{')}/{body.count('}')}"
    if body.count("(") != body.count(")"):
        return f"paren_imbalance:{body.count('(')}/{body.count(')')}"
    return "closed"


def has_indirect_call(block: str) -> bool:
    """A call through a computed/loaded pointer: ``(*(...))(...)`` or ``(...)()``
    on a dereferenced/cast target — the operations-table / callback dispatch."""
    body = _strip_comments(block)
    return bool(re.search(r"\)\s*\)\s*\(", body) or re.search(r"\(\s*\*[^)]*\)\s*\(", body))


def has_memory_store(block: str) -> bool:
    """A store to memory survived lowering: ``*(T *)(addr) = v`` or ``[idx] = v``."""
    body = _strip_comments(block)
    return bool(re.search(r"\*\s*\([^)]*\*\s*\)\s*\([^;]*\)\s*=", body)
                or re.search(r"\]\s*=", body)
                or re.search(r"\*\s*\w+\s*=", body))


_VERIFY = re.compile(r"(?m)^// glaurung-verify: (.+)$")


def def_use_violations(block: str) -> list[str]:
    """Definition-before-use violations the decompiler reported for this function.

    `src/ir/verify_defs.rs` checks the post-transformation AST — the exact AST that
    is printed — and the pipeline emits each violation as a `// glaurung-verify:`
    comment. A violation means the emitted C reads a value it never produced, so
    the recompiled function returns garbage: real corruption, invisible to
    type_match / GED / byte_match, and worth gating per function.
    """
    return sorted(m.group(1).strip() for m in _VERIFY.finditer(block))


def has_placeholder_dispatch(block: str) -> bool:
    """A fabricated target name like ``dispatch_0x1234`` / ``sub_401000`` / ``fn_...``
    invented in place of a recovered indirect callee — a semantic lie."""
    body = _strip_comments(block)
    return bool(re.search(r"\b(dispatch|sub|fn|loc|func)_0?x?[0-9a-fA-F]{3,}\s*\(", body))


def is_nonempty(block: str) -> bool:
    """The function body recovered at least one real statement (not just braces)."""
    body = _strip_comments(block)
    inner = body[body.find("{") + 1: body.rfind("}")] if "{" in body else ""
    return ";" in inner


PREDICATES = {
    "indirect_call": has_indirect_call,
    "memory_store": has_memory_store,
    "nonempty": is_nonempty,
}


def closure_map(so: str | Path) -> dict[str, str]:
    """{f"{func}:{style}": closure_status} across every render style."""
    out: dict[str, str] = {}
    for style in STYLES:
        for name, block in decompile_all(so, style).items():
            out[f"{name}:{style}"] = closure_status(block)
    return out


# --- shared report builder (generator + structural lane call the same code) ---

import sys

import manifest as M

HERE = Path(__file__).resolve().parent
SRC = HERE / "src"
sys.path.insert(0, str(HERE.parent.parent / "tools"))
import diff_decompile as D  # ty: ignore[unresolved-import]
import fixture_toolchain as TC  # ty: ignore[unresolved-import]


def _build(stem: str, workdir: Path) -> Path:
    """Compile one fixture with gcc -O0 -g for structural inspection.

    Under the pinned toolchain (`tools/fixture_toolchain.py`), for the same reason
    the execution lane is: the structural baseline records decompiler OUTPUT, which
    follows the compiled binary. Built with a host compiler it drifts with the
    host's gcc release — labels move, indirect-call recovery changes — so the
    committed map would only be checkable on the machine that wrote it.
    """
    src = SRC / f"{stem}.c"
    if not src.exists():
        src = SRC / f"{stem}.cpp"
    cc = "g++" if src.suffix == ".cpp" else "gcc"
    so = workdir / f"{stem}.so"
    r = TC.run([cc, "-shared", "-fPIC", "-g", "-O0", "-w", "-o", str(so), str(src)])
    if r.returncode != 0:
        raise RuntimeError(f"compile {stem}: {r.stderr.strip()[-200:]}")
    return so


def structural_report(workdir: Path) -> dict:
    """Decompile every fixture once per style and return a structural map:

      {"closure":     {"fixture:func:style": status},
       "effects":     {"fixture:func": {predicate: bool}},
       "placeholder": {"fixture:func": bool},   # decbench emits a fabricated name
       "verify":      {"fixture:func": [violation, ...]},  # def-before-use
       "gaps":        ["fixture:func", ...]}     # structural-only, no assertion

    `closure` covers every REQUIRED function in every style; `effects` runs the
    predicates the manifest's STRUCTURAL map declares. `verify` records the
    definition-before-use violations the decompiler reported for the function (see
    `def_use_violations`). `gaps` lists functions the execution gate can only mark
    `structural` yet that carry NO structural assertion — a structural label with
    nothing executed behind it. A non-empty `gaps` list must fail the lane.
    """
    closure: dict[str, str] = {}
    effects: dict[str, dict] = {}
    placeholder: dict[str, bool] = {}
    verify: dict[str, list[str]] = {}
    gaps: list[str] = []
    for fixture, funcs in M.REQUIRED_FUNCTIONS.items():
        so = _build(fixture, workdir)
        per_style = {style: decompile_all(so, style) for style in STYLES}
        for fn in funcs:
            for style in STYLES:
                block = per_style[style].get(fn)
                closure[f"{fixture}:{fn}:{style}"] = (
                    "not_emitted" if block is None else closure_status(block)
                )
            dec = per_style["decbench"].get(fn, "")
            placeholder[f"{fixture}:{fn}"] = has_placeholder_dispatch(dec)
            verify[f"{fixture}:{fn}"] = def_use_violations(dec)
            spec = M.structural_spec(fixture, fn)
            if spec:
                effects[f"{fixture}:{fn}"] = {
                    pred: PREDICATES[pred](dec) for pred in spec if pred in PREDICATES
                }
            # Contract: a function the exec gate can ONLY treat as structural must
            # carry at least one structural assertion, else it is untested.
            sig = _sig_for(so, fn)
            if sig is not None and D.exec_class(sig, fixture)[0] == "structural" and not spec:
                gaps.append(f"{fixture}:{fn}")
    return {"closure": closure, "effects": effects,
            "placeholder": placeholder, "verify": verify, "gaps": sorted(gaps)}


_SIG_CACHE: dict[str, dict] = {}


def _sig_for(so: Path, fn: str):
    key = str(so)
    if key not in _SIG_CACHE:
        _SIG_CACHE[key] = {s["name"]: s for s in D.signatures(str(so))}
    return _SIG_CACHE[key].get(fn)
