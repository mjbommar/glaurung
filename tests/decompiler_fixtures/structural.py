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

import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "tools"))
import build_guard as BG  # ty: ignore[unresolved-import]

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
        [
            BG.glaurung_bin(),
            "decompile",
            str(so),
            "--all",
            "--limit",
            "1000",
            "--style",
            style,
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        # Opt in to the `// glaurung-verify:` diagnostics. They are deliberately OFF by
        # default — they are instrumentation, and the decbench render is an artifact
        # other tools consume and score — so this lane asks for them explicitly.
        env={**os.environ, "GLAURUNG_VERIFY_DEFS": "1"},
    )
    if p.returncode != 0:
        raise RuntimeError(
            f"glaurung decompile failed ({style}): {p.stderr.strip()[-200:]}"
        )
    out = p.stdout
    parts = list(_HDR.finditer(out))
    funcs: dict[str, str] = {}
    for i, m in enumerate(parts):
        end = parts[i + 1].start() if i + 1 < len(parts) else len(out)
        funcs[m.group("a") or m.group("b")] = out[m.start() : end]
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


#: A function-pointer CAST that is then APPLIED:
#: ``((int (*)(long, long))(ops[i]))(a, b)``. The `(*)` is C's function-pointer
#: declarator, and requiring the `))(` after it is what distinguishes a call from
#: the `static void (*ops[5])(void)` DECLARATION of the same table.
_FN_PTR_CAST_APPLIED = re.compile(r"\(\s*\*\s*\)\s*\([^;]*?\)\s*\)\s*\(")
#: A dereferenced callee applied directly: ``(*fp)(a)``, ``(*obj->vtbl[2])(x)``.
_DEREF_CALLEE_APPLIED = re.compile(r"\(\s*\*\s*[A-Za-z_][\w\[\]\.\s\+\-\>]*\)\s*\(")


def has_indirect_call(block: str) -> bool:
    """A call through a computed/loaded pointer — operations-table dispatch.

    The previous predicate was a bare ))( match — which ordinary
    nested casts produce constantly. Measured over 139 REQUIRED functions from
    45 fixtures at `gcc:O0`, it fired on **45 of them (32%)**, including
    `108_multidimensional_arrays:sum_true_2d`, which contains no call of any
    kind. A predicate true of a third of all functions cannot distinguish a
    recovered indirect call from a nested cast, so every `indirect_call: True`
    assertion was passing whether or not the feature worked.

    The two patterns above fire on **8 of the same 139 (5%)**, and the four
    functions that actually assert this — `08_indirect_dispatch`'s `dispatch`,
    `apply` and `tail_dispatch`, plus `10_cpp_runtime_shapes`'
    `cpp_virtual_dispatch` — still hold on **all 16 cells** (both compilers,
    both optimisation levels). So the assertions were not vacuous after all:
    the recovery genuinely works, and now the test says so for a reason.

    One removed hit is worth naming: `08_indirect_dispatch:dispatch_switch` no
    longer matches, correctly — it dispatches through a `switch`, not through a
    pointer, and it asserts nothing.
    """
    body = _strip_comments(block)
    return bool(_FN_PTR_CAST_APPLIED.search(body) or _DEREF_CALLEE_APPLIED.search(body))


def has_memory_store(block: str) -> bool:
    """A store to memory survived lowering: ``*(T *)(addr) = v`` or ``[idx] = v``."""
    body = _strip_comments(block)
    return bool(
        re.search(r"\*\s*\([^)]*\*\s*\)\s*\([^;]*\)\s*=", body)
        or re.search(r"\]\s*=", body)
        or re.search(r"\*\s*\w+\s*=", body)
    )


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
    return bool(
        re.search(r"\b(dispatch|sub|fn|loc|func)_0?x?[0-9a-fA-F]{3,}\s*\(", body)
    )


def is_nonempty(block: str) -> bool:
    """The function body recovered at least one real statement (not just braces)."""
    body = _strip_comments(block)
    inner = body[body.find("{") + 1 : body.rfind("}")] if "{" in body else ""
    return ";" in inner


def has_head_tested_while(block: str) -> bool:
    """A canonical pre-tested loop, rather than a guarded ``while (1)``.

    Anchor at the start of a statement so the trailing ``while`` of a do-while
    cannot satisfy this predicate.
    """
    body = _strip_comments(block)
    return bool(re.search(r"(?m)^\s*while\s*\((?!\s*1\s*\))", body))


def has_for_loop(block: str) -> bool:
    """A source-level ``for (init; condition; iterator)`` survived rendering."""
    body = _strip_comments(block)
    return bool(re.search(r"(?m)^\s*for\s*\([^;]+;[^;]+;[^)]+\)", body))


def has_void_signature(block: str) -> bool:
    """The recovered source prototype explicitly returns ``void``.

    This is distinct from a scalar function containing a bare machine return:
    the latter is rendered as ``return 0`` for parseability. Only prototype
    recovery may satisfy this predicate.
    """
    body = _strip_comments(block)
    return bool(re.search(r"(?m)^\s*void\s+[A-Za-z_]\w*\s*\(", body))


def has_switch(block: str) -> bool:
    """A ``switch`` statement survived into the rendered C.

    THE GAP THIS CLOSES. Until this predicate existed the corpus could assert
    that a function *executes* correctly and nothing more, and a dispatch
    recovered as a labelled goto chain executes correctly: the arms are all
    present, the control flow is faithful, and the C is simply not a switch.
    Measured over the 250 scored DecBench sample-set functions, 28.8% render as
    goto soup (40.5% on x86-64) -- the single largest defect class -- and every
    one of them passes an execution differential.

    Deliberately textual and deliberately weak: it asks whether the renderer
    emitted the construct, not whether the arms are right. `04_switch_shapes`
    and the manifest's `arg_values` already drive the exact case constants, so
    correctness of the arms is covered where it belongs. Anchored at the start
    of a statement so a `switch` inside a string literal or a comment cannot
    satisfy it.
    """
    body = _strip_comments(block)
    return bool(re.search(r"(?m)^\s*switch\s*\(", body))


def goto_free(block: str) -> bool:
    """No ``goto`` survived into the rendered C.

    The companion to [`has_switch`], and phrased as an ABSENCE on purpose: the
    structural map records booleans, and `{"goto_free": True}` reads as the
    property being asserted rather than as a count being tolerated. A count
    would also be the wrong shape -- it would have to be refreshed every time a
    lane's rendering shifted by one label, which is exactly the churn the
    closure/verify sections already carry.

    A `goto` is not itself a defect: `102_duffs_device`, `103_computed_goto` and
    `105_goto_ladder` are ABOUT goto, and irreducible control flow legitimately
    needs one. This predicate exists so that a fixture whose source has no goto
    can say so, and notice when the structurer starts emitting them.
    """
    body = _strip_comments(block)
    return not re.search(r"(?m)^\s*goto\s+\w+\s*;", body)


PREDICATES = {
    "indirect_call": has_indirect_call,
    "switch": has_switch,
    "goto_free": goto_free,
    "memory_store": has_memory_store,
    "nonempty": is_nonempty,
    "head_tested_while": has_head_tested_while,
    "for_loop": has_for_loop,
    "void_signature": has_void_signature,
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


def _c_source(stem: str) -> Path | None:
    """The fixture's C or C++ source, or None if it is written in something else.

    The corpus is no longer C-only: it carries Rust (`.rs`), Go (`.go`) and hand
    -written assembly (`.S`) fixtures. This lane compiles with `gcc -O0 -g` and
    grades the decompiled C against a committed structural map, so it applies
    only to the C-family sources — and it used to *assume* that, falling back to
    `<stem>.cpp` for anything that was not `<stem>.c` and then handing a path
    that does not exist to `g++`. With the curriculum fixtures in the manifest
    that turned into `cc1plus: fatal error: 166_rust_generics.cpp: No such file`,
    which errored the whole lane at setup rather than skipping one fixture.
    """
    for suffix in (".c", ".cpp"):
        candidate = SRC / f"{stem}{suffix}"
        if candidate.exists():
            return candidate
    return None


def _build(stem: str, workdir: Path) -> Path:
    """Compile one fixture with gcc -O0 -g for structural inspection.

    Under the pinned toolchain (`tools/fixture_toolchain.py`), for the same reason
    the execution lane is: the structural baseline records decompiler OUTPUT, which
    follows the compiled binary. Built with a host compiler it drifts with the
    host's gcc release — labels move, indirect-call recovery changes — so the
    committed map would only be checkable on the machine that wrote it.
    """
    src = _c_source(stem)
    if src is None:
        raise RuntimeError(f"compile {stem}: no C/C++ source")
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
    #: Fixtures this lane cannot grade because they are not C-family sources.
    #: Reported rather than dropped: a silently shortened corpus reads as
    #: "everything passed" when it means "we did not look".
    skipped: list[str] = []
    for fixture, funcs in M.REQUIRED_FUNCTIONS.items():
        if _c_source(fixture) is None:
            skipped.append(fixture)
            continue
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
            if (
                sig is not None
                and D.exec_class(sig, fixture)[0] == "structural"
                and not spec
            ):
                gaps.append(f"{fixture}:{fn}")
    return {
        "closure": closure,
        "effects": effects,
        "placeholder": placeholder,
        "verify": verify,
        "gaps": sorted(gaps),
        "skipped": sorted(skipped),
    }


_SIG_CACHE: dict[str, dict] = {}


def _sig_for(so: Path, fn: str):
    key = str(so)
    if key not in _SIG_CACHE:
        _SIG_CACHE[key] = {s["name"]: s for s in D.signatures(str(so))}
    return _SIG_CACHE[key].get(fn)
