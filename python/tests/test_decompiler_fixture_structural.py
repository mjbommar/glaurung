"""Structural lane: correctness properties the execution gate cannot see.

Some faithfulness properties are not observable by recompiling and calling the
decompilation — control-flow closure across every render style, that an indirect
callback stays an indirect call, that a memory store survives, that no fabricated
`sub_1234()` / `dispatch_<va>` target names are invented, and the C++ vtable/EH
shapes. This lane inspects the decompiled TEXT and compares it to a committed
`structural_baseline.json`, so known-broken output stays visible while any
regression fails closed — and any *improvement* fails too, forcing a baseline
refresh so the gate ratchets upward (it can never silently slide back).

Hard, non-baselined invariants (must always hold):
  * every execution-untestable REQUIRED function carries a structural assertion
    (`gaps` empty) — a `structural` status with nothing executed behind it fails;
  * the DecBench render style is control-flow closed for every function;
  * apply() remains an indirect callback call.

Marked `slow` (builds 10 fixtures + decompiles each in 3 styles); run with -m slow.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import manifest as M
import structural as S

BASELINE = ROOT / "tests" / "decompiler_fixtures" / "structural_baseline.json"
pytestmark = pytest.mark.slow


def _baseline() -> dict:
    assert BASELINE.is_file(), (
        "structural_baseline.json missing — regenerate with "
        "tools/gen_structural_baseline.py"
    )
    return json.loads(BASELINE.read_text())


@pytest.fixture(scope="session")
def report() -> dict:
    _td = M.tmpdir()
    with tempfile.TemporaryDirectory(**({"dir": _td} if _td else {})) as td:
        return S.structural_report(Path(td))


@pytest.fixture(scope="session")
def baseline() -> dict:
    return _baseline()


# --- hard invariants --------------------------------------------------------


def test_every_structural_only_function_has_an_assertion(report):
    # A function the exec gate can only mark `structural` MUST have a structural
    # assertion — otherwise it is completely untested.
    assert report["gaps"] == [], (
        f"structural-only functions with no assertion: {report['gaps']}"
    )


def test_verify_diagnostics_are_opt_in():
    """The decbench render is an ARTIFACT other tools consume, parse and score.

    `// glaurung-verify:` lines are instrumentation for this gate, not decompiler
    output. Emitted unconditionally they travel into every consumer — including the
    C submitted to an external benchmark, where each line is a note announcing our
    own bug inside the code being scored. So they are off unless asked for, and this
    lane asks (see `structural.decompile_all`).
    """
    import os
    import subprocess

    _td = M.tmpdir()
    with tempfile.TemporaryDirectory(**({"dir": _td} if _td else {})) as td:
        so = S._build("06_calling_conventions", Path(td))
        cmd = [
            "glaurung",
            "decompile",
            str(so),
            "--all",
            "--limit",
            "50",
            "--style",
            "decbench",
            "--no-color",
        ]
        clean = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, check=True
        ).stdout
        asked = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
            env={**os.environ, "GLAURUNG_VERIFY_DEFS": "1"},
        ).stdout

    assert "glaurung-verify" not in clean, (
        "diagnostics leaked into the default render — they would ship inside a "
        "submitted artifact"
    )
    assert "glaurung-verify" in asked, (
        "opting in produced no diagnostics; this lane's ratchet would silently stop "
        "checking def-before-use"
    )
    # Same code either way: the diagnostics are additive comment lines only.
    assert [
        l for l in asked.splitlines() if "glaurung-verify" not in l
    ] == clean.splitlines()


def test_do_while_latch_condition_is_defined(tmp_path):
    """A recovered post-test must retain every value used by its latch.

    Pinned GCC O2's ``crc32_step`` places several flag-producing operations in the
    single loop block.  This real shape caught a lowering bug where do-while
    recovery dropped the definition of the temporary used by its condition.
    """
    import subprocess

    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC  # ty: ignore[unresolved-import]

    source = ROOT / "tests" / "decbench_corpus" / "src" / "checksum.c"
    binary = tmp_path / "checksum-gcc-O2.so"
    compiled = TC.run(
        ["gcc", "-shared", "-fPIC", "-g", "-O2", "-o", str(binary), str(source)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    result = subprocess.run(
        [
            "glaurung",
            "decompile",
            binary,
            "--func",
            "crc32_step",
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
        env={**os.environ, "GLAURUNG_VERIFY_DEFS": "1"},
    )

    assert "do {" in result.stdout, "the real bottom-tested loop was not recovered"
    assert "glaurung-verify" not in result.stdout, result.stdout


def test_all_and_vas_agree():
    """`decompile --all` and `decompile --vas <list>` must produce the same functions.

    They did not. The four decompile entry points in `python_bindings/ir.rs` each
    reproduce the pass sequence by hand, and the `--all` one ran dead-flag pruning
    before constant folding and never pruned unreferenced labels. That is a product
    bug — two CLI modes disagreeing about the same function — and it quietly
    undermined this gate: the structural lane reads `--all` while the execution lane
    reads `--vas`, so the two lanes were grading different pipelines.

    `03_loop_shapes` is the fixture chosen because it WITNESSES that drift: with
    label pruning removed from `--all` again, two of its functions differ (fixtures
    01 and 05 have no unreferenced labels and cannot detect it). One multi-VA call
    covers all 19 functions, so this invariant costs a couple of seconds.
    """
    import subprocess
    import sys as _sys

    _sys.path.insert(0, str(ROOT / "tools"))
    import diff_decompile as D  # ty: ignore[unresolved-import]

    _td = M.tmpdir()
    with tempfile.TemporaryDirectory(**({"dir": _td} if _td else {})) as td:
        so = S._build("03_loop_shapes", Path(td))
        vas = [hex(sig["va"]) for sig in D.signatures(str(so))]
        assert vas, "no DWARF signatures recovered — the comparison would be vacuous"
        p = subprocess.run(
            [
                "glaurung",
                "decompile",
                str(so),
                "--vas",
                ",".join(vas),
                "--style",
                "decbench",
                "--no-color",
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
            # `S.decompile_all` opts in to the verify diagnostics, so this side must
            # too, or the comparison is between two different CONFIGURATIONS rather
            # than two pipelines. Comparing with diagnostics on is strictly stronger:
            # the two paths then have to agree about the violations as well as the code.
            env={**os.environ, "GLAURUNG_VERIFY_DEFS": "1"},
        )
        per_va = _split_functions(p.stdout)
        from_all = {k: v.strip() for k, v in S.decompile_all(so, "decbench").items()}

    assert len(per_va) == len(vas), (
        f"--vas returned {len(per_va)} functions for {len(vas)} addresses"
    )
    mismatched = []
    for name, one in sorted(per_va.items()):
        many = from_all.get(name)
        if many is None:
            mismatched.append(f"{name}: absent from --all")
        elif many != one:
            mismatched.append(f"{name}:\n--- --vas ---\n{one}\n--- --all ---\n{many}")
    assert not mismatched, (
        "`--all` and `--vas` disagree (the four hand-copied pass sequences have "
        "drifted apart):\n" + "\n".join(mismatched)
    )


def _split_functions(text: str) -> dict[str, str]:
    """Split a multi-function decbench render into {name: block}."""
    parts = list(S._HDR.finditer(text))
    out = {}
    for i, m in enumerate(parts):
        end = parts[i + 1].start() if i + 1 < len(parts) else len(text)
        out[m.group("a") or m.group("b")] = text[m.start() : end].strip()
    return out


def test_decbench_output_is_control_flow_closed(report):
    broken = {
        k: v
        for k, v in report["closure"].items()
        if k.endswith(":decbench") and v != "closed"
    }
    assert not broken, f"DecBench render not control-flow closed: {broken}"


def test_apply_remains_an_indirect_callback_call(report):
    got = report["effects"].get("08_indirect_dispatch:apply", {})
    assert got.get("indirect_call") is True, "apply() lost its indirect callback call"


def test_dispatch_recovers_portable_local_function_table(tmp_path: Path) -> None:
    """A relocation-proven local function table must survive standalone C.

    Pinned GCC O0 emits ``call *ops(,%rax,8)`` for this real fixture.  A raw
    image VA such as ``0x4040`` happens to name the table in the input DSO but
    is unmapped in the rebuilt differential object, where calling through it
    segfaults.  Every table slot has an exact dynamic relocation to one of the
    five local handlers, so the decompiler can preserve the table itself rather
    than guessing a direct callee.
    """
    import subprocess

    source = ROOT / "tests" / "decompiler_fixtures" / "src" / "08_indirect_dispatch.c"
    binary = tmp_path / "indirect-dispatch-gcc-O0.so"
    compiled = S.TC.run(
        ["gcc", "-shared", "-fPIC", "-g", "-O0", "-w", "-o", str(binary), str(source)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    result = subprocess.run(
        [
            "glaurung",
            "decompile",
            binary,
            "--func",
            "dispatch",
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )

    assert "ops[5]" in result.stdout, result.stdout
    for handler in ("h_add", "h_sub", "h_mul", "h_xor", "h_max"):
        assert handler in result.stdout, result.stdout
    assert "0x4040" not in result.stdout, result.stdout
    assert "unrecovered indirect jump" not in result.stdout, result.stdout


def test_optimized_tail_dispatch_recovers_portable_local_function_table(
    tmp_path: Path,
) -> None:
    """A relocation-proven indexed tail jump must become a returning call."""
    import subprocess

    source = ROOT / "tests" / "decompiler_fixtures" / "src" / "08_indirect_dispatch.c"
    binary = tmp_path / "indirect-dispatch-clang-O2.so"
    compiled = S.TC.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-g",
            "-O2",
            "-w",
            "-o",
            str(binary),
            str(source),
        ],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    result = subprocess.run(
        [
            "glaurung",
            "decompile",
            binary,
            "--func",
            "tail_dispatch",
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )

    assert "ops[5]" in result.stdout, result.stdout
    for handler in ("h_add", "h_sub", "h_mul", "h_xor", "h_max"):
        assert handler in result.stdout, result.stdout
    assert "unrecovered indirect jump" not in result.stdout, result.stdout
    assert "return ret;" in result.stdout, result.stdout

    helper = subprocess.run(
        [
            "glaurung",
            "decompile",
            binary,
            "--func",
            "h_add",
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    assert "void h_add" not in helper.stdout, helper.stdout
    assert "return;" not in helper.stdout, helper.stdout
    assert "100" in helper.stdout, helper.stdout


def test_gcc_o0_direct_dispatch_switch_recovers_all_cases(tmp_path: Path) -> None:
    """A memory-operand range guard must retain every jump-table case."""
    import subprocess

    source = ROOT / "tests" / "decompiler_fixtures" / "src" / "08_indirect_dispatch.c"
    binary = tmp_path / "indirect-dispatch-gcc-O0-switch.so"
    compiled = S.TC.run(
        ["gcc", "-shared", "-fPIC", "-g", "-O0", "-w", "-o", str(binary), str(source)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    result = subprocess.run(
        [
            "glaurung",
            "decompile",
            binary,
            "--func",
            "dispatch_switch",
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    assert "switch" in result.stdout, result.stdout
    for handler in ("h_add", "h_sub", "h_mul", "h_xor", "h_max"):
        assert handler in result.stdout, result.stdout
    assert "unrecovered indirect jump" not in result.stdout, result.stdout


def test_factorial_recovers_a_head_tested_while(report):
    """A real compiled factorial must retain its source-level loop form."""
    got = report["effects"].get("12_loop_rotation:factorial_while", {})
    assert got.get("head_tested_while") is True, (
        "factorial_while stayed as `while (1) { if (...) break; ... }` instead of "
        "recovering a head-tested while"
    )


def test_sum_array_recovers_a_for_loop(tmp_path):
    """A real compiled counted array walk must regain its source-level loop form."""
    import subprocess

    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC  # ty: ignore[unresolved-import]

    source = ROOT / "tests" / "decbench_corpus" / "src" / "arrays.c"
    binary = tmp_path / "arrays-gcc-O0.so"
    compiled = TC.run(
        ["gcc", "-shared", "-fPIC", "-g", "-O0", "-o", str(binary), str(source)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    result = subprocess.run(
        [
            "glaurung",
            "decompile",
            binary,
            "--func",
            "sum_array",
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
        env={**os.environ, "GLAURUNG_VERIFY_DEFS": "1"},
    )

    assert S.has_for_loop(result.stdout), result.stdout
    assert "++" in result.stdout, result.stdout
    assert "glaurung-verify" not in result.stdout, result.stdout


@pytest.mark.parametrize("opt", ["-O0", "-O2"])
def test_signs_renders_lifted_select_as_pure_ternary(tmp_path: Path, opt: str) -> None:
    """Real compiled selects must retain both pure value alternatives."""
    import subprocess

    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC  # ty: ignore[unresolved-import]

    source = ROOT / "tests" / "decbench_corpus" / "src" / "arith.c"
    binary = tmp_path / f"arith-gcc-{opt[1:]}.so"
    compiled = TC.run(
        ["gcc", "-shared", "-fPIC", "-g", opt, "-o", str(binary), str(source)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    result = subprocess.run(
        [
            "glaurung",
            "decompile",
            binary,
            "--func",
            "signs",
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
        env={**os.environ, "GLAURUNG_VERIFY_DEFS": "1"},
    )

    assert result.stdout.count(" ? ") == 2, result.stdout
    assert "if (" not in result.stdout, result.stdout
    assert "else" not in result.stdout, result.stdout
    assert "glaurung-verify" not in result.stdout, result.stdout


def test_nested_select_under_existing_branch_retains_inner_else(tmp_path: Path) -> None:
    """An optimized select inside source control flow must retain both arms."""
    import subprocess

    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC  # ty: ignore[unresolved-import]

    source = ROOT / "tests" / "decbench_corpus" / "src" / "branches.c"
    binary = tmp_path / "branches-gcc-O2.so"
    compiled = TC.run(
        ["gcc", "-shared", "-fPIC", "-g", "-O2", "-o", str(binary), str(source)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    result = subprocess.run(
        [
            "glaurung",
            "decompile",
            binary,
            "--func",
            "nested",
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
        env={**os.environ, "GLAURUNG_VERIFY_DEFS": "1"},
    )

    assert result.stdout.count(" ? ") == 1, result.stdout
    assert result.stdout.count("if (") == 1, result.stdout
    assert "else" not in result.stdout, result.stdout
    assert "glaurung-verify" not in result.stdout, result.stdout


def test_classify_collapses_same_destination_diamonds(tmp_path: Path) -> None:
    """The real GCC O0 return-value diamond must become nested selects."""
    import subprocess

    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC  # ty: ignore[unresolved-import]

    source = ROOT / "tests" / "decbench_corpus" / "src" / "branches.c"
    binary = tmp_path / "branches-gcc-O0.so"
    compiled = TC.run(
        ["gcc", "-shared", "-fPIC", "-g", "-O0", "-o", str(binary), str(source)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    result = subprocess.run(
        [
            "glaurung",
            "decompile",
            binary,
            "--func",
            "classify",
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
        env={**os.environ, "GLAURUNG_VERIFY_DEFS": "1"},
    )

    assert "if (" not in result.stdout, result.stdout
    assert "else" not in result.stdout, result.stdout
    assert " ? " in result.stdout, result.stdout
    assert "glaurung-verify" not in result.stdout, result.stdout


def test_declared_structural_predicates_are_all_present(report):
    # A declared predicate must actually be evaluated (True/False), never absent —
    # a structural assertion that silently does not run is a fail-open gap.
    for key, spec in M.STRUCTURAL.items():
        fkey = f"{key[0]}:{key[1]}"
        got = report["effects"].get(fkey, {})
        for pred in spec:
            assert pred in got, f"predicate {pred} not evaluated for {fkey}"


# --- baseline comparison (fail closed on regression) ------------------------


def _closure_regressed(base: str, cur: str) -> bool:
    if base == cur:
        return False
    if base == "closed" and cur != "closed":
        return True
    return base != "not_emitted" and cur == "not_emitted"


def test_no_structural_regression(report, baseline):
    problems = []
    for k, base in baseline["closure"].items():
        cur = report["closure"].get(k)
        if cur is None:
            problems.append(f"closure {k}: MISSING")
        elif _closure_regressed(base, cur):
            problems.append(f"closure {k}: {base} -> {cur}")
    for k, base in baseline["effects"].items():
        cur = report["effects"].get(k, {})
        for pred, bval in base.items():
            if bval and not cur.get(pred):
                problems.append(f"effect {k}.{pred}: True -> {cur.get(pred)}")
    for k, bval in baseline["placeholder"].items():
        cur = report["placeholder"].get(k)
        if cur is None:
            problems.append(f"placeholder {k}: MISSING")
        elif not bval and cur:
            problems.append(f"placeholder {k}: fabricated name newly introduced")
    # Definition-before-use: known violations stay visible, a NEW one fails. The
    # emitted C reading a value it never produced is real corruption, so this is
    # baselined per function rather than merely logged.
    for k, base in baseline.get("verify", {}).items():
        cur = report["verify"].get(k)
        if cur is None:
            problems.append(f"verify {k}: MISSING")
            continue
        new = sorted(set(cur) - set(base))
        if new:
            problems.append(f"verify {k}: NEW def-before-use violation(s): {new}")
    for k, cur in report["verify"].items():
        if k not in baseline.get("verify", {}) and cur:
            problems.append(f"verify {k}: unrecorded function with violation(s): {cur}")
    assert not problems, "STRUCTURAL REGRESSIONS:\n  " + "\n  ".join(problems)


def test_structural_improvements_require_a_baseline_refresh(report, baseline):
    # Ratchet: an improvement that is not yet recorded must fail, so the baseline
    # is refreshed to lock it in and the function can never regress unnoticed.
    improved = []
    for k, base in baseline["closure"].items():
        cur = report["closure"].get(k)
        if base != "closed" and cur == "closed":
            improved.append(f"closure {k}: now closed")
    for k, base in baseline["effects"].items():
        cur = report["effects"].get(k, {})
        for pred, bval in base.items():
            if not bval and cur.get(pred):
                improved.append(f"effect {k}.{pred}: now True")
    for k, bval in baseline["placeholder"].items():
        if bval and not report["placeholder"].get(k):
            improved.append(f"placeholder {k}: fabricated name now gone")
    for k, base in baseline.get("verify", {}).items():
        fixed = sorted(set(base) - set(report["verify"].get(k, [])))
        if fixed:
            improved.append(f"verify {k}: violation(s) resolved: {fixed}")
    assert not improved, (
        "STRUCTURAL IMPROVEMENTS — refresh structural_baseline.json to ratchet:\n  "
        + "\n  ".join(improved)
    )
