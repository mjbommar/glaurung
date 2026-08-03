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
import shutil
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
    # This used to also assert that opting in PRODUCED diagnostics here, as a
    # canary that the ratchet had not stopped checking. That anchored the canary
    # on the corpus staying broken: `06_calling_conventions:fact_mod` and `:fib`
    # read an undefined `var0`, and when that was fixed the whole fixture corpus
    # went to zero diagnostics and the assertion became unsatisfiable.
    #
    # The canary itself is not lost. `src/ir/verify_defs.rs` owns 29 direct
    # tests, one of which pins the exact rendered string
    # `// glaurung-verify: var0 is read but never defined`, so the detector
    # cannot silently stop working. What this test still owns — and what only an
    # end-to-end render can show — is that the diagnostics stay OFF by default.
    #
    # If a future violation reappears anywhere in the corpus, prefer fixing it to
    # re-adding an assertion that depends on it existing.
    #
    # No assertion is made about `asked` containing diagnostics: on a clean
    # corpus there are none to find, and a condition written to be satisfiable
    # either way would be a tautology dressed as a check.
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


def test_nested_conditional_result_recovers_direct_returns(tmp_path: Path) -> None:
    """An optimized guarded select must recover the source's nested returns."""
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

    assert " ? " not in result.stdout, result.stdout
    assert result.stdout.count("if (") == 2, result.stdout
    assert result.stdout.count("return ") == 3, result.stdout
    assert result.stdout.count("} else {") == 1, result.stdout
    assert "return 0;" in result.stdout, result.stdout
    assert "ret =" not in result.stdout, result.stdout
    assert "glaurung-verify" not in result.stdout, result.stdout


def test_classify_keeps_the_source_if_chain_out_of_a_ternary(tmp_path: Path) -> None:
    """The real GCC O0 return-value diamond must stay branches, not a ternary.

    This assertion used to demand the opposite (`if (` absent, `?` present). It
    was added when `select_fold` was introduced to delete *fake* control flow,
    and collapsing every same-destination diamond was how that was done. But
    `classify`'s source is an if/else-if/return chain:

        int classify(int a,int b){ if(a>b) return a-b; else if(a<b) return b-a; return 0; }

    and collapsing it produced one nested ternary. DecBench scores structure as
    graph edit distance against the source CFG, and measured with the same
    pyjoern the benchmark uses, the nested-ternary spelling is 6 nodes / 7 edges
    against the source's 5 / 4 — GED 7 — while the branch spelling is an exact
    match at GED 0. The scoped matrix agrees: `branches:gcc:O0` and
    `branches:clang:O0` both went 7.0 -> 0.0.

    The transform is NOT disabled — the fake-control-flow removal it exists for
    still runs. `test_signs_renders_lifted_select_as_pure_ternary` below pins the
    case where the source really is a ternary, and it is unchanged. What changed
    is only that a joined result whose sole use is the `return` keeps its branch.
    """
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

    assert " ? " not in result.stdout, result.stdout
    assert result.stdout.count("if (") == 2, result.stdout
    assert result.stdout.count("return ") == 3, result.stdout
    assert "glaurung-verify" not in result.stdout, result.stdout


def test_classify_clang_o2_recovers_signed_relations_without_flag_locals(
    tmp_path: Path,
) -> None:
    """Repeated CMOV predicates must not strand their SF/OF implementation."""
    import subprocess

    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC  # ty: ignore[unresolved-import]

    source = ROOT / "tests" / "decbench_corpus" / "src" / "branches.c"
    binary = tmp_path / "branches-clang-O2.so"
    compiled = TC.run(
        ["clang", "-shared", "-fPIC", "-g", "-O2", "-o", str(binary), str(source)],
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

    assert "sf_" not in result.stdout, result.stdout
    assert "of_" not in result.stdout, result.stdout
    assert "arg0 < arg1" in result.stdout, result.stdout
    assert "glaurung-verify" not in result.stdout, result.stdout


def test_recursion_clang_o0_recovers_exhaustive_direct_returns(tmp_path: Path) -> None:
    """Recursive result joins must become source-level returns, without frame residue."""
    import subprocess

    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC  # ty: ignore[unresolved-import]

    source = ROOT / "tests" / "decbench_corpus" / "src" / "recursion.c"
    binary = tmp_path / "recursion-clang-O0.so"
    compiled = TC.run(
        ["clang", "-shared", "-fPIC", "-g", "-O0", "-o", str(binary), str(source)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr

    outputs: dict[str, str] = {}
    for function in ("fib", "ackermann"):
        result = subprocess.run(
            [
                "glaurung",
                "decompile",
                binary,
                "--func",
                function,
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
        outputs[function] = result.stdout
        assert "rsp =" not in result.stdout, result.stdout
        assert "return local_" not in result.stdout, result.stdout
        assert "glaurung-verify" not in result.stdout, result.stdout

    assert outputs["fib"].count("return ") == 2, outputs["fib"]
    assert outputs["ackermann"].count("return ") == 3, outputs["ackermann"]
    assert "long fib(int arg0)" in outputs["fib"], outputs["fib"]
    assert "long ackermann(long arg0, long arg1)" in outputs["ackermann"], outputs[
        "ackermann"
    ]

    differential = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "recursion",
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    verdicts = json.loads(differential.stdout)
    assert verdicts["fib"]["status"] == "pass", verdicts["fib"]
    assert verdicts["ackermann"]["status"] == "pass", verdicts["ackermann"]


def test_recursion_gcc_o2_inherits_declared_parameter_types(tmp_path: Path) -> None:
    """A concrete optimized DIE must inherit the source prototype it implements."""
    import subprocess

    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC  # ty: ignore[unresolved-import]

    source = ROOT / "tests" / "decbench_corpus" / "src" / "recursion.c"
    binary = tmp_path / "recursion-gcc-O2.so"
    compiled = TC.run(
        ["gcc", "-shared", "-fPIC", "-g", "-O2", "-o", str(binary), str(source)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr

    fib = subprocess.run(
        [
            "glaurung",
            "decompile",
            binary,
            "--func",
            "fib",
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    ).stdout
    assert "long fib(int arg0)" in fib or "long int fib(int arg0)" in fib, fib

    ackermann = subprocess.run(
        [
            "glaurung",
            "decompile",
            binary,
            "--func",
            "ackermann",
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    ).stdout
    assert (
        "long ackermann(long arg0, long arg1)" in ackermann
        or "long int ackermann(long int arg0, long int arg1)" in ackermann
    ), ackermann
    assert "arg2" not in ackermann, ackermann

    differential = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "recursion",
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=900,
        check=True,
    )
    verdicts = json.loads(differential.stdout)
    assert verdicts["fib"]["status"] == "pass", verdicts["fib"]
    assert verdicts["ackermann"]["status"] == "pass", verdicts["ackermann"]


def test_bst_clang_o2_recovers_anonymous_struct_typedef(tmp_path: Path) -> None:
    """A typedef to an anonymous DWARF struct must retain its named identity."""
    import subprocess

    source = ROOT / "tests" / "decompiler_fixtures" / "src" / "15_binary_search_tree.c"
    binary = tmp_path / "15_binary_search_tree-clang-O2.so"
    compiled = S.TC.run(
        ["clang", "-shared", "-fPIC", "-g", "-O2", "-o", str(binary), str(source)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr

    outputs = {}
    for function in ("bst_search", "bst_inorder_checksum"):
        outputs[function] = subprocess.run(
            [
                "glaurung",
                "decompile",
                binary,
                "--func",
                function,
                "--style",
                "decbench",
                "--no-color",
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        ).stdout
        assert "BstNode * arg0" in outputs[function], outputs[function]
        assert "((struct BstNode *)arg0)" not in outputs[function], outputs[function]
        assert ".key" in outputs[function], outputs[function]
    assert ".left" in outputs["bst_inorder_checksum"], outputs["bst_inorder_checksum"]
    assert ".right" in outputs["bst_inorder_checksum"], outputs["bst_inorder_checksum"]

    differential = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "15_binary_search_tree",
            "--seed",
            "20260731",
            "--fuzz",
            "256",
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=900,
        check=True,
    )
    verdicts = json.loads(differential.stdout)
    assert verdicts["bst_search"]["status"] == "pass", verdicts["bst_search"]
    assert verdicts["bst_inorder_checksum"]["status"] == "pass", verdicts[
        "bst_inorder_checksum"
    ]


def test_bst_eager_setcc_guard_recovers_logical_predicates(tmp_path: Path) -> None:
    """A real SETcc/OR lowering must recover pure source-level predicates."""
    import subprocess

    clang = shutil.which("clang")
    objdump = shutil.which("objdump")
    if clang is None or objdump is None:
        pytest.skip("host clang and objdump are required")

    source = ROOT / "tests" / "decompiler_fixtures" / "src" / "15_binary_search_tree.c"
    binary = tmp_path / "15_binary_search_tree-host-clang-O2.so"
    compiled = subprocess.run(
        [clang, "-shared", "-fPIC", "-g", "-O2", "-o", str(binary), str(source)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    machine = subprocess.run(
        [objdump, "-d", "--disassemble=bst_search", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout
    setcc_count = sum("\tset" in line for line in machine.splitlines())
    byte_or_count = sum("\tor" in line and "%" in line for line in machine.splitlines())
    if setcc_count < 2 or byte_or_count < 2:
        pytest.skip("host clang did not select the eager SETcc/OR lowering")

    outputs = {}
    for function in ("bst_search", "bst_inorder_checksum"):
        outputs[function] = subprocess.run(
            [
                "glaurung",
                "decompile",
                binary,
                "--func",
                function,
                "--style",
                "decbench",
                "--no-color",
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        ).stdout
    assert outputs["bst_search"].count(" && ") >= 2, outputs["bst_search"]
    assert outputs["bst_inorder_checksum"].count(" && ") >= 3, outputs[
        "bst_inorder_checksum"
    ]
    assert " || " not in outputs["bst_search"], outputs["bst_search"]

    differential = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "15_binary_search_tree",
            "--seed",
            "20260731",
            "--fuzz",
            "256",
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=900,
        check=True,
    )
    verdicts = json.loads(differential.stdout)
    assert verdicts["bst_search"]["status"] == "pass", verdicts["bst_search"]
    assert verdicts["bst_inorder_checksum"]["status"] == "pass", verdicts[
        "bst_inorder_checksum"
    ]


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
