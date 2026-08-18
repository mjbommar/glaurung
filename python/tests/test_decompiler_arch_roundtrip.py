"""The cross-architecture execution differential must be FAIL-CLOSED and ratcheted.

`tools/arch_roundtrip.py` is the only gate that executes anything recovered from an
AArch64, ARM32 or 32-bit x86 binary. Its predecessor's failure mode is the one that
matters here: a lane that reports nothing, or reports a harness artifact as a
decompiler verdict, is worse than no lane at all — it converts an unmeasured
architecture into a green tick.

These tests exercise the harness, not the lifters:

  * the ratchet (`comparison_problems`) fails on a regression AND on a silent
    improvement, on a vanished lane, on a vanished function, and on a function the
    baseline never recorded;
  * every fail-closed rule (`baseline_problems`, `schema_problems`,
    `toolchain_problems`) rejects what must never be written or compared;
  * the control lane requirement (`control_problems`) — a foreign-architecture
    number produced without a clean same-architecture control is uninterpretable;
  * two REAL round trips that pin the two harness bugs the prototype shipped:
    executing file-local `static` roots, and linking the rebuilt C against a
    foreign-architecture object.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import arch_roundtrip as A  # ty: ignore[unresolved-import]
import build_guard as BG  # ty: ignore[unresolved-import]
import diff_decompile as D  # ty: ignore[unresolved-import]
import fixture_harness as H  # ty: ignore[unresolved-import]
import fixture_toolchain as TC  # ty: ignore[unresolved-import]
import manifest as M  # ty: ignore[unresolved-import]

_TD = M.tmpdir()
WORKDIR_KW = {"dir": _TD} if _TD else {}

FP_REBUILD: dict[str, str] = {"mode": "docker", "gcc": "gcc 11", "clang": "clang 14"}
FP_FIXTURE: dict[str, str] = {
    "x86_64": "pinned: gcc 11",
    "aarch64": "host: aarch64 gcc 15",
}
FP_RUNNER: dict[str, str] = {}
FP: dict = {
    "rebuild": FP_REBUILD,
    "fixture": FP_FIXTURE,
    "runner": FP_RUNNER,
    "aslr": "no-randomize (setarch)",
}


def _result(**lanes) -> dict:
    return {H.TOOLCHAIN_KEY: FP, **lanes}


# ---------------------------------------------------------------------------
# The ratchet
# ---------------------------------------------------------------------------


def test_identical_results_are_not_a_problem():
    base = _result(**{"f:x86_64:O0": {"g": "pass", "h": "fail"}})
    assert A.comparison_problems(dict(base), base) == []


def test_a_regression_is_a_problem():
    base = _result(**{"f:aarch64:O0": {"g": "pass"}})
    cur = _result(**{"f:aarch64:O0": {"g": "fail"}})
    (problem,) = A.comparison_problems(cur, base)
    assert "REGRESSION" in problem and "f:aarch64:O0:g" in problem


def test_an_improvement_is_a_problem_so_the_baseline_ratchets():
    """A fix absorbed silently can regress later with nothing to notice: the
    baseline would still record `fail` and the regression would read as no
    change. So an improvement fails the gate and demands a refresh."""
    base = _result(**{"f:aarch64:O0": {"g": "fail"}})
    cur = _result(**{"f:aarch64:O0": {"g": "pass"}})
    (problem,) = A.comparison_problems(cur, base)
    assert "IMPROVEMENT" in problem and "refresh" in problem


def test_a_structural_result_that_starts_passing_still_ratchets():
    base = _result(**{"f:armv7:O2": {"g": "structural"}})
    cur = _result(**{"f:armv7:O2": {"g": "pass"}})
    assert any("IMPROVEMENT" in p for p in A.comparison_problems(cur, base))


def test_a_vanished_lane_is_a_problem():
    base = _result(**{"f:armv7:O0": {"g": "pass"}})
    (problem,) = A.comparison_problems(_result(), base)
    assert "disappeared" in problem


def test_a_vanished_function_is_a_problem():
    base = _result(**{"f:i386:O0": {"g": "pass", "h": "fail"}})
    cur = _result(**{"f:i386:O0": {"g": "pass"}})
    (problem,) = A.comparison_problems(cur, base)
    assert "f:i386:O0:h" in problem and "missing" in problem


def test_a_function_the_baseline_never_recorded_is_a_problem():
    """Every other comparison iterates the BASELINE's function list, so a newly
    appearing export would be completely ungated until somebody refreshed."""
    base = _result(**{"f:i386:O0": {"g": "pass"}})
    cur = _result(**{"f:i386:O0": {"g": "pass", "new": "fail"}})
    (problem,) = A.comparison_problems(cur, base)
    assert "f:i386:O0:new" in problem and "ungated" in problem


def test_a_lane_the_baseline_never_recorded_is_a_problem():
    cur = _result(**{"f:i386:O0": {"g": "pass"}})
    (problem,) = A.comparison_problems(cur, _result())
    assert "not in the baseline" in problem


def test_a_newly_broken_lane_is_a_problem():
    base = _result(**{"f:aarch64:O2": {"g": "pass"}})
    cur = _result(**{"f:aarch64:O2": {"__lane__": "cross-build-failed: boom"}})
    (problem,) = A.comparison_problems(cur, base)
    assert "newly broken" in problem


def test_a_declared_gap_that_became_buildable_is_a_problem():
    """A lane recorded unsupported is excluded from the per-function comparison.
    Where the toolchain IS provisioned it runs, and its real results would
    silently drop out of the gate."""
    base = _result(**{"f:armv7:O0": {"__lane__": A.UNSUPPORTED_PREFIX + "no __int128"}})
    cur = _result(**{"f:armv7:O0": {"g": "fail"}})
    (problem,) = A.comparison_problems(cur, base)
    assert "built and ran it" in problem


def test_a_lane_that_became_unsupported_is_a_problem():
    base = _result(**{"f:armv7:O0": {"g": "pass"}})
    cur = _result(**{"f:armv7:O0": {"__lane__": A.UNSUPPORTED_PREFIX + "no __int128"}})
    (problem,) = A.comparison_problems(cur, base)
    assert "provision the toolchain" in problem


def test_a_stable_declared_gap_is_not_a_problem():
    lane = {"__lane__": A.UNSUPPORTED_PREFIX + "no __int128"}
    base = _result(**{"f:armv7:O0": dict(lane)})
    assert A.comparison_problems(_result(**{"f:armv7:O0": dict(lane)}), base) == []


# ---------------------------------------------------------------------------
# Fail-closed: what may never be written, and what may never be compared
# ---------------------------------------------------------------------------


def test_a_lane_error_may_not_be_written_as_a_baseline():
    for lane_error in (
        "missing-compiler: aarch64-linux-gnu-gcc",
        "cross-build-failed: internal compiler error",
        "reference-build-failed: nope",
        "no functions executed",
        "no DWARF signatures recoverable from x.so",
        "gate-crashed: Traceback",
    ):
        result = _result(**{"f:aarch64:O0": {"__lane__": lane_error}})
        assert A.baseline_problems(result), (
            f"{lane_error!r} was accepted into a baseline — an unverified "
            f"architecture must never be recordable as a result"
        )


def test_infrastructure_statuses_may_not_be_written_as_a_baseline():
    """`timeout` says the machine was slow, `missing`/`nocases` say the harness
    could not ask the question — none is a verdict on the decompiler."""
    for status in ("missing", "nocases", "timeout"):
        result = _result(**{"f:aarch64:O0": {"g": status}})
        assert A.baseline_problems(result), status


def test_known_failures_are_writable_as_a_baseline():
    """The whole point of a baseline is to record what is currently broken."""
    result = _result(
        **{
            "f:aarch64:O0": {"g": "fail", "h": "pass", "i": "structural"},
            "f:armv7:O0": {"__lane__": A.UNSUPPORTED_PREFIX + "no __int128"},
        }
    )
    assert A.baseline_problems(result) == []


def test_schema_requires_every_declared_fixture_in_every_lane():
    """One `missing lane` per fixture this tool is RESPONSIBLE for.

    That is the C/C++ corpus, not the whole manifest. `TARGETS` configures no
    cross-`rustc`, so `schema_problems` deliberately scopes itself to fixtures
    with a C or C++ source — otherwise every `--write-baseline` refused with six
    "only declared" entries that no amount of building could satisfy. This
    assertion counted the raw manifest and so drifted the moment the Rust
    fixtures joined it: 181 declared against 175 answerable.
    """
    matrix = [("x86_64", "O0")]
    problems = A.schema_problems(_result(), matrix)
    cross_buildable = [
        name
        for name in M.REQUIRED_FUNCTIONS
        if (A.SRC / f"{name}.c").exists() or (A.SRC / f"{name}.cpp").exists()
    ]
    assert cross_buildable, "no C/C++ fixture sources found"
    assert len(problems) == len(cross_buildable)
    assert all("missing lane" in p for p in problems)


def test_schema_rejects_an_unknown_status():
    matrix = [("x86_64", "O0")]
    lanes = {
        A.lane_key(stem, "x86_64", "O0"): {"g": "pass"} for stem in M.REQUIRED_FUNCTIONS
    }
    lanes["01_conditional_polarity:x86_64:O0"] = {"g": "probably fine"}
    problems = A.schema_problems(_result(**lanes), matrix)
    assert problems == [
        "01_conditional_polarity:x86_64:O0:g: bad status 'probably fine'"
    ]


def test_schema_requires_a_toolchain_fingerprint():
    assert any(H.TOOLCHAIN_KEY in p for p in A.schema_problems({}, [("x86_64", "O0")]))


def test_toolchain_mismatch_is_reported_for_both_compilers():
    """Two different compilers shape every verdict: the one that builds the
    fixture (its codegen is what the lifter is asked to recover) and the pinned
    one that rebuilds our decompiled C. Either moving invalidates the baseline."""
    assert A.toolchain_problems(None, FP), "a missing fingerprint must be a problem"
    drifted = {**FP, "fixture": {**FP_FIXTURE, "aarch64": "16"}}
    (problem,) = A.toolchain_problems(FP, drifted)
    assert "fixture cc[aarch64]" in problem
    assert A.toolchain_problems(FP, dict(FP)) == []


def test_toolchain_mismatch_covers_the_pinned_rebuild_toolchain():
    drifted = {**FP, "rebuild": {**FP_REBUILD, "gcc": "gcc 14"}}
    problems = A.toolchain_problems(FP, drifted)
    assert any(p.startswith("rebuild ") and "gcc" in p for p in problems)


def test_toolchain_mismatch_covers_the_target_execution_runtime():
    recorded = {**FP, "runner": {"armv7": "qemu-arm 10.2"}}
    current = {**FP, "runner": {"armv7": "qemu-arm 10.3"}}
    (problem,) = A.toolchain_problems(recorded, current)
    assert problem.startswith("target runner[armv7]")


def test_a_run_with_address_randomization_is_not_comparable():
    """A recovery that reads an uninitialised local dereferences whatever the
    stack held. `09_memory_effects:armv7:O2:read_counter` segfaulted on 4 of 8
    identical runs and passed on the other 4 — one flapping function is enough to
    make a ratchet unusable, so the setting is part of the fingerprint."""
    randomized = {**FP, "aslr": "RANDOMIZED"}
    (problem,) = A.toolchain_problems(FP, randomized)
    assert problem.startswith("aslr:") and "setarch" in problem


def test_the_worker_is_launched_with_address_randomization_disabled():
    prefix = BG.worker_launch_prefix()
    if shutil.which("setarch") is None:
        assert prefix == [] and BG.aslr_mode() == "RANDOMIZED"
    else:
        assert prefix[1:] == ["--addr-no-randomize"]
        assert "no-randomize" in BG.aslr_mode()
    # ...and the differential actually uses it, or the fingerprint lies.
    source = (ROOT / "tools" / "diff_decompile.py").read_text()
    assert "BG.worker_launch_prefix()" in source


def test_the_worker_environment_is_fixed_width_and_shell_independent():
    """Disabling randomization is not enough. The environment block sits at the
    top of the initial stack, so its SIZE shifts every frame beneath it: the same
    `read_counter` build passed in an interactive shell and failed under the
    gate's `env -i`. The worker therefore gets a canonical, fixed-width block."""
    import os

    baseline = BG.worker_env()
    assert set(baseline) >= {"PATH", "HOME", "LC_ALL", "TZ"}
    assert "GLAURUNG_STACK_PAD" in baseline

    def width(env):
        return sum(len(k) + len(v) + 2 for k, v in env.items())

    # A caller's exported junk must not reach the worker, and must not move it.
    with_junk = dict(os.environ)
    try:
        os.environ["SOME_UNRELATED_EXPORT"] = "x" * 500
        polluted = BG.worker_env()
    finally:
        os.environ.clear()
        os.environ.update(with_junk)
    assert "SOME_UNRELATED_EXPORT" not in polluted
    assert width(polluted) == width(baseline)

    source = (ROOT / "tools" / "diff_decompile.py").read_text()
    assert "env=BG.worker_env()" in source


def test_the_worker_sees_only_fixed_length_paths(tmp_path):
    """The third channel, and the subtlest. The dynamic loader's own stack use
    scales with the path it is handed, so an absolute `dlopen` argument made the
    residue an uninitialised local reads depend on how long the scratch directory
    happened to be: the same build of `04_switch_shapes:armv7:O0:dense_compute`
    reported `fail` from `/tmp/aa` and `pass` from a 65-character sibling. The
    worker therefore runs with `cwd=workdir` and every path in its spec is a
    short relative name."""
    src = tmp_path / "p.c"
    src.write_text("int f(int a){ return a + 1; }\n")
    so = tmp_path / "p.so"
    _build(["gcc", "-shared", "-fPIC", "-g", "-O0", "-w", "-o", str(so), str(src)])
    work = tmp_path / "work"
    work.mkdir()

    reference = D._fixed_name_sibling(so, work)
    assert reference.name == D.REFERENCE_LINK_NAME
    # A COPY, not a symlink: the pinned toolchain compiles in a container that
    # mounts only what the command line names, and a symlink out of `workdir`
    # dangles there — which silently drops the link and produced 42 x86-64
    # `undefined symbol` failures.
    assert not reference.is_symlink()
    assert reference.read_bytes() == so.read_bytes()
    assert D._fixed_name_sibling(so, work) == reference  # idempotent

    source = (ROOT / "tools" / "diff_decompile.py").read_text()
    assert "cwd=str(workdir)" in source
    assert '"orig_so": f"./{' in source
    assert '"dec_so": f"./{' in source
    assert '"-Wl,-rpath,$ORIGIN"' in source


# ---------------------------------------------------------------------------
# The control lane
# ---------------------------------------------------------------------------


def test_the_control_lane_may_not_be_dropped_from_the_matrix():
    """`x86_64` decompiles a host object and diffs it against a host reference,
    so every failure it reports is this harness or a bug the x86-64 gate already
    sees. Without it, a foreign-architecture percentage is uninterpretable."""
    (problem,) = A.control_problems(_result(), [("aarch64", "O0")])
    assert "control lane is absent" in problem


def test_a_failing_control_lane_is_a_problem():
    result = _result(**{"f:x86_64:O0": {"g": "fail"}})
    (problem,) = A.control_problems(result, [("x86_64", "O0")])
    assert "control lane f:x86_64:O0" in problem and "g=fail" in problem


def test_a_broken_control_lane_is_a_problem():
    result = _result(**{"f:x86_64:O0": {"__lane__": "cross-build-failed: boom"}})
    assert A.control_problems(result, [("x86_64", "O0")])


def test_foreign_architecture_failures_do_not_trip_the_control_check():
    """The control lane gates interpretation, not the other lanes' verdicts —
    those are what the baseline ratchets."""
    result = _result(
        **{
            "f:x86_64:O0": {"g": "pass", "h": "structural"},
            "f:aarch64:O0": {"g": "fail"},
        }
    )
    assert A.control_problems(result, [("x86_64", "O0"), ("aarch64", "O0")]) == []


def test_the_control_lane_must_reproduce_the_x86_64_gate_verdict_for_verdict():
    """The control lane compiles with the same pinned compiler and the same flags
    as `fixture_harness`, so `fixture:x86_64:{opt}` and the committed
    `fixture:gcc:{opt}` ask the identical question through a different code path.
    Any disagreement is THIS tool's plumbing and would otherwise be invisible."""
    gate = {H.TOOLCHAIN_KEY: {}, "f:gcc:O0": {"g": "pass", "h": "fail"}}
    agreeing = _result(**{"f:x86_64:O0": {"g": "pass", "h": "fail"}})
    assert A.control_gate_disagreements(agreeing, gate) == []

    disagreeing = _result(**{"f:x86_64:O0": {"g": "fail", "h": "fail"}})
    (problem,) = A.control_gate_disagreements(disagreeing, gate)
    assert "f:x86_64:O0:g" in problem and "'fail'" in problem and "'pass'" in problem


def test_a_control_lane_function_the_x86_64_gate_never_saw_is_a_disagreement():
    """An extra or missing function is the shape a wrong export filter takes —
    the exact bug that let 11 file-local statics be reported as failures."""
    gate = {H.TOOLCHAIN_KEY: {}, "f:gcc:O0": {"g": "pass"}}
    extra = _result(**{"f:x86_64:O0": {"g": "pass", "static_helper": "fail"}})
    (problem,) = A.control_gate_disagreements(extra, gate)
    assert "static_helper" in problem


def test_control_gate_disagreements_ignores_non_control_lanes():
    gate = {H.TOOLCHAIN_KEY: {}, "f:gcc:O0": {"g": "pass"}}
    foreign = _result(**{"f:aarch64:O0": {"g": "fail"}})
    assert A.control_gate_disagreements(foreign, gate) == []


def test_the_control_lane_is_compiled_exactly_like_the_x86_64_gate():
    """Byte-identical flags, or the comparison above is not a comparison. In
    particular `-fno-stack-protector` (which the prototype added) would mean the
    control lane measured a code shape the real gate never sees."""
    src = Path("/tmp/x.c")
    out = Path("/tmp/x.so")
    ours = A._build_argv("gcc", src, "O2", out)
    # The remap flags are taken FROM `fixture_harness` rather than restated, for
    # the same reason as every other flag here: a control lane compiled unlike
    # the gate is not a control. See `fixture_harness.path_remap_flags` for why
    # an absolute build path in the object moves the census.
    theirs = [
        "gcc",
        "-shared",
        "-fPIC",
        "-g",
        "-O2",
        "-w",
        *H.path_remap_flags("gcc"),
        "-o",
        str(out),
        str(src),
    ]
    assert ours == theirs, f"{ours} != fixture_harness.compile_fixture's {theirs}"
    assert H.path_remap_flags("gcc"), (
        "the build must erase the checkout path, or a fixture object differs "
        "between checkouts and every census built on it is a property of the "
        "build directory"
    )
    assert A.TARGETS[A.CONTROL_ARCH].cflags == (), (
        "the control lane must add no target-selection flags at all"
    )
    assert A.TARGETS[A.CONTROL_ARCH].pinned, (
        "the control lane must build under the pinned image, or its verdicts are "
        "not comparable to the committed x86-64 baseline"
    )


def test_the_control_architecture_is_in_the_required_matrix():
    assert A.CONTROL_ARCH in A.REQUIRED_ARCHES
    assert all((A.CONTROL_ARCH, opt) in A.REQUIRED_MATRIX for opt in A.REQUIRED_OPTS)


def test_the_required_matrix_covers_every_lifted_architecture_and_both_opts():
    """x86-64 alone is what the existing 656-case gate already measures. The
    point of this lane is the other three families, both ARM32 instruction sets,
    and an optimised build."""
    assert set(A.REQUIRED_ARCHES) == {
        "x86_64",
        "i386",
        "aarch64",
        "armv7",
        "armv7_a32",
        "x86_64_gcc15",
    }
    assert set(A.REQUIRED_OPTS) == {"O0", "O2"}
    assert len(A.REQUIRED_MATRIX) == 12


def test_arm32_required_lanes_select_distinct_instruction_sets():
    assert "-mthumb" in A.TARGETS["armv7"].cflags
    assert "-marm" in A.TARGETS["armv7_a32"].cflags


def test_gcc15_x86_64_shape_control_is_required_and_host_built():
    control = A.TARGETS["x86_64_gcc15"]

    assert "x86_64_gcc15" in A.REQUIRED_ARCHES
    assert control.cc == "gcc"
    assert control.cflags == ()
    assert control.pointer_bytes == 8
    assert control.pinned is False


# ---------------------------------------------------------------------------
# Real round trips: the two harness bugs the prototype shipped
# ---------------------------------------------------------------------------

_STATIC_CALLEE_SRC = """
static int helper(int x) { return x * 3 + 1; }
int caller(int x) { return helper(x) - 2; }
"""


def _build(argv: list[str]) -> None:
    r = TC.run(argv)
    assert r.returncode == 0, r.stderr


def test_only_exported_functions_are_executed(tmp_path):
    """A file-local `static` root is a harness artifact twice over.

    It has no dynamic symbol, so the reference side cannot be called through
    ctypes at all; and because it IS local, `include_referenced_local_callees`
    matches the definition line of the very body under test and prepends it,
    so the rebuild dies with `redefinition of ...`. The prototype executed every
    DWARF subprogram and turned those 11 artifacts into "decompiler failures" in
    both the x86-64 control lane and the AArch64 lane — identical counts, which
    is what gave the harness away.
    """
    src = tmp_path / "statics.c"
    src.write_text(_STATIC_CALLEE_SRC)
    so = tmp_path / "statics.so"
    _build(["gcc", "-shared", "-fPIC", "-g", "-O0", "-w", "-o", str(so), str(src)])

    assert "helper" in D.defined_functions(str(so)), (
        "the static helper must exist in .symtab, or this test proves nothing"
    )
    assert "helper" not in D.exported_functions(str(so))

    results = D.run(str(so), str(src), "statics", seed=1234, fuzz=4)
    assert "__error__" not in results, results
    assert "helper" not in results, (
        f"a file-local static was executed as a root: {results.get('helper')}"
    )
    assert results["caller"]["status"] == "pass", results["caller"]


def test_zero_recoverable_signatures_is_an_error_not_a_green_structural_run(
    monkeypatch, tmp_path
):
    """With DWARF present but no signature recoverable, every function used to
    degrade to `structural` — a lane that executes nothing and reports success.
    That is precisely the silent-green shape this tool exists to eliminate."""
    src = tmp_path / "sig.c"
    src.write_text("int f(int a){ return a + 1; }\n")
    so = tmp_path / "sig.so"
    _build(["gcc", "-shared", "-fPIC", "-g", "-O0", "-w", "-o", str(so), str(src)])
    monkeypatch.setattr(D, "signatures", lambda _binary: [])
    results = D.run(str(so), str(src), "sig", seed=1, fuzz=1)
    assert "__error__" in results and "signature" in results["__error__"]


_SIBLING_CALL_SRC = """
int callee(int x) { return x * 7; }
int caller(int x) { return callee(x) + 1; }
"""


@pytest.mark.skipif(
    shutil.which(A.TARGETS["aarch64"].cc) is None,
    reason=f"{A.TARGETS['aarch64'].cc} is not installed on this host",
)
def test_a_cross_lane_links_the_rebuild_against_the_host_reference(tmp_path):
    """The rebuilt C must link against the HOST reference, not the target object.

    `build_so_with_diagnostic` links the rebuilt decompilation against the
    original so a call to an exported sibling keeps its real behaviour. Handed an
    AArch64 object that link silently fails, the rebuild falls back to unlinked,
    and every recovered body that calls a sibling then dies at load time with
    `undefined symbol` — 44 of the prototype's ARM "failures" were exactly this.
    """
    src = tmp_path / "sibling.c"
    src.write_text(_SIBLING_CALL_SRC)
    target = tmp_path / "sibling-aarch64.so"
    ok, err = A._cross_build("aarch64", src, "O0", target)
    assert ok, err
    reference = tmp_path / "sibling-host.so"
    ok, err = A._reference_build(src, "O0", reference)
    assert ok, err

    results = D.run(
        str(target),
        str(src),
        "sibling",
        seed=1234,
        fuzz=4,
        reference_so=str(reference),
        lane="aarch64:O0",
        only={"caller"},
    )
    assert "__error__" not in results, results
    detail = str(results["caller"].get("detail", ""))
    assert "undefined symbol" not in detail, detail


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
@pytest.mark.parametrize(
    ("fixture", "function"),
    [
        ("07_packet_parser", "validate_header"),
        ("17_hash_table", "hash_lookup"),
        ("19_disjoint_set", "dsu_find"),
    ],
)
@pytest.mark.skipif(
    shutil.which(A.TARGETS["aarch64"].cc) is None,
    reason=f"{A.TARGETS['aarch64'].cc} is not installed on this host",
)
def test_aarch64_spilled_arg0_call_results_round_trip(
    tmp_path: Path, fixture: str, function: str
) -> None:
    """A helper result must not inherit the caller's incoming ``arg0`` role."""
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O0.so"
    ok, error = A._cross_build("aarch64", source, "O0", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O0.so"
    ok, error = A._reference_build(source, "O0", reference)
    assert ok, error

    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O0",
        native_cc=A.native_cc("aarch64"),
        only={function},
    )

    assert results[function]["status"] == "pass", results[function]


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_o0_distinct_call_result_types_round_trip(tmp_path: Path) -> None:
    """Sequential ``x0`` results must retain their own callee prototypes."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "07_packet_parser"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O0.so"
    ok, error = A._cross_build("aarch64", source, "O0", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O0.so"
    ok, error = A._reference_build(source, "O0", reference)
    assert ok, error

    function = "parse_packet"
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O0",
        native_cc=A.native_cc("aarch64"),
        only={function},
    )

    assert results[function]["status"] == "pass", results[function]


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_recursive_saved_parameter_round_trips(tmp_path: Path) -> None:
    """A recursive call must not replace a saved entry parameter with x0."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "06_calling_conventions"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    function = "fact_mod"
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only={function},
    )

    assert results[function]["status"] == "pass", results[function]


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_vectorized_find_first_set_round_trips(tmp_path: Path) -> None:
    """A packed pre-scan must preserve the scalar search window and result."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "12_loop_rotation"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    function = "find_first_set"
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only={function},
    )

    assert results[function]["status"] == "pass", results[function]


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_aliased_load_pair_round_trips_rb_validation(tmp_path: Path) -> None:
    """LDP aliases and BFI partial definitions must round-trip without live-ins."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "16_red_black_tree"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    function = "rb_validate"
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only={function},
    )

    assert results[function]["status"] == "pass", results[function]

    functions = D.exported_functions(str(target))
    code = D.decompiled_c(str(target), functions[function])
    assert code is not None
    assigned = set(re.findall(r"(?m)^\s*(var\d+)\s*=", code))
    copied_sources = set(re.findall(r"(?m)^\s*var\d+\s*=\s*(var\d+)\s*;", code))
    assert copied_sources <= assigned, (
        "an unobserved preserved BFI lane became an undefined C live-in: "
        f"{sorted(copied_sources - assigned)}\n{code}"
    )


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_packed_bit_insert_round_trips_topological_sort(tmp_path: Path) -> None:
    """BIT must preserve masked indegrees before Kahn queue construction."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "23_topological_sort"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    function = "topological_sort"
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only={function},
    )

    assert results[function]["status"] == "pass", results[function]


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_optimized_call_flow_round_trips(tmp_path: Path) -> None:
    """Implicit x0 inputs survive loops and a prior-call-result tail call."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "11_call_shapes"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    functions = {"call_chain_in_loop", "call_into_spill"}
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only=functions,
    )

    assert {
        function: results[function]["status"] for function in sorted(functions)
    } == {function: "pass" for function in sorted(functions)}, results


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_optimized_indirect_tail_dispatch_round_trips(tmp_path: Path) -> None:
    """AArch64 ``br`` must return the selected function-table result."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "08_indirect_dispatch"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    functions = {"dispatch", "tail_dispatch"}
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only=functions,
    )

    assert {
        function: results[function]["status"] for function in sorted(functions)
    } == {function: "pass" for function in sorted(functions)}, results


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_optimized_readonly_switch_results_round_trip(tmp_path: Path) -> None:
    """A terminating range guard must make the following table load portable."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "04_switch_shapes"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    functions = {"negative_cases", "sparse_shared_tail"}
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only=functions,
    )

    assert {
        function: results[function]["status"] for function in sorted(functions)
    } == {function: "pass" for function in sorted(functions)}, results


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
@pytest.mark.parametrize(  # ty: ignore[unresolved-attribute]
    "arch", ["armv7", "armv7_a32"]
)
def test_arm32_optimized_readonly_switch_result_round_trips(
    tmp_path: Path, arch: str
) -> None:
    """Thumb-2 and A32 early guards must make the table result portable."""
    if shutil.which(A.TARGETS[arch].cc) is None:
        pytest.skip(f"{A.TARGETS[arch].cc} is not installed on this host")
    fixture = "04_switch_shapes"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-{arch}-O2.so"
    ok, error = A._cross_build(arch, source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    function = "negative_cases"
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane=f"{arch}:O2",
        native_cc=A.native_cc(arch),
        native_runner=A.native_runner(arch),
        only={function},
    )

    assert results[function]["status"] == "pass", results[function]


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_a32_instruction_predication_round_trips_conditional_polarity(
    tmp_path: Path,
) -> None:
    """A32 condition fields must guard data writes and register returns."""
    arch = "armv7_a32"
    if shutil.which(A.TARGETS[arch].cc) is None:
        pytest.skip(f"{A.TARGETS[arch].cc} is not installed on this host")
    fixture = "01_conditional_polarity"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-{arch}-O2.so"
    ok, error = A._cross_build(arch, source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    functions = {
        "classify",
        "cmp_signed",
        "cmp_unsigned",
        "early_return",
        "early_return_ge",
        "elseif",
        "nested",
        "sc_and",
        "sc_mixed",
        "sc_or",
        "ternary",
        "ternary_nested",
    }
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane=f"{arch}:O2",
        native_cc=A.native_cc(arch),
        native_runner=A.native_runner(arch),
        only=functions,
    )

    assert {
        function: results[function]["status"] for function in sorted(functions)
    } == {function: "pass" for function in sorted(functions)}, results


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_a32_predicated_store_round_trips_cas_update(tmp_path: Path) -> None:
    """A false A32 store predicate must leave target memory untouched."""
    arch = "armv7_a32"
    if shutil.which(A.TARGETS[arch].cc) is None:
        pytest.skip(f"{A.TARGETS[arch].cc} is not installed on this host")
    fixture = "09_memory_effects"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-{arch}-O2.so"
    ok, error = A._cross_build(arch, source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    function = "cas_update"
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane=f"{arch}:O2",
        native_cc=A.native_cc(arch),
        native_runner=A.native_runner(arch),
        only={function},
    )

    assert results[function]["status"] == "pass", results[function]


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_optimized_clz_idiom_round_trips(tmp_path: Path) -> None:
    """AArch64 CLZ must define the exact-width bit-length computation."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "14_flag_effects"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    function = "shift_until_zero"
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only={function},
    )

    assert results[function]["status"] == "pass", results[function]


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_optimized_factorial_preserves_its_wide_accumulator(
    tmp_path: Path,
) -> None:
    """64-bit x0 loop results must not inherit 32-bit x0 input types."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "12_loop_rotation"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    functions = {"factorial_while", "nested_rotated"}
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only=functions,
    )

    assert {
        function: results[function]["status"] for function in sorted(functions)
    } == {function: "pass" for function in sorted(functions)}, results


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_o0_kmp_array_initializer_aliases_indexed_storage(
    tmp_path: Path,
) -> None:
    """A scalar ``prefix[0]`` store must define the indexed array object."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "25_kmp_search"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O0.so"
    ok, error = A._cross_build("aarch64", source, "O0", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O0.so"
    ok, error = A._reference_build(source, "O0", reference)
    assert ok, error

    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O0",
        native_cc=A.native_cc("aarch64"),
        only={"kmp_search"},
    )

    assert results["kmp_search"]["status"] == "pass", results


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_o2_horizontal_reduction_preserves_all_integer_lanes(
    tmp_path: Path,
) -> None:
    """AArch64 ADDV must reduce every packed lane into the integer result."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "03_loop_shapes"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only={"for_sum"},
    )

    assert results["for_sum"]["status"] == "pass", results


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_o2_signed_lane_max_preserves_continue_semantics(
    tmp_path: Path,
) -> None:
    """AArch64 SMAX must exclude every negative packed lane from the sum."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "03_loop_shapes"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only={"loop_continue"},
    )

    assert results["loop_continue"]["status"] == "pass", results


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_o2_byte_table_permutation_preserves_reverse_mutation(
    tmp_path: Path,
) -> None:
    """AArch64 TBL must preserve every byte of an in-place vectorized reverse."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "03_loop_shapes"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only={"mutate_reverse"},
    )

    assert results["mutate_reverse"]["status"] == "pass", results


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_o0_unsigned_byte_load_preserves_zero_offset_parameter_access(
    tmp_path: Path,
) -> None:
    """AArch64 LDRB must not make ``uint8_t *arg`` signed at offset zero."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "05_cleanup_and_state_machine"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O0.so"
    ok, error = A._cross_build("aarch64", source, "O0", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O0.so"
    ok, error = A._reference_build(source, "O0", reference)
    assert ok, error

    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O0",
        native_cc=A.native_cc("aarch64"),
        only={"process"},
    )

    assert results["process"]["status"] == "pass", results


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_o2_halfword_byte_swap_preserves_packet_length_bounds(
    tmp_path: Path,
) -> None:
    """AArch64 REV16 must decode each big-endian uint16_t packet field."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "07_packet_parser"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only={"parse_packet", "validate_header"},
    )

    assert results["validate_header"]["status"] == "pass", results
    assert results["parse_packet"]["status"] == "pass", results


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_o0_non_byte_aligned_extracts_keep_all_live_bits(
    tmp_path: Path,
) -> None:
    """AArch64 UBFIZ bit slices must not be narrowed to whole bytes."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "02_integer_widths"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O0.so"
    ok, error = A._cross_build("aarch64", source, "O0", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O0.so"
    ok, error = A._reference_build(source, "O0", reference)
    assert ok, error

    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O0",
        native_cc=A.native_cc("aarch64"),
        only={"rotl16_3", "trunc_u16_after_mul"},
    )

    assert results["rotl16_3"]["status"] == "pass", results
    assert results["trunc_u16_after_mul"]["status"] == "pass", results


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_o2_x0_roles_preserve_wide_product_and_identity_return(
    tmp_path: Path,
) -> None:
    """Distinct wide and identity-result x0 roles must retain their values."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "02_integer_widths"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only={"mul_widen", "rt_u32"},
    )

    assert results["mul_widen"]["status"] == "pass", results
    assert results["rt_u32"]["status"] == "pass", results


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_aarch64_o2_direct_callee_live_ins_preserve_a_wide_call_result(
    tmp_path: Path,
) -> None:
    """A locked two-argument call and its 64-bit x0 result need distinct roles."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    fixture = "11_call_shapes"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only={"call_fold_wide_result"},
    )

    assert results["call_fold_wide_result"]["status"] == "pass", results


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
@pytest.mark.parametrize(  # ty: ignore[unresolved-attribute]
    ("fixture", "function"),
    [
        ("15_binary_search_tree", "bst_inorder_checksum"),
        ("20_graph_bfs", "graph_bfs"),
    ],
)
def test_aarch64_o2_stack_protected_functions_return_through_their_canary(
    tmp_path: Path, fixture: str, function: str
) -> None:
    """A structured stack guard must not force every valid return to abort."""
    if shutil.which(A.TARGETS["aarch64"].cc) is None:
        pytest.skip(f"{A.TARGETS['aarch64'].cc} is not installed on this host")
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-aarch64-O2.so"
    ok, error = A._cross_build("aarch64", source, "O2", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O2.so"
    ok, error = A._reference_build(source, "O2", reference)
    assert ok, error

    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane="aarch64:O2",
        native_cc=A.native_cc("aarch64"),
        only={function},
    )

    assert results[function]["status"] == "pass", results


def test_reference_so_defaults_to_the_binary_so_host_lanes_are_unchanged(tmp_path):
    """Every x86-64 lane must be bit-identical to what it was before
    `reference_so` existed, or the 656-case gate is measuring something new."""
    src = tmp_path / "same.c"
    src.write_text("int f(int a){ return a * 2; }\n")
    so = tmp_path / "same.so"
    _build(["gcc", "-shared", "-fPIC", "-g", "-O0", "-w", "-o", str(so), str(src)])
    sig = next(s for s in D.signatures(str(so)) if s["name"] == "f")
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        implicit = D.run_function(sig, "same", str(so), Path(td), 1234, 4)
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        explicit = D.run_function(
            sig, "same", str(so), Path(td), 1234, 4, reference_so=str(so)
        )
    assert implicit["status"] == explicit["status"] == "pass"


# ---------------------------------------------------------------------------
# Fail-closed lane execution (no compiler / no build)
# ---------------------------------------------------------------------------


def test_a_missing_cross_compiler_is_a_lane_error_not_a_skip(monkeypatch, tmp_path):
    src = tmp_path / "x.c"
    src.write_text("int f(int a){return a;}\n")
    monkeypatch.setattr(A.shutil, "which", lambda _name: None)
    lane = A._run_lane(src, "aarch64", "O0", fuzz=1, unsupported=None)
    assert lane["__lane__"].startswith("missing-compiler:")
    assert not A.is_unsupported(lane)
    assert A.baseline_problems(_result(**{"f:aarch64:O0": lane}))


def test_a_failed_cross_build_is_a_lane_error_not_a_skip(tmp_path):
    src = tmp_path / "broken.c"
    src.write_text("this is not C at all;\n")
    lane = A._run_lane(src, A.CONTROL_ARCH, "O0", fuzz=1, unsupported=None)
    assert lane["__lane__"].startswith("cross-build-failed:")
    assert not A.is_unsupported(lane)


def test_a_stale_unsupported_exemption_is_an_assertion_failure(tmp_path):
    """A declared gap must be a REAL gap. If the source builds after all, the
    exemption is silently hiding a lane that could have been measured."""
    src = tmp_path / "fine.c"
    src.write_text("int f(int a){return a;}\n")
    with pytest.raises(AssertionError, match="stale"):
        A._run_lane(src, A.CONTROL_ARCH, "O0", fuzz=1, unsupported="not really")


def test_int128_is_probed_per_architecture_not_hardcoded():
    """The 32-bit exemption for `__int128` is derived from a compile probe plus
    the source text, so a new fixture using it — or a target that grows support —
    changes the answer without anyone editing a list of fixture names."""
    assert A._supports_int128(A.CONTROL_ARCH)
    if shutil.which("gcc") is not None:
        probe = subprocess.run(
            ["gcc", "-m32", "-E", "-"],
            input="int x;\n",
            capture_output=True,
            text=True,
            check=False,
        )
        if probe.returncode == 0:
            assert not A._supports_int128("i386")


def test_declared_gaps_name_a_reason():
    for (arch, fixture), reason in A.detect_unsupported(A.REQUIRED_ARCHES).items():
        assert arch in A.TARGETS
        assert fixture in M.REQUIRED_FUNCTIONS
        assert reason and reason.strip() == reason, (arch, fixture, reason)


# ---------------------------------------------------------------------------
# The committed baseline
# ---------------------------------------------------------------------------


def test_the_committed_baseline_is_valid_and_has_a_clean_control_lane():
    """The baseline must itself satisfy every rule `--check` applies: no lane
    errors, no infrastructure statuses, every fixture in every required lane, and
    a control lane with nothing but `pass`/`structural` in it."""
    assert A.BASELINE.is_file(), (
        f"{A.BASELINE} is missing — regenerate with "
        f"`tools/arch_roundtrip.py --write-baseline`"
    )
    import json

    baseline = json.loads(A.BASELINE.read_text())
    # The control lane is trustworthy when it AGREES WITH THE GATE, not when it
    # is free of failure — see `control_problems`, which takes the x86-64 gate
    # baseline for exactly this comparison. Omitting it here silently selected
    # the stricter fallback ("every control verdict must be `pass`"), and that
    # is what held `arch_baseline.json` to the 30 fixtures the decompiler
    # happens to be perfect on: a function with a known, recorded x86-64 failure
    # still has a meaningful ARM comparison against that recorded result.
    gate_baseline = json.loads(H.BASELINE.read_text())
    problems = (
        A.baseline_problems(baseline)
        + A.schema_problems(baseline, A.REQUIRED_MATRIX)
        + A.control_problems(baseline, A.REQUIRED_MATRIX, gate_baseline)
    )
    assert not problems, "COMMITTED ARCH BASELINE INVALID:\n  " + "\n  ".join(problems)


def test_the_committed_baseline_covers_every_lifted_architecture():
    import json

    baseline = json.loads(A.BASELINE.read_text())
    seen = {key.split(":")[1] for key in H.lanes(baseline)}
    assert seen == set(A.REQUIRED_ARCHES), seen


# ---------------------------------------------------------------------------
# The 32-bit confound: ABI comparability, native rebuild, width audit
# ---------------------------------------------------------------------------


def _multilib_available(tmp_path) -> bool:
    """Can this host build a 32-bit object at all? Probed, never assumed — the
    probe's verdict is only meaningful where the target toolchain exists."""
    if shutil.which("gcc") is None:
        return False
    source = tmp_path / "multilib_probe.c"
    source.write_text("int probe(int x){ return x + 1; }\n")
    return (
        subprocess.run(
            ["gcc", "-m32", "-c", "-o", str(tmp_path / "p.o"), str(source)],
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )


def _sig(name: str, ret: dict, *params: dict) -> dict:
    return {"name": name, "va": 0x1000, "params": list(params), "ret": ret}


_I32 = {"k": "int", "w": 4, "s": True}
_I64 = {"k": "int", "w": 8, "s": True}


def test_a_same_architecture_lane_has_nothing_to_compare():
    """`reference_sig is None` is the same-architecture case, where both sides of
    the differential ARE the same object. It must not be read as a mismatch."""
    assert D.abi_incomparable(_sig("f", _I32, _I32), None) is None


def test_identical_prototypes_are_comparable():
    assert (
        D.abi_incomparable(_sig("f", _I32, _I32, _I32), _sig("f", _I32, _I32, _I32))
        is None
    )


def test_a_return_width_that_moves_with_the_target_is_not_comparable():
    """`long count_up(int)` — `w:4` in the i386/ARM32 object, `w:8` in the host
    reference. One ctypes prototype cannot describe both, so the verdict this
    lane used to record (`pass`, on every input small enough not to notice the
    truncation) was not a statement about the lifter."""
    why = D.abi_incomparable(_sig("count_up", _I32, _I32), _sig("count_up", _I64, _I32))
    assert why is not None and "return type differs" in why


def test_a_parameter_width_that_moves_with_the_target_is_not_comparable():
    why = D.abi_incomparable(
        _sig("sum_mixed_widths", _I32, _I32, _I32),
        _sig("sum_mixed_widths", _I32, _I32, _I64),
    )
    assert why is not None and "parameter 1 differs" in why


def test_a_parameter_count_that_differs_is_not_comparable():
    why = D.abi_incomparable(_sig("f", _I32, _I32), _sig("f", _I32, _I32, _I32))
    assert why is not None and "parameter count differs" in why


def test_the_native_probe_is_configured_for_every_foreign_architecture():
    """The control lane is deliberately exempt (its "target" compiler is the host
    one, a DIFFERENT gcc from the pinned rebuild); every other lane must carry the
    probe, or the architecture it names is unchecked for C it cannot spell."""
    assert A.native_cc(A.CONTROL_ARCH) is None
    for arch in A.REQUIRED_ARCHES:
        if arch == A.CONTROL_ARCH:
            continue
        cc = A.native_cc(arch)
        assert cc and cc[0] == A.TARGETS[arch].cc, arch


def test_genuine_target_execution_is_configured_for_all_ilp32_lanes():
    """ILP32 C++ objects cannot be judged inside LP64 ctypes.

    The three 32-bit lanes therefore need a target process, while the two 64-bit
    lanes keep the simpler host-portable differential.
    """
    assert A.native_runner("x86_64") is None
    assert A.native_runner("aarch64") is None
    assert A.native_runner("i386")[:1] == ["qemu-i386"]
    assert A.native_runner("armv7")[:1] == ["qemu-arm"]
    assert A.native_runner("armv7_a32")[:1] == ["qemu-arm"]


def test_native_worker_refuses_malformed_vectors_and_unknown_integer_widths():
    """An unsupported comparator input must fall back, never emit a weak oracle."""
    two_args = _sig("f", _I32, _I32, _I32)
    assert D._native_worker_source(two_args, [[1]], "int") is None

    odd_width = {"k": "int", "w": 3, "s": True}
    assert D._native_worker_source(_sig("f", odd_width), [[]], "int") is None


def test_native_worker_materializes_flat_struct_pointer_arrays_exactly():
    """Plain DWARF structs are ABI-stable inputs, not a reason to fall back."""
    node = {
        "k": "struct",
        "w": 8,
        "name": "Node",
        "fields": [
            {"name": "key", "off": 0, "t": _I32},
            {"name": "color", "off": 4, "t": {"k": "int", "w": 4, "s": False}},
        ],
    }
    sig = _sig("validate", _I32, {"k": "ptr", "p": node, "const": True}, _I32)
    worker = D._native_worker_source(sig, [[[[7, 0], [9, 1]], 2]], "int")

    assert worker is not None
    assert "typedef struct Node" in worker
    assert '_Static_assert(sizeof(Node) == 8, "DWARF layout")' in worker
    assert '_Static_assert(offsetof(Node, color) == 4, "DWARF field offset")' in worker
    assert "typedef int32_t (*measured_fn)(const Node *, int32_t);" in worker
    assert "Node o_0_0[2]" in worker
    assert ".key = (int32_t)(7)" in worker
    assert ".color = (uint32_t)(1)" in worker


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
def test_native_execution_compares_ilp32_returns_and_buffer_effects(tmp_path):
    """Non-vacuity for the generated target worker, using a real i386 process."""
    if not _multilib_available(tmp_path) or shutil.which("qemu-i386") is None:
        pytest.skip("32-bit gcc multilib and qemu-i386 are required")
    original_source = tmp_path / "original.c"
    original_source.write_text(
        "int native_effect(int *out, int x) { out[0] = x + 1; return out[0]; }\n"
    )
    original = tmp_path / "original.so"
    subprocess.run(
        ["gcc", "-m32", "-shared", "-fPIC", "-o", original, original_source],
        check=True,
    )
    sig = _sig(
        "native_effect",
        _I32,
        {"k": "ptr", "p": _I32, "pw": 4, "ps": True},
        _I32,
    )
    vectors = [[[3, 4, 5], 7], [[-1, 0, 1], -3]]
    runner = ["qemu-i386", "-L", "/"]

    good = D.native_execution_differential(
        "int native_effect(int *out, int x) { out[0] = x + 1; return out[0]; }",
        original,
        sig,
        vectors,
        tmp_path,
        ["gcc", "-m32"],
        runner,
        "int",
    )
    assert good == {
        "status": "pass",
        "detail": "2 cases (native target ABI)",
    }

    bad = D.native_execution_differential(
        "int native_effect(int *out, int x) { out[0] = x + 2; return out[0]; }",
        original,
        sig,
        vectors,
        tmp_path,
        ["gcc", "-m32"],
        runner,
        "int",
    )
    assert bad is not None and bad["status"] == "fail"
    assert "native target" in bad["detail"]


@pytest.mark.slow
def test_the_native_probe_rejects_a_type_the_target_cannot_spell(tmp_path):
    """Non-vacuity. `__int128` is what the renderer emitted for every 32-bit
    multiply-high before `double_width_ctype`; the host rebuild accepted it and
    all four lanes stayed green. This probe is the thing that must not."""
    if not _multilib_available(tmp_path):
        pytest.skip("no 32-bit gcc multilib on this host")
    probe = D.native_rebuild_diagnostic(
        "unsigned int mul_high(unsigned int a, unsigned int b) {\n"
        "    return (unsigned int)(((unsigned __int128)a * b) >> 32);\n"
        "}\n",
        tmp_path,
        "int128",
        ["gcc", "-m32"],
    )
    assert probe, "a 32-bit build must reject `__int128` — the probe is vacuous"
    assert "__int128" in probe


@pytest.mark.slow
def test_the_native_probe_accepts_c_the_target_can_spell(tmp_path):
    """The other half of non-vacuity: the probe must not simply always fail. The
    harness's own PRELUDE goes through it too, so this also pins that the
    scaffolding is width-portable (`int64_t` as `long long`, `undefined16`
    guarded)."""
    if not _multilib_available(tmp_path):
        pytest.skip("no 32-bit gcc multilib on this host")
    probe = D.native_rebuild_diagnostic(
        "unsigned int mul_high(unsigned int a, unsigned int b) {\n"
        "    return (unsigned int)(((unsigned long long)a * b) >> 32);\n"
        "}\n",
        tmp_path,
        "portable",
        ["gcc", "-m32"],
    )
    assert probe == "", probe


def test_the_native_prelude_spells_its_64_bit_types_portably():
    """`typedef long int64_t` is 4 bytes on the very targets the probe compiles
    for. Getting this wrong makes the harness's own scaffolding look like a
    decompiler defect on every 32-bit function at once."""
    assert "typedef long long int64_t" in D.NATIVE_PRELUDE
    assert "typedef long int64_t" not in D.NATIVE_PRELUDE
    assert "typedef long int64_t" in D.PRELUDE


def test_width_sensitivity_is_decided_by_the_types_named():
    assert not D.width_sensitive("int f(int a){ return a + 1; }")
    assert not D.width_sensitive("long long f(int a){ return (long long)a * a; }")
    assert D.width_sensitive("long f(int a){ return a; }")
    assert D.width_sensitive("unsigned long f(int a){ return a; }")
    assert D.width_sensitive("int f(int a){ return (int)(size_t)a; }")
    assert D.width_sensitive("__int128 f(long long a){ return a; }")


def test_the_width_audit_separates_residue_from_real_defects():
    """A 32-bit failure whose recovered C names no width-varying type computes the
    same values at either width, so the host rebuild IS the 32-bit semantics and
    the failure is real. One that does cannot be separated by this apparatus."""
    detailed = _result(
        **{
            "f:i386:O0": {
                "real_one": {"status": "fail", "width_sensitive": False},
                "residue": {"status": "fail", "width_sensitive": True},
                "nonport": {"status": "nonportable", "width_sensitive": False},
                "fine": {"status": "pass", "width_sensitive": True},
            },
            # 64-bit lanes carry no confound and are not audited at all.
            "f:aarch64:O0": {"other": {"status": "fail", "width_sensitive": True}},
        }
    )
    audit = A.width_audit(detailed)
    assert set(audit) == {"i386"}
    assert audit["i386"]["real"] == ["f:O0:real_one"]
    assert audit["i386"]["artifact"] == ["f:O0:residue"]
    assert audit["i386"]["nonportable"] == ["f:O0:nonport"]


def test_a_reclassification_between_two_non_pass_statuses_still_ratchets():
    """`fail -> nonportable` is neither a regression nor an improvement, but it is
    the gate learning something new about that function. Absorbing it silently is
    how a reclassification lands in a baseline with nobody having looked."""
    problems = A.comparison_problems(
        _result(**{"f:i386:O0": {"g": "nonportable"}}),
        _result(**{"f:i386:O0": {"g": "fail"}}),
    )
    assert any("RECLASSIFIED fail -> nonportable" in p for p in problems)


def test_an_abi_incomparable_verdict_is_writable_as_a_baseline():
    """It is a declared measurement gap, like `structural` — not an infrastructure
    failure, and not something to block a refresh on."""
    assert not A.baseline_problems(_result(**{"f:i386:O0": {"g": "incomparable"}}))


def test_a_nonportable_verdict_may_not_appear_on_the_control_lane():
    problems = A.control_problems(
        _result(**{"f:x86_64:O0": {"g": "nonportable"}}), [("x86_64", "O0")]
    )
    assert problems and "nonportable" in problems[0]
