"""The fixture gate's toolchain must be pinned, provisioned, and attributable.

A per-function baseline is only a regression gate if the compilers that produced
it are the compilers that check it. Two ways that silently broke before:

  * the fixture baseline was recorded with whatever gcc/clang the developer's host
    shipped (gcc 15 / clang 21 here, gcc 11 / clang 14 on the CI runner). Codegen
    idioms and — for the rebuild of our own decompiled C — the set of diagnostics
    that are hard errors both move between releases, so verdicts recorded on one
    host cannot reproduce on the other;
  * the C++ fixture's clang lanes were recorded `env-missing` because this host's
    clang++ cannot link libstdc++. On a runner where it CAN, the lane runs for
    real and its results were dropped from every comparison — a silent hole.

These checks are fast (no fixture matrix) and run on every PR.
"""

from __future__ import annotations

import ctypes
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import fixture_harness as H  # ty: ignore[unresolved-import]  # added to sys.path above
import fixture_toolchain as TC  # ty: ignore[unresolved-import]
import manifest as M  # ty: ignore[unresolved-import]

BASELINE = ROOT / "tests" / "decompiler_fixtures" / "baseline.json"


def _baseline() -> dict:
    return json.loads(BASELINE.read_text())


# ---------------------------------------------------------------------------
# env-missing -> runnable must force a baseline refresh (never a silent skip)
# ---------------------------------------------------------------------------


def test_env_missing_lane_that_became_runnable_requires_a_baseline_refresh():
    base = {"10_cpp:clang:O0": {"__lane__": "env-missing"}}
    cur = {"10_cpp:clang:O0": {"cpp_move": "pass", "cpp_exception": "fail"}}
    probs = H.env_lane_problems(cur, base)
    assert probs, "a lane that became runnable must not be silently excluded"
    assert "10_cpp:clang:O0" in probs[0] and "refresh" in probs[0]
    # and the count of results that would have been dropped is reported
    assert "2 function result" in probs[0]


def test_runnable_lane_that_became_env_missing_is_a_failure():
    base = {"10_cpp:clang:O0": {"cpp_move": "pass"}}
    cur = {"10_cpp:clang:O0": {"__lane__": "env-missing"}}
    probs = H.env_lane_problems(cur, base)
    assert probs and "provision" in probs[0]


def test_env_lane_agreement_is_clean():
    same_env = {"10_cpp:clang:O0": {"__lane__": "env-missing"}}
    assert H.env_lane_problems(same_env, same_env) == []
    same_run = {"10_cpp:clang:O0": {"cpp_move": "pass"}}
    assert H.env_lane_problems(same_run, same_run) == []


def test_env_lane_check_ignores_the_toolchain_key():
    base = {H.TOOLCHAIN_KEY: {"mode": "docker"}, "01:gcc:O0": {"f": "pass"}}
    assert H.env_lane_problems(base, base) == []


# ---------------------------------------------------------------------------
# toolchain fingerprint comparison
# ---------------------------------------------------------------------------

_FP = {
    "mode": "docker",
    "gcc": "gcc 11.4.0",
    "gpp": "g++ 11.4.0",
    "clang": "clang 14.0.0",
    "clangpp": "clang++ 14.0.0",
    "ld": "ld 2.38",
    "libc": "glibc 2.35",
}


def test_identical_fingerprints_are_comparable():
    assert TC.fingerprint_problems(dict(_FP), dict(_FP)) == []


def test_a_different_compiler_release_is_not_comparable():
    other = dict(_FP, gcc="gcc 15.2.0")
    probs = TC.fingerprint_problems(dict(_FP), other)
    assert probs and probs[0].startswith("gcc:")


def test_host_mode_is_not_comparable_to_a_pinned_baseline():
    probs = TC.fingerprint_problems(dict(_FP), dict(_FP, mode="host"))
    assert any(p.startswith("mode:") for p in probs)


def test_a_baseline_without_a_fingerprint_is_rejected():
    assert TC.fingerprint_problems(None, dict(_FP))
    assert TC.fingerprint_problems({}, dict(_FP))


def test_schema_requires_a_toolchain_fingerprint():
    lane_only = {"01_conditional_polarity:gcc:O0": {"cmp_signed": "pass"}}
    probs = H.schema_problems(lane_only, [("gcc", "O0")])
    assert any(H.TOOLCHAIN_KEY in p for p in probs)


def test_lanes_helper_hides_only_the_reserved_key():
    m = {H.TOOLCHAIN_KEY: {"mode": "docker"}, "a:gcc:O0": {}, "b:clang:O2": {}}
    assert set(H.lanes(m)) == {"a:gcc:O0", "b:clang:O2"}


# ---------------------------------------------------------------------------
# the pinned toolchain itself
# ---------------------------------------------------------------------------


def test_pinned_toolchain_is_the_default():
    assert TC.mode() == "docker", (
        "the gate must compile under the pinned toolchain by default; host "
        "compilers make the baseline machine-specific"
    )


def test_this_environment_matches_the_committed_baseline_toolchain():
    """The real guard: whatever host or runner this is, the pinned toolchain must
    be the one the committed baseline was recorded with — otherwise every verdict
    comparison downstream is meaningless."""
    recorded = _baseline().get(H.TOOLCHAIN_KEY)
    probs = TC.fingerprint_problems(recorded)
    assert not probs, (
        "TOOLCHAIN MISMATCH vs tests/decompiler_fixtures/baseline.json:\n  "
        + "\n  ".join(probs)
        + "\n(rebuild the pinned image, or refresh the baseline under it)"
    )


def test_pinned_clang_can_link_a_cxx_program():
    """The clang C++ hole: on this host clang++ cannot find libstdc++, which made
    the C++ fixture's clang lanes `env-missing` and dropped them from the gate. The
    pinned image provisions the runtime, so the lanes are real everywhere."""
    assert H._cxx_runtime_ok("clang"), "pinned clang++ cannot build a C++ program"
    assert H._cxx_runtime_ok("gcc"), "pinned g++ cannot build a C++ program"


def test_no_lane_is_env_missing_under_the_pinned_toolchain():
    assert H.detect_allowed_missing() == set(), (
        "the pinned toolchain provisions every required runtime, so no lane may "
        "be declared env-missing"
    )


def test_pinned_toolchain_output_executes_on_this_host(tmp_path):
    """Only compilation is containerised; the object must load and run natively.
    That holds because the image's glibc floor (2.35) is older than any host we
    build on — this asserts it instead of assuming it."""
    src = tmp_path / "t.c"
    src.write_text("int add7(int a){ return a + 7; }\n")
    so = tmp_path / "t.so"
    r = TC.run(["gcc", "-shared", "-fPIC", "-O0", "-o", str(so), str(src)])
    assert r.returncode == 0, r.stderr
    lib = ctypes.CDLL(str(so))
    lib.add7.restype = ctypes.c_int
    lib.add7.argtypes = [ctypes.c_int]
    assert lib.add7(35) == 42


def test_pinned_toolchain_reports_compile_errors_like_a_direct_invocation(tmp_path):
    src = tmp_path / "bad.c"
    src.write_text("int f(void){ this is not c }\n")
    r = TC.run(["gcc", "-shared", "-fPIC", "-o", str(tmp_path / "bad.so"), str(src)])
    assert r.returncode != 0 and r.stderr.strip(), (
        "compiler stderr must reach the caller"
    )


def test_an_unknown_toolchain_mode_is_rejected(monkeypatch):
    monkeypatch.setenv("GLAURUNG_FIXTURE_TOOLCHAIN", "whatever")
    try:
        TC.mode()
    except TC.ToolchainError as e:
        assert "whatever" in str(e)
    else:
        raise AssertionError("an unrecognised toolchain mode must fail closed")


# --- the build must not depend on where the checkout lives ------------------


def test_a_prefix_map_rule_is_not_mistaken_for_an_input_path(tmp_path):
    """`-ffile-prefix-map=/a/b=.` splits at its first `=` into `/a/b=.`, which is
    not a directory, so the generic rule would mount its PARENT -- a wider mount
    than the compile needs and one that changes with the checkout's depth."""
    argv = [
        "gcc",
        "-c",
        f"-ffile-prefix-map={tmp_path}=.",
        "-o",
        str(tmp_path / "x.o"),
        str(tmp_path / "x.c"),
    ]
    mounts = TC._mount_dirs(argv, tmp_path)
    assert tmp_path.parent not in mounts, mounts
    assert mounts == [tmp_path]


def test_the_rustc_rule_is_skipped_too(tmp_path):
    argv = [
        "rustc",
        f"--remap-path-prefix={tmp_path}=.",
        "-o",
        str(tmp_path / "x.so"),
        str(tmp_path / "x.rs"),
    ]
    assert TC._mount_dirs(argv, tmp_path) == [tmp_path]


def test_ordinary_equals_form_flags_are_still_mounted(tmp_path):
    """The skip must be narrow. `--sysroot=/path` has the same `flag=value`
    shape as a prefix-map rule and still names a real input directory, so it must
    survive. Mounted from OUTSIDE the work directory, since anything under it is
    already covered by the work mount and would prove nothing.

    (`-I/path` in its ATTACHED form is not handled by `_mount_dirs` at all --
    it has no `=`, so the token keeps its `-I` and resolves to nothing. Nothing
    in the fixture gate passes one, so this is noted rather than asserted.)
    """
    work = tmp_path / "work"
    sysroot = tmp_path / "sysroot"
    work.mkdir()
    sysroot.mkdir()
    argv = [
        "gcc",
        f"--sysroot={sysroot}",
        f"-ffile-prefix-map={work}=.",
        "-o",
        str(work / "x.o"),
        str(work / "x.c"),
    ]
    mounts = TC._mount_dirs(argv, work)
    assert sysroot in mounts and work in mounts, mounts


def test_every_fixture_compiler_erases_the_checkout_path():
    """The flag is per-front-end: rustc does not accept `-ffile-prefix-map` and
    gcc/clang do not accept `--remap-path-prefix`."""
    assert H.path_remap_flags("rustc") == [f"--remap-path-prefix={H.ROOT}=."]
    for cc in ("gcc", "clang", "g++", "arm-linux-gnueabihf-gcc"):
        assert H.path_remap_flags(cc) == [f"-ffile-prefix-map={H.ROOT}=."], cc


def test_a_built_fixture_contains_no_absolute_checkout_path():
    """The property the flags exist for, checked on a real object rather than on
    the command line. A path in the binary is a STRING: its length moves
    `.rodata`, which moves section addresses, which changes what function
    discovery finds -- so a census taken in a worktree disagrees with the same
    commit in the main checkout. Measured 2026-08-18: `rustc:O0` read 7522
    violations over 3034 functions in an agent worktree and 7525 over 3035 in the
    main checkout, and two agents reported the committed baseline stale on it."""
    src = next(
        p
        for p in sorted((H.ROOT / "tests/decompiler_fixtures/src").glob("*.c"))
        if p.stem in M.REQUIRED_FUNCTIONS
    )
    so, err = H.compile_fixture(src, "gcc", "O0")
    assert so is not None, err
    blob = so.read_bytes()
    assert bytes(str(H.ROOT), "utf-8") not in blob, (
        f"{so.name} embeds the checkout path, so its bytes differ between checkouts"
    )
