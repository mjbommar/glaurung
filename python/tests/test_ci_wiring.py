"""The CI workflows run what the facet system says they run.

A gate that exists but is wired to nothing is indistinguishable from one that
does not exist -- this repository has found that out repeatedly (`cargo test`
unrun by any workflow until 2026-08-31; 195 symbolic tests type-checked forever
and executed never; a perf gate nothing invoked). These assertions pin the
wiring decisions of the tiered suite so that removing a line from a workflow
fails a test instead of quietly restoring a hole.

Each assertion names the decision it protects and why it was made.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
WF = ROOT / ".github" / "workflows"


def load(name: str) -> dict:
    return yaml.safe_load((WF / name).read_text())


def test_the_known_failure_corpus_runs_where_the_fixtures_are_built():
    """1,162 strict xfails need the built fixture matrix, which is gitignored
    and exists on exactly one CI job: the one that builds it. On the
    test-suite runner every one of them skips. A fix must go red in CI."""
    text = (WF / "decompiler-fixtures.yml").read_text()
    assert "test_known_decompiler_failures.py" in text, (
        "decompiler-fixtures.yml no longer runs the known-failure corpus; "
        "1,162 xfails now run nowhere in CI"
    )
    assert "-m fixtures" in text, "the corpus step must select by the `fixtures` facet"


def test_the_wheel_matrix_is_gated_on_tags_not_on_every_push():
    """Fifteen wheel jobs -- four under QEMU -- used to run on every push and
    PR and discard their output. The matrix runs where it is consumed."""
    ci = load("CI.yml")
    jobs = ci["jobs"]
    gate = "startsWith(github.ref, 'refs/tags/')"
    for job in ("linux", "musllinux", "windows", "macos", "sdist"):
        cond = jobs[job].get("if", "")
        assert gate in cond, f"CI.yml job `{job}` is no longer gated on tags: {cond!r}"
    # The release path must still see all of them.
    assert set(jobs["release"]["needs"]) == {
        "linux",
        "musllinux",
        "windows",
        "macos",
        "sdist",
    }
    assert "always()" not in jobs["release"].get("if", ""), (
        "release must not run against skipped builds"
    )


def test_pushes_still_get_a_wheel_smoke():
    """Gating the matrix must not mean a push can break packaging unnoticed."""
    jobs = load("CI.yml")["jobs"]
    assert "wheel-smoke" in jobs, "the x86_64 wheel smoke for push/PR is gone"
    cond = jobs["wheel-smoke"].get("if", "")
    assert "!startsWith(github.ref, 'refs/tags/')" in cond, (
        "wheel-smoke should run on ordinary pushes, not duplicate the tag matrix"
    )
    steps = " ".join(str(s) for s in jobs["wheel-smoke"]["steps"])
    assert "upload-artifact" not in steps, (
        "wheel-smoke uploads nothing; the artifact is the proof, not the product"
    )


def test_the_rust_suite_demands_its_toolchains():
    """`GLAURUNG_REQUIRE_TOOLCHAINS=1` turns a would-be silent skip into a
    failure. CI is the place that guarantees the 21 fixture-compiling tests
    actually ran, so the job must set it and must install the compilers
    WITHOUT `|| true`."""
    text = (WF / "test-suite.yml").read_text()
    assert 'GLAURUNG_REQUIRE_TOOLCHAINS: "1"' in text
    install = [ln for ln in text.splitlines() if "gcc-arm-none-eabi" in ln]
    assert install and not any("|| true" in ln for ln in install), (
        "the arm toolchain install must fail loudly, not be swallowed"
    )


def test_every_facet_that_can_run_on_a_hosted_runner_has_a_job():
    """A facet no workflow selects is a tier that runs only on laptops."""
    texts = "\n".join(p.read_text() for p in WF.glob("*.yml"))
    # `fixtures` is covered by the matrix job; `core`/`lfs`/`toolchain` by the
    # python job's full run; `symbolic` by its own cargo job. `docker`, `llm`
    # and `decbench` are opt-in by construction and are NOT expected here.
    assert "--features symbolic" in texts, "no workflow runs the symbolic engine tests"
    assert "-m fixtures" in texts, "no workflow runs the fixtures facet"


def test_the_python_suite_is_tiered_into_core_and_extended():
    """Two required jobs, partitioning the non-fixture suite exactly.

    `core` is the fast signal and needs no LFS; `extended` carries the
    lfs/toolchain half with its own timeout so a budget overrun there cannot
    mask a core failure. Both run on every push -- a tier that runs only
    nightly is how coverage silently degrades.
    """
    jobs = load("test-suite.yml")["jobs"]
    assert "python-core" in jobs and "python-extended" in jobs, list(jobs)
    core_run = " ".join(str(s.get("run", "")) for s in jobs["python-core"]["steps"])
    ext_run = " ".join(str(s.get("run", "")) for s in jobs["python-extended"]["steps"])
    assert '-m "core and not decbench" -n auto' in core_run, core_run
    assert '-m "not core and not fixtures and not decbench" -n auto' in ext_run, ext_run
    # Parallel by default in CI: measured 11:19 -> 4:13 on 24 cores with zero
    # failures. A job that drops `-n auto` silently goes back to serial.
    # Neither job may run the fixtures facet: this runner never has the matrix.
    assert "-m fixtures" not in core_run + ext_run


def test_the_core_job_does_not_fetch_lfs():
    """`core` is defined as needing no sample binaries, so the ~663 MB LFS
    fetch is pure cost there. The facet guarantees it, not the checkout: if a
    core test ever reads samples/, test_test_facets.py reclassifies it."""
    jobs = load("test-suite.yml")["jobs"]
    for step in jobs["python-core"]["steps"]:
        if "checkout" in str(step.get("uses", "")):
            assert not (step.get("with") or {}).get("lfs"), (
                "python-core fetches LFS; that is the extended job's cost"
            )
    ext_checkout = [
        s
        for s in jobs["python-extended"]["steps"]
        if "checkout" in str(s.get("uses", ""))
    ]
    assert ext_checkout and ext_checkout[0]["with"]["lfs"] is True, (
        "python-extended must fetch LFS or every `lfs` test reads a pointer file"
    )
