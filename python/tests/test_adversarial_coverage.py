"""Adversarial-input regression coverage (#214).

Walks every sample in `samples/adversarial/` and confirms each
parser shipped this run handles weird inputs gracefully — no
panics, no infinite loops, no silent corruption.

Each parser must either:
  * return cleanly (empty list / None / a structured "missing"
    response), or
  * raise a known exception type that the CLI surfaces as a clean
    error message.

Anything else (Python crash, segfault, runaway memory, hang) is
a regression worth catching here.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

import glaurung as g


_ADVERSARIAL = Path("samples/adversarial")
_EMBEDDED = Path("samples/adversarial/embedded")

# Per-parser hard time bound. Adversarial samples are tiny (most
# under 4 KB); any single parser taking longer than this on one
# file is a runaway regression.
TIME_BUDGET_S = 3.0


def _all_adversarial() -> list[Path]:
    out = []
    if _ADVERSARIAL.exists():
        for p in sorted(_ADVERSARIAL.iterdir()):
            if p.is_file():
                out.append(p)
    if _EMBEDDED.exists():
        for p in sorted(_EMBEDDED.iterdir()):
            if p.is_file():
                out.append(p)
    return out


_SAMPLES = _all_adversarial()
if not _SAMPLES:
    pytest.skip("no adversarial samples", allow_module_level=True)


@pytest.mark.parametrize("sample", _SAMPLES, ids=lambda p: p.name)
def test_gopclntab_walker_handles_adversarial(sample: Path) -> None:
    """Go pclntab walker (#212) must return [] for non-Go inputs and
    not raise on any adversarial sample."""
    t = time.perf_counter()
    pairs = g.analysis.gopclntab_names_path(str(sample))
    assert isinstance(pairs, list)
    elapsed = time.perf_counter() - t
    assert elapsed < TIME_BUDGET_S, f"runaway: {elapsed:.2f}s on {sample.name}"


@pytest.mark.parametrize("sample", _SAMPLES, ids=lambda p: p.name)
def test_cil_methods_handles_adversarial(sample: Path) -> None:
    """CIL parser (#210) returns [] for non-.NET / malformed PEs.
    Must not raise except on truly corrupt CLR headers."""
    t = time.perf_counter()
    try:
        methods = g.analysis.cil_methods_path(str(sample))
        assert isinstance(methods, list)
    except RuntimeError:
        # RuntimeError is the documented surface for genuinely-broken
        # CLR metadata; treat as expected and move on.
        pass
    elapsed = time.perf_counter() - t
    assert elapsed < TIME_BUDGET_S, f"runaway: {elapsed:.2f}s on {sample.name}"


@pytest.mark.parametrize("sample", _SAMPLES, ids=lambda p: p.name)
def test_java_class_handles_adversarial(sample: Path) -> None:
    """Java classfile parser (#209) returns None for non-class files."""
    t = time.perf_counter()
    try:
        info = g.analysis.parse_java_class_path(str(sample))
        # Either None (non-class) or a dict (somehow valid). Both fine.
        assert info is None or isinstance(info, dict)
    except RuntimeError:
        # Truncated/corrupt class file = known error; not a panic.
        pass
    elapsed = time.perf_counter() - t
    assert elapsed < TIME_BUDGET_S, f"runaway: {elapsed:.2f}s on {sample.name}"


@pytest.mark.parametrize("sample", _SAMPLES, ids=lambda p: p.name)
def test_lua_bytecode_handles_adversarial(sample: Path) -> None:
    """Lua bytecode recognizer (#211) returns None for non-Lua."""
    t = time.perf_counter()
    try:
        info = g.analysis.parse_lua_bytecode_path(str(sample))
        assert info is None or isinstance(info, dict)
    except RuntimeError:
        pass
    elapsed = time.perf_counter() - t
    assert elapsed < TIME_BUDGET_S, f"runaway: {elapsed:.2f}s on {sample.name}"


@pytest.mark.parametrize("sample", _SAMPLES, ids=lambda p: p.name)
def test_detect_packer_handles_adversarial(sample: Path) -> None:
    """Packer detector (#187) walks raw bytes and computes entropy.
    It must produce a verdict for any input — that's the contract."""
    from glaurung.llm.kb.packer_detect import detect_packer

    t = time.perf_counter()
    verdict = detect_packer(str(sample))
    assert verdict.is_packed in (True, False)
    assert 0.0 <= verdict.overall_entropy <= 8.0
    elapsed = time.perf_counter() - t
    assert elapsed < TIME_BUDGET_S, f"runaway: {elapsed:.2f}s on {sample.name}"


@pytest.mark.parametrize("sample", _SAMPLES, ids=lambda p: p.name)
def test_triage_analyze_handles_adversarial(sample: Path) -> None:
    """The triage entry point sees every adversarial input first.
    Must produce a TriagedArtifact (possibly with errors recorded)
    or raise a clean exception — never a Rust panic across PyO3."""
    t = time.perf_counter()
    try:
        art = g.triage.analyze_path(str(sample), 10_000_000, 100_000_000, 1)
        assert art is not None
        # Either it found a format with verdicts, or it surfaced errors.
        assert art.verdicts is not None or art.errors is not None
    except (RuntimeError, ValueError, OSError):
        pass
    elapsed = time.perf_counter() - t
    assert elapsed < TIME_BUDGET_S, f"runaway: {elapsed:.2f}s on {sample.name}"


def test_kickoff_analysis_handles_adversarial_root(tmp_path: Path) -> None:
    """End-to-end: kickoff_analysis on every adversarial sample. The
    skip_if_packed=True default short-circuits the deeper passes when
    detect_packer flags it. We don't assert specific outputs — only
    that the call returns a summary structure for every sample."""
    from glaurung.llm.kb.kickoff import kickoff_analysis

    for sample in _SAMPLES:
        db = tmp_path / f"adv-{sample.name}.glaurung"
        try:
            summary = kickoff_analysis(str(sample), db_path=str(db))
        except Exception as e:
            # Some adversarial samples will fail at PE/ELF triage. That's
            # fine — surface as a known exception, not a panic.
            assert isinstance(e, (RuntimeError, ValueError, OSError)), (
                f"unexpected exception type {type(e).__name__} "
                f"on {sample.name}: {e}"
            )
            continue
        # Every successful summary must carry at least the format /
        # functions_total / packer fields (even if all zero).
        assert hasattr(summary, "functions_total")
        assert hasattr(summary, "packer")
