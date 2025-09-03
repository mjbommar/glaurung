from pathlib import Path

import pytest

# Skip or adapt if pytest-benchmark is not installed
try:
    import pytest_benchmark  # type: ignore  # noqa: F401

    HAS_BENCH = True
except Exception:  # pragma: no cover - environment dependent
    HAS_BENCH = False

import glaurung as g


@pytest.mark.skipif(not HAS_BENCH, reason="pytest-benchmark plugin not installed")
def test_triage_speed_small_matrix(benchmark):
    # Keep this list small and stable; CI-friendly
    candidates = [
        Path("samples/binaries/platforms/linux/arm64/export/fortran/hello-gfortran-O0"),
        Path(
            "samples/binaries/platforms/windows/i386/export/windows/i686/O0/hello-c-mingw32-O0.exe"
        ),
        Path("samples/containers/zip/hello-cpp-g++-O0.zip"),
    ]
    candidates = [p for p in candidates if p.exists()]
    if not candidates:
        pytest.skip("no sample files present")

    def run():
        for p in candidates:
            _ = g.triage.analyze_path(str(p))

    benchmark(run)
