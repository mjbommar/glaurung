# WP10 performance-gate preflight evidence

Date: 2026-09-04

Implementation revision: `ef24d729858a2fa363cf314611b9da9b8b2da177`

Base revision: `d4072731597b6e92eeeb717c6df48d3c20962c8c`

## Defect

The required post-`src/` Python suite reached
`test_perf_gate_fails_closed.py::test_an_incomparable_unit_is_not_a_pass` and
then stopped making progress. The test invokes `tools/perf_gate.py` with a
baseline whose unit is deliberately incompatible with the current host.

The gate already knew both units before measurement, but it first launched
nine whole-program decompilations: three runs over each of three large Go/Rust
binaries. The same ordering affected a missing baseline and a baseline naming
an impossible reference. These are metadata-only “not evidence” states; no
measurement can make them comparable.

After 1:51:36 the interrupted suite had reached 71% and reported the partial
accounting below. This is not a completed full-suite result:

```text
372 failed, 2761 passed, 27 skipped, 14 deselected, 892 xfailed,
11 warnings, 2 subtests passed
```

At interruption, pytest's traceback was waiting in `subprocess.run` from the
incomparable-unit test. The gate had no remaining useful metadata decision to
make. The repository remained pinned to the pushed base revision throughout
the run.

## Change

`tools/perf_gate.py` now resolves the counter unit and validates comparison
metadata before calling `measure()`:

- a missing baseline returns exit 3 immediately;
- an incompatible baseline unit returns exit 3 immediately; and
- a positive baseline reference absent from the configured population or the
  filesystem returns exit 3 immediately.

Baseline creation still measures normally. A configured reference that fails
during a real run is still checked after measurement, so the existing
fail-closed partial-result contract is preserved.

The three contract tests now also assert that stderr never reaches the
`measuring (` marker. This pins the control-flow property directly rather than
using a fragile wall-time threshold.

## Validation

```text
uv run pytest python/tests/test_perf_gate_fails_closed.py -q
4 passed; elapsed 0.62 seconds; max RSS 64,172 KiB

uv run pytest python/tests/test_perf_gate_fails_closed.py \
  python/tests/test_test_census.py -q
10 passed; elapsed 0.74 seconds; max RSS 64,140 KiB

uvx ruff format python/tests/test_perf_gate_fails_closed.py tools/perf_gate.py
2 files left unchanged

uvx ruff check python/tests/test_perf_gate_fails_closed.py tools/perf_gate.py
all checks passed
```

This increment repairs a WP10 gate-integrity and test-runtime defect. It does
not claim a fresh performance comparison, a green Python suite, or a change in
decompiler output.
