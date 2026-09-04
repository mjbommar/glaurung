"""The one parser-recovery test that reads the DecBench checkout.

Split out of ``test_parser_recovery.py`` so the rest of that file is not
classified ``decbench`` and deselected wholesale. ``tools/gen_test_facets.py``
classifies by whole-file text match, so a single mention of the checkout tags
every test beside it -- and ``pytest.ini`` deselects ``-m decbench``, which
meant 58 real tests contributed nothing to the suite while appearing to pass.

Reads one pure-Python function from the checkout. No JVM, no pipeline, no
DecBench run.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from python.tests.test_parser_recovery import UNIT_A, UNIT_B, UNIT_C, _need, prb


def test_the_decbench_sanitizer_flags_the_dialect_class() -> None:
    """Our class-2/3 damage must be exactly what DecBench rewrites for Joern.

    The DecBench checkout is read for one pure-Python function; no JVM, no
    pipeline. This is the single test that tags the whole file `decbench` -- see
    the KNOWN PROBLEM note in this module's docstring.
    """
    decbench = Path(os.environ.get("DECBENCH_DIR", prb.DEFAULT_DECBENCH_DIR))
    _need(
        (decbench / "decbench" / "utils" / "cfg.py").is_file(),
        f"no DecBench checkout at {decbench}",
    )
    units = [
        UNIT_A,
        UNIT_B,
        UNIT_C,
        UNIT_C.__class__(**{**vars(UNIT_C), "name": "delta"}),
    ]
    cases = prb.build_cases(units, seed=5, cases_per_source=1, functions_per_case=4)
    counts = prb.sanitizer_hazard(cases, decbench)
    assert counts is not None
    assert counts[("unit-test", "1-pristine")] == 0, "clean C must need no rewrite"
    assert counts[("unit-test", "2-dialect")] >= 3
    assert counts[("unit-test", "3-gnu")] >= 1
    # The counter must discriminate: the structural class edits braces and
    # parens, none of which the sanitizer's five rules touch.
    assert counts[("unit-test", "6-structural")] == 0
