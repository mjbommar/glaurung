#!/usr/bin/env python3
"""Regenerate tests/decompiler_fixtures/structural_baseline.json.

The structural lane compares the current decompiler's textual output to this
committed baseline and fails on ANY change (regression or improvement), so the
gate ratchets. Run this only after independently confirming an improvement is
real — never to make a red gate green.
"""

from __future__ import annotations

import scratch  # noqa: F401  -- points TMPDIR off the shared /tmp tmpfs on import
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import manifest as M  # ty: ignore[unresolved-import]
import structural as S  # ty: ignore[unresolved-import]

OUT = ROOT / "tests" / "decompiler_fixtures" / "structural_baseline.json"


def main() -> int:
    # Refuse to record a state that includes an undeclared fixture. This writer used
    # to skip the check that fixture_harness.py performs, so an undeclared fixture
    # landed in the structural baseline and not the execution one.
    M.assert_fixtures_declared()
    _td = M.tmpdir()
    with tempfile.TemporaryDirectory(**({"dir": _td} if _td else {})) as td:
        rep = S.structural_report(Path(td))
    assert rep["gaps"] == [], (
        f"refusing to write baseline with unassertioned structural funcs: {rep['gaps']}"
    )
    OUT.write_text(json.dumps(rep, indent=2, sort_keys=True) + "\n")
    cl = rep["closure"]
    print(f"wrote {OUT}")
    print(f"  closure: {sum(1 for v in cl.values() if v == 'closed')}/{len(cl)} closed")
    print(
        f"  effects: {len(rep['effects'])}, placeholders: {sum(rep['placeholder'].values())}"
    )
    print(f"  accepted honest goto lanes: {len(rep['accepted_honest_goto'])}")
    viol = {k: v for k, v in rep["verify"].items() if v}
    print(
        f"  def-before-use: {sum(len(v) for v in viol.values())} violation(s) "
        f"in {len(viol)} function(s)"
    )
    for k, v in sorted(viol.items()):
        print(f"    {k}: {'; '.join(v)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
