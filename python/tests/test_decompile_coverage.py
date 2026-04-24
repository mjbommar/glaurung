"""Functional regression: the decompiler should not emit `unknown(...)`
for any mnemonic we've committed to covering.

The c2_demo binary exercises a wide slice of gcc -O2 output (prologue /
epilogue, stack canary, string loads, SSE moves for inline-constant
`%rsi = "fmt…"` setups, etc.). Any new `unknown(...)` line that appears
here is a regression in lifter coverage or a pass that stopped firing.
The single accepted exception is `unknown(hlt)` — `hlt` is semantically
irreducible and we leave it as a tombstone.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

import glaurung as g


X86_SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/c2_demo-gcc-O2"
)
ARM64_SAMPLE = Path(
    "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc"
)

# Accepted survivors. Each entry is a canonical `unknown(...)` line that we
# deliberately leave in the output because no sensible IR op represents it.
ACCEPTED_UNKNOWNS = {"unknown(hlt)"}


def _collect_unknowns(path: Path) -> Counter:
    c: Counter = Counter()
    for _name, _va, text in g.ir.decompile_all(str(path), 64):
        for ln in text.splitlines():
            stripped = ln.strip().rstrip(";")
            if stripped.startswith("unknown("):
                c[stripped] += 1
    return c


@pytest.mark.skipif(not X86_SAMPLE.exists(), reason="x86-64 sample missing")
def test_c2_demo_has_no_unexpected_unknowns():
    unknowns = _collect_unknowns(X86_SAMPLE)
    unexpected = {k: v for k, v in unknowns.items() if k not in ACCEPTED_UNKNOWNS}
    assert not unexpected, (
        f"Unexpected unknowns (possible lifter regression): {unexpected}"
    )


@pytest.mark.skipif(not ARM64_SAMPLE.exists(), reason="arm64 sample missing")
def test_hello_arm64_has_no_unexpected_unknowns():
    unknowns = _collect_unknowns(ARM64_SAMPLE)
    unexpected = {k: v for k, v in unknowns.items() if k not in ACCEPTED_UNKNOWNS}
    assert not unexpected, (
        f"Unexpected ARM64 unknowns (possible lifter regression): {unexpected}"
    )
