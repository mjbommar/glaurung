"""Parity tests for the native IOCTL surface mapper (glaurung.analysis).

Gated on GLAURUNG_IOCTL_FIXTURES (a directory holding the reference .sys files)
so third-party vendor drivers are not committed to the repo. Expected counts are
the cross-checked reference values, including the MSVC two-level switch jump
table decode on e22w8x64 (22 jump-table codes).
"""

import os

import pytest

import glaurung.analysis as analysis

FIX = os.environ.get("GLAURUNG_IOCTL_FIXTURES")

pytestmark = pytest.mark.skipif(
    not FIX, reason="set GLAURUNG_IOCTL_FIXTURES to a dir with the reference .sys files"
)

# (filename, unique IOCTL codes, jump-table codes, dispatcher count)
CASES = [
    ("PXGX112.sys", 2, 0, 1),
    ("e22w8x64.sys", 85, 22, 5),
    ("glusbflt.sys", 3, 0, 1),
    ("vn0601.sys", 6, 0, 3),
]


@pytest.mark.parametrize("name,n_codes,n_jt,n_disp", CASES)
def test_ioctl_surface_parity(name, n_codes, n_jt, n_disp):
    path = os.path.join(FIX, name)
    if not os.path.exists(path):
        pytest.skip(f"{name} not in fixtures dir")
    dispatchers = analysis.ioctl_surface_map_path(path)
    assert len(dispatchers) == n_disp, f"{name} dispatcher count"
    codes = set()
    jt = 0
    for d in dispatchers:
        for c in d["codes"]:
            codes.add(int(c["code"], 16))
        jt += len(d["jump_table"])
    assert len(codes) == n_codes, f"{name} unique codes"
    assert jt == n_jt, f"{name} jump-table codes"


def test_bytes_and_path_agree():
    """The bytes and path entry points must return identical structure."""
    path = os.path.join(FIX, "e22w8x64.sys")
    if not os.path.exists(path):
        pytest.skip("e22w8x64.sys not in fixtures dir")
    from_path = analysis.ioctl_surface_map_path(path)
    from_bytes = analysis.ioctl_surface_map_bytes(open(path, "rb").read())
    assert len(from_path) == len(from_bytes)
    assert {d["dispatcher_va"] for d in from_path} == {d["dispatcher_va"] for d in from_bytes}
