import pathlib
import pytest


def sample_path():
    import os

    test_dir = os.path.dirname(__file__)
    return pathlib.Path(
        os.path.join(
            test_dir,
            "../../samples/binaries/platforms/linux/amd64/export/fortran/hello-gfortran-O2",
        )
    )


def test_detect_entry_and_cfg_if_sample_present():
    import glaurung as g

    p = sample_path()
    if not p.exists():
        pytest.skip("sample not present")
    ent = g.analysis.detect_entry_path(str(p))
    assert ent is not None
    fmt, arch, end, entry_va, file_off = ent
    assert isinstance(entry_va, int)

    funcs, cg = g.analysis.analyze_functions_path(str(p))
    assert isinstance(funcs, list)
    assert funcs
    f = funcs[0]
    assert f.entry_point.value >= 0
    assert f.basic_blocks
    assert cg.edge_count() >= 0
