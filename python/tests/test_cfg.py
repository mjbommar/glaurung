import pathlib
import pytest


def sample_path():
    return pathlib.Path(
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
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
