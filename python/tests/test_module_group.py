"""Cross-binary module-group reasoning: detect pool tags shared across a
driver family (the cross-module corruption surface). Regression for the
"dxgmms1 overflows into dxgmms2's shared pool" hypothesis that crossed the
per-.glaurung boundary and had no expression before.
"""
from __future__ import annotations

from pathlib import Path

import pytest

_D = Path("/nas4/data/workspace-infosec/cold-hunt-durable/v7vm/System32/drivers")
_M2 = _D / "dxgmms2.sys"
_M1 = _D / "dxgmms1.sys"
_have = _M2.is_file() and _M1.is_file()

pytestmark = pytest.mark.skipif(not _have, reason="dxgmms1/2 corpus absent")


def test_tag_extraction_finds_alloc_sites():
    from glaurung.llm.kb.module_group import pool_tags

    f = pool_tags(str(_M2), name="dxgmms2")
    assert f.alloc_calls > 0
    assert f.tags, "expected at least one resolved pool tag"
    # every tag is a 4-char string
    assert all(len(t) == 4 for t in f.tags)


def test_shared_pool_tags_across_family():
    from glaurung.llm.kb.module_group import ModuleGroup

    g = ModuleGroup.from_binaries([("dxgmms2", str(_M2)), ("dxgmms1", str(_M1))])
    shared = g.shared_tags()
    # The two GPU scheduler modules must share >=1 pool tag.
    assert shared, "expected shared pool tags between dxgmms1 and dxgmms2"
    for tag, members in shared.items():
        assert len(members) >= 2  # used by both
    # Coverage must hedge: shared tag != proven overflow path.
    caveats = " ".join(g.coverage.to_dict()["caveats"]).lower()
    assert "not a proven overflow" in caveats


def test_to_dict_shape():
    from glaurung.llm.kb.module_group import ModuleGroup

    g = ModuleGroup.from_binaries([("a", str(_M2)), ("b", str(_M1))])
    d = g.to_dict()
    assert len(d["members"]) == 2
    assert "shared_tags" in d and "coverage" in d
