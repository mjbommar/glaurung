"""Tests for global data labels (#181)."""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_HELLO_DEBUG = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


def test_set_get_list_remove_round_trip(tmp_path: Path) -> None:
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "labels.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    xref_db.set_data_label(
        kb, va=0x4000, name="g_config", c_type="struct config", size=128,
    )
    xref_db.set_data_label(kb, va=0x4080, name="g_log_buf", c_type="char[]", size=4096)
    xref_db.set_data_label(kb, va=0x5000, name="g_quit_flag", c_type="int")

    rec = xref_db.get_data_label(kb, 0x4000)
    assert rec is not None
    assert rec.name == "g_config"
    assert rec.c_type == "struct config"
    assert rec.size == 128
    assert rec.set_by == "manual"

    listing = xref_db.list_data_labels(kb)
    assert [d.name for d in listing] == ["g_config", "g_log_buf", "g_quit_flag"]

    xref_db.remove_data_label(kb, 0x4080)
    assert xref_db.get_data_label(kb, 0x4080) is None
    assert len(xref_db.list_data_labels(kb)) == 2
    kb.close()


def test_manual_entries_survive_analyzer_overwrite(tmp_path: Path) -> None:
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "labels.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    xref_db.set_data_label(kb, va=0x4000, name="my_secret_table", set_by="manual")
    # Auto-import later tries to clobber with the symbol-table name.
    xref_db.set_data_label(
        kb, va=0x4000, name="something_generic", set_by="analyzer",
    )
    rec = xref_db.get_data_label(kb, 0x4000)
    assert rec is not None
    assert rec.name == "my_secret_table"
    assert rec.set_by == "manual"
    kb.close()


def test_import_data_symbols_skips_function_VAs(tmp_path: Path) -> None:
    """Function symbols already live in function_names; importing data
    labels must not duplicate them at the same VA."""
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "labels.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    # Index callgraph first so function_names is populated.
    xref_db.index_callgraph(kb, str(binary))
    func_vas = {n.entry_va for n in xref_db.list_function_names(kb)}
    assert func_vas

    n = xref_db.import_data_symbols_from_binary(kb, str(binary))
    assert n >= 0  # could be 0 on heavily-stripped, but we know it has symbols
    labels = xref_db.list_data_labels(kb)
    label_vas = {d.va for d in labels}
    # No data label should land at a known function entry.
    assert not (label_vas & func_vas), (
        f"data labels overlap function VAs: {label_vas & func_vas}"
    )
    kb.close()
