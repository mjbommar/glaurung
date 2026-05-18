from __future__ import annotations

from pathlib import Path

from glaurung.llm.kb import cfg_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


class _Address:
    def __init__(self, value: int) -> None:
        self.value = value


class _Block:
    def __init__(
        self,
        block_id: str,
        start: int,
        end: int,
        instructions: int,
        successors: list[str],
        predecessors: list[str],
    ) -> None:
        self.id = block_id
        self.start_address = _Address(start)
        self.end_address = _Address(end)
        self.instruction_count = instructions
        self.successor_ids = successors
        self.predecessor_ids = predecessors


class _Function:
    def __init__(self, entry: int, blocks: list[_Block]) -> None:
        self.entry_point = _Address(entry)
        self.basic_blocks = blocks


def test_cfg_db_persists_basic_blocks_and_edges(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import glaurung as g

    def fake_analyze_functions_path(*_args, **_kwargs):
        return (
            [
                _Function(
                    0x1000,
                    [
                        _Block("entry", 0x1000, 0x1010, 3, ["gate"], []),
                        _Block("gate", 0x1010, 0x1020, 2, ["sink"], ["entry"]),
                        _Block("sink", 0x1020, 0x1030, 1, [], ["gate"]),
                    ],
                )
            ],
            None,
        )

    monkeypatch.setattr(g.analysis, "analyze_functions_path", fake_analyze_functions_path)
    pe = tmp_path / "driver.sys"
    pe.write_bytes(b"MZ")
    project_path = tmp_path / "driver.glaurung"

    project = PersistentKnowledgeBase.open(project_path, binary_path=pe)
    try:
        assert cfg_db.index_cfg(project, str(pe)) == 3
        assert cfg_db.is_indexed(project)
        assert cfg_db.cfg_counts(project).edge_count == 2
        assert project._conn.execute(
            "SELECT block_id FROM basic_blocks WHERE is_entry = 1"
        ).fetchone()[0] == "entry"
        assert project._conn.execute("SELECT COUNT(*) FROM cfg_edges").fetchone()[0] == 2
        assert cfg_db.index_cfg(project, str(pe)) == 3
    finally:
        project.close()
