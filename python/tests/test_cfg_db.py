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


class _Instruction:
    def __init__(self, va: int, mnemonic: str, operands: list[str]) -> None:
        self.address = _Address(va)
        self.mnemonic = mnemonic
        self.operands = operands


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


def test_cfg_db_precomputes_dominance_summaries(
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
        cfg_db.index_cfg(project, str(pe))
        assert cfg_db.index_cfg_dominance(project) == 3
        assert cfg_db.is_dominance_indexed(project)
        assert cfg_db.cfg_dominance_counts(project).function_count == 1
        rows = {
            row[0]: row[1:]
            for row in project._conn.execute(
                "SELECT block_id, immediate_dominator_id, "
                "immediate_post_dominator_id, dominator_count, "
                "post_dominator_count FROM cfg_dominance"
            )
        }
        assert rows["entry"] == (None, "gate", 0, 2)
        assert rows["gate"] == ("entry", "sink", 1, 1)
        assert rows["sink"] == ("gate", None, 2, 0)
    finally:
        project.close()


def test_cfg_db_persists_branch_condition_facts(
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
                        _Block("entry", 0x1000, 0x1010, 3, ["gate", "sink"], []),
                        _Block("gate", 0x1010, 0x1030, 2, ["sink"], ["entry"]),
                        _Block("sink", 0x1020, 0x1030, 1, [], ["entry", "gate"]),
                    ],
                )
            ],
            None,
        )

    def fake_disassemble_window_at(_path: str, va: int, **_kwargs):
        if va == 0x1000:
            return [
                _Instruction(0x1000, "cmp", ["rcx", "0x10"]),
                _Instruction(0x1004, "jae", ["0x1020"]),
            ]
        return []

    monkeypatch.setattr(g.analysis, "analyze_functions_path", fake_analyze_functions_path)
    monkeypatch.setattr(g.disasm, "disassemble_window_at", fake_disassemble_window_at)
    pe = tmp_path / "driver.sys"
    pe.write_bytes(b"MZ")
    project_path = tmp_path / "driver.glaurung"

    project = PersistentKnowledgeBase.open(project_path, binary_path=pe)
    try:
        cfg_db.index_cfg(project, str(pe))
        assert cfg_db.index_cfg_branch_facts(project, str(pe)) == 1
        assert cfg_db.is_branch_facts_indexed(project)
        assert cfg_db.cfg_branch_counts(project).function_count == 1
        row = project._conn.execute(
            "SELECT block_id, branch_mnemonic, branch_operands_json, "
            "compare_mnemonic, compare_operands_json, condition_kind, "
            "target_block_id, fallthrough_block_id FROM cfg_branch_facts"
        ).fetchone()
        assert row == (
            "entry",
            "jae",
            '["0x1020"]',
            "cmp",
            '["rcx", "0x10"]',
            "unsigned_greater_equal",
            "sink",
            "gate",
        )
    finally:
        project.close()
