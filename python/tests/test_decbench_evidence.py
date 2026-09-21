"""Check how Glaurung's CLI evidence is shaped for DecBench's models.

Glaurung already emits `variables` and `line_mappings` in its `--style decbench
--format json` payload, but both adapters discard them, so `type_match` falls
back to parsing the C text. Forwarding them is the change; these tests pin the
shaping rules, which mirror DecBench's own in-tree JSON backend
(`decompilers/raw/kuna_raw.py:_build_function`) and its golden test
(`tests/test_raw_line_provenance.py`, the kuna case).
"""

import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "decbench_evidence", ROOT / "tools" / "decbench_evidence.py"
)
assert SPEC is not None and SPEC.loader is not None
EV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EV)


def _record(**overrides: object) -> dict:
    record = {
        "name": "f",
        "entry_va": 0x5000,
        "size": 0x20,
        "pseudocode": "int f(void) {\n    return x;\n}",
        "line_mappings": [
            {"line_number": 2, "addresses": [0x5008, 0x5004]},
            {"line_number": 99, "addresses": [0x5004]},
            {"line_number": 3, "addresses": [0x6000]},
        ],
        "variables": [
            {
                "name": "x",
                "type": "int",
                "kind": "stack",
                "stack_offset": -8,
                "size": 4,
                "arg_index": None,
                "addresses": [0x5008, 0x6000],
            }
        ],
    }
    record.update(overrides)
    return record


def test_rows_are_rebased_sorted_and_deduped() -> None:
    mappings, _ = EV.shape_evidence(_record(), file_addr=0x1000, line_count=3)
    assert mappings == [{"line_number": 2, "addresses": [0x1004, 0x1008]}]


def test_a_line_beyond_the_emitted_text_is_dropped() -> None:
    """Line 99 does not exist in a 3-line function."""
    mappings, _ = EV.shape_evidence(_record(), file_addr=0x1000, line_count=3)
    assert [row["line_number"] for row in mappings] == [2]


def test_an_address_outside_the_function_is_dropped_and_empty_rows_vanish() -> None:
    """0x6000 is past `entry + size`, so line 3 keeps nothing and disappears."""
    mappings, _ = EV.shape_evidence(_record(), file_addr=0x1000, line_count=3)
    assert all(row["addresses"] for row in mappings)
    assert 3 not in [row["line_number"] for row in mappings]


def test_variable_evidence_is_filtered_to_match() -> None:
    _, variables = EV.shape_evidence(_record(), file_addr=0x1000, line_count=3)
    assert len(variables) == 1
    assert variables[0]["addresses"] == [0x1008]
    assert variables[0]["name"] == "x"
    assert variables[0]["stack_offset"] == -8


def test_only_fields_decbench_declares_are_forwarded() -> None:
    """Glaurung adds `static_variable`/`static_type`; DecBench models neither."""
    record = _record(
        variables=[
            {
                "name": "x",
                "type": "int",
                "kind": "stack",
                "stack_offset": -8,
                "size": 4,
                "arg_index": None,
                "addresses": [0x5008],
                "static_variable": {"id": "static-variable-deadbeef"},
                "static_type": None,
            }
        ]
    )
    _, variables = EV.shape_evidence(record, file_addr=0x1000, line_count=3)
    assert set(variables[0]) <= EV.VARIABLE_FIELDS
    assert "static_variable" not in variables[0]


def test_an_argument_with_no_addresses_is_kept_for_its_abi_position() -> None:
    """Stage 1 of DecBench's matcher needs `arg_index`, not addresses."""
    record = _record(
        variables=[
            {
                "name": "arg0",
                "type": "long",
                "kind": "arg",
                "arg_index": 0,
                "stack_offset": None,
                "size": None,
                "addresses": [],
            }
        ]
    )
    _, variables = EV.shape_evidence(record, file_addr=0x1000, line_count=3)
    assert len(variables) == 1
    assert variables[0]["arg_index"] == 0
    assert variables[0]["addresses"] == []


def test_an_unknown_size_skips_the_upper_bound_rather_than_dropping_everything() -> (
    None
):
    """Glaurung reports `size: null` for many functions; that must not void it."""
    record = _record(size=None)
    mappings, variables = EV.shape_evidence(record, file_addr=0x1000, line_count=3)
    assert [row["line_number"] for row in mappings] == [2, 3]
    assert variables[0]["addresses"] == [0x1008, 0x2000]


def test_a_missing_or_malformed_payload_yields_empty_lists_not_an_error() -> None:
    for record in (
        {},
        {"line_mappings": None, "variables": None},
        {"line_mappings": [{"line_number": "x"}], "variables": [None]},
    ):
        mappings, variables = EV.shape_evidence(record, file_addr=0x1000, line_count=3)
        assert mappings == []
        assert variables == []
